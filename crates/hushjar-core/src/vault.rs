//! The decrypted vault: items, folders, collections and organisations, and
//! the conversion from and back to Bitwarden's encrypted JSON.
//!
//! Edits start from the item's original encrypted JSON and replace only the
//! values Hushjar edits, so data it does not understand (passkeys,
//! attachments, newer item types) is sent back unchanged.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::api::{field, field_str, field_u64};
use crate::crypto::{EncString, PrivateKey, SymmetricKey};
use crate::send::{self, SendEntry};

/// Shown in place of a value that could not be decrypted.
pub const UNREADABLE: &str = "⚠ could not decrypt";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("the key for this item is not available")]
    MissingKey,
    #[error("this kind of item cannot be edited in Hushjar yet")]
    ReadOnlyType,
    #[error("an encrypted value could not be decrypted")]
    Unreadable,
    #[error(
        "this item has an attachment from an old version of Bitwarden that cannot be moved; \
         download and delete it first"
    )]
    LegacyAttachment,
    #[error("a file Send needs a file name")]
    MissingFileName,
}

/// The keys that open an account's items.
pub struct Keys {
    pub user: SymmetricKey,
    pub organizations: HashMap<String, SymmetricKey>,
}

impl Keys {
    pub fn new(user: SymmetricKey, private_key: Option<&PrivateKey>, sync: &Value) -> Self {
        let mut organizations = HashMap::new();
        if let (Some(private), Some(orgs)) = (
            private_key,
            field(sync, "profile")
                .and_then(|p| field(p, "organizations"))
                .and_then(Value::as_array),
        ) {
            for org in orgs {
                if let (Some(id), Some(key)) = (field_str(org, "id"), field_str(org, "key"))
                    && let Ok(key) = private.unwrap_key(key)
                {
                    organizations.insert(id.to_string(), key);
                }
            }
        }
        Self {
            user,
            organizations,
        }
    }

    pub fn owner(&self, organization: Option<&str>) -> Option<&SymmetricKey> {
        match organization {
            Some(org) => self.organizations.get(org),
            None => Some(&self.user),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    /// A type this version does not understand; shown read-only.
    Other(u8),
}

impl ItemKind {
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => ItemKind::Login,
            2 => ItemKind::SecureNote,
            3 => ItemKind::Card,
            4 => ItemKind::Identity,
            5 => ItemKind::SshKey,
            n => ItemKind::Other(n),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            ItemKind::Login => 1,
            ItemKind::SecureNote => 2,
            ItemKind::Card => 3,
            ItemKind::Identity => 4,
            ItemKind::SshKey => 5,
            ItemKind::Other(n) => n,
        }
    }

    pub fn editable(self) -> bool {
        !matches!(self, ItemKind::Other(_))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct Uri {
    pub uri: String,
    /// Bitwarden's match detection setting, kept as sent by the server.
    #[zeroize(skip)]
    pub match_type: Option<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct Login {
    pub username: String,
    pub password: String,
    pub totp: String,
    pub uris: Vec<Uri>,
    #[zeroize(skip)]
    pub passkeys: usize,
    /// What can be shown about each stored passkey. The key material is
    /// never decrypted; it stays in [`Item::raw`] and is sent back as is.
    pub passkey_details: Vec<Passkey>,
}

/// A passkey (FIDO2 credential) stored on a login, read-only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct Passkey {
    /// Identifies the passkey for [`remove_passkey`].
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    /// When it was created, as the server stores it.
    #[zeroize(skip)]
    pub created: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct Card {
    pub cardholder_name: String,
    pub brand: String,
    pub number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub code: String,
}

/// Identity fields in Bitwarden's order, as (JSON name, label, secret).
pub const IDENTITY_FIELDS: [(&str, &str, bool); 18] = [
    ("title", "Title", false),
    ("firstName", "First name", false),
    ("middleName", "Middle name", false),
    ("lastName", "Last name", false),
    ("username", "Username", false),
    ("company", "Company", false),
    ("email", "Email", false),
    ("phone", "Phone", false),
    ("ssn", "Social security number", true),
    ("passportNumber", "Passport number", true),
    ("licenseNumber", "Licence number", true),
    ("address1", "Address 1", false),
    ("address2", "Address 2", false),
    ("address3", "Address 3", false),
    ("city", "City", false),
    ("state", "State or province", false),
    ("postalCode", "Postcode", false),
    ("country", "Country", false),
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct SshKey {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Hidden,
    Boolean,
    Linked,
}

impl FieldType {
    fn from_code(code: u64) -> Self {
        match code {
            1 => FieldType::Hidden,
            2 => FieldType::Boolean,
            3 => FieldType::Linked,
            _ => FieldType::Text,
        }
    }

    fn code(self) -> u8 {
        match self {
            FieldType::Text => 0,
            FieldType::Hidden => 1,
            FieldType::Boolean => 2,
            FieldType::Linked => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[zeroize(skip)]
    pub kind: FieldType,
    #[zeroize(skip)]
    pub linked_id: Option<u64>,
}

/// A file attached to an item. The contents are fetched on request with
/// `Session::download_attachment`.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Attachment {
    #[zeroize(skip)]
    pub id: String,
    pub file_name: String,
    /// Size of the encrypted file in bytes, as the server reports it.
    #[zeroize(skip)]
    pub size: u64,
    /// The server's readable size, such as "4.2 KB".
    #[zeroize(skip)]
    pub size_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct PasswordEntry {
    pub password: String,
    pub last_used: String,
}

#[derive(Clone, PartialEq)]
pub struct Item {
    pub id: String,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub kind: ItemKind,
    pub name: String,
    pub notes: String,
    pub favorite: bool,
    pub reprompt: bool,
    pub deleted: bool,
    pub archived: bool,
    /// Whether the account may change this item.
    pub editable: bool,
    /// Whether the account may see hidden values (organisation setting).
    pub view_password: bool,
    pub created: String,
    pub revised: String,
    pub login: Login,
    pub card: Card,
    /// Identity values keyed by JSON name; see [`IDENTITY_FIELDS`].
    pub identity: HashMap<String, String>,
    pub ssh_key: SshKey,
    pub fields: Vec<CustomField>,
    pub password_history: Vec<PasswordEntry>,
    /// Attached files. Saving an item never changes them; they are added
    /// and removed with their own requests.
    pub attachments: Vec<Attachment>,
    /// Values that could not be decrypted.
    pub unreadable: usize,
    /// The encrypted item as the server sent it. Empty for new items.
    pub raw: Value,
}

/// Shows only what identifies the item; its contents are secret.
impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Item {
    /// A new, empty item of the given kind.
    pub fn new(kind: ItemKind, organization_id: Option<String>, folder_id: Option<String>) -> Self {
        Self {
            id: String::new(),
            organization_id,
            folder_id,
            collection_ids: vec![],
            kind,
            name: String::new(),
            notes: String::new(),
            favorite: false,
            reprompt: false,
            deleted: false,
            archived: false,
            editable: true,
            view_password: true,
            created: String::new(),
            revised: String::new(),
            login: Login::default(),
            card: Card::default(),
            identity: HashMap::new(),
            ssh_key: SshKey::default(),
            fields: vec![],
            password_history: vec![],
            attachments: vec![],
            unreadable: 0,
            raw: Value::Null,
        }
    }

    pub fn is_new(&self) -> bool {
        self.id.is_empty()
    }

    pub fn identity_value(&self, key: &str) -> &str {
        self.identity.get(key).map(String::as_str).unwrap_or("")
    }

    /// Records the previous password in the history when it changes, keeping
    /// the five most recent, as Bitwarden clients do.
    pub fn note_password_change(&mut self, previous: &Item) {
        let old = &previous.login.password;
        if self.kind == ItemKind::Login && !old.is_empty() && *old != self.login.password {
            self.password_history.insert(
                0,
                PasswordEntry {
                    password: old.clone(),
                    last_used: now_iso(),
                },
            );
            self.password_history.truncate(5);
        }
    }
}

impl Drop for Item {
    fn drop(&mut self) {
        self.name.zeroize();
        self.notes.zeroize();
        self.login.zeroize();
        self.card.zeroize();
        for value in self.identity.values_mut() {
            value.zeroize();
        }
        self.ssh_key.zeroize();
        self.fields.zeroize();
        self.password_history.zeroize();
        self.attachments.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct Vault {
    pub user_id: String,
    pub email: String,
    pub folders: Vec<Folder>,
    pub collections: Vec<Collection>,
    pub organizations: Vec<Organization>,
    pub items: Vec<Item>,
    pub sends: Vec<SendEntry>,
}

impl Vault {
    pub fn item(&self, id: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn send(&self, id: &str) -> Option<&SendEntry> {
        self.sends.iter().find(|s| s.id == id)
    }
}

/// Decrypts an encrypted string field, counting failures.
struct Reader<'a> {
    key: Option<&'a SymmetricKey>,
    unreadable: usize,
}

impl Reader<'_> {
    fn get(&mut self, object: Option<&Value>, name: &str) -> String {
        let Some(value) = object.and_then(|o| field_str(o, name)) else {
            return String::new();
        };
        match self.key.map(|k| k.decrypt_str(value)) {
            Some(Ok(plain)) => plain.to_string(),
            _ => {
                self.unreadable += 1;
                UNREADABLE.to_string()
            }
        }
    }
}

/// Decrypts a full sync reply.
pub fn decrypt_sync(sync: &Value, keys: &Keys) -> Vault {
    let profile = field(sync, "profile");
    let mut vault = Vault {
        user_id: profile
            .and_then(|p| field_str(p, "id"))
            .unwrap_or_default()
            .to_string(),
        email: profile
            .and_then(|p| field_str(p, "email"))
            .unwrap_or_default()
            .to_string(),
        ..Default::default()
    };
    let list = |name: &str| {
        field(sync, name)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    for folder in list("folders") {
        let mut reader = Reader {
            key: Some(&keys.user),
            unreadable: 0,
        };
        vault.folders.push(Folder {
            id: field_str(&folder, "id").unwrap_or_default().to_string(),
            name: reader.get(Some(&folder), "name"),
        });
    }
    if let Some(orgs) = profile
        .and_then(|p| field(p, "organizations"))
        .and_then(Value::as_array)
    {
        for org in orgs {
            vault.organizations.push(Organization {
                id: field_str(org, "id").unwrap_or_default().to_string(),
                name: field_str(org, "name").unwrap_or_default().to_string(),
            });
        }
    }
    for collection in list("collections") {
        let org = field_str(&collection, "organizationId")
            .unwrap_or_default()
            .to_string();
        let mut reader = Reader {
            key: keys.organizations.get(&org),
            unreadable: 0,
        };
        vault.collections.push(Collection {
            id: field_str(&collection, "id").unwrap_or_default().to_string(),
            name: reader.get(Some(&collection), "name"),
            organization_id: org,
            read_only: field(&collection, "readOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    for cipher in list("ciphers") {
        vault.items.push(decrypt_item(&cipher, keys));
    }
    for send in list("sends") {
        vault.sends.push(send::decrypt_send(&send, &keys.user));
    }
    vault
}

/// The key that encrypts an item's fields: its own item key if it has one,
/// otherwise the account or organisation key.
pub(crate) fn item_key(raw: &Value, keys: &Keys) -> Option<SymmetricKey> {
    let owner = keys.owner(field_str(raw, "organizationId"))?;
    match field_str(raw, "key") {
        Some(wrapped) => owner.unwrap_key(wrapped).ok(),
        None => Some(owner.clone()),
    }
}

pub fn decrypt_item(raw: &Value, keys: &Keys) -> Item {
    let key = item_key(raw, keys);
    let mut r = Reader {
        key: key.as_ref(),
        unreadable: 0,
    };
    let string = |name: &str| field_str(raw, name).map(str::to_string);
    let kind = ItemKind::from_code(field_u64(raw, "type").unwrap_or(0) as u8);
    let mut item = Item::new(kind, string("organizationId"), string("folderId"));
    item.id = string("id").unwrap_or_default();
    item.collection_ids = field(raw, "collectionIds")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    item.name = r.get(Some(raw), "name");
    item.notes = r.get(Some(raw), "notes");
    item.favorite = field(raw, "favorite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    item.reprompt = field_u64(raw, "reprompt").unwrap_or(0) == 1;
    item.deleted = field(raw, "deletedDate").is_some_and(|v| !v.is_null());
    item.archived = field(raw, "archivedDate").is_some_and(|v| !v.is_null());
    item.editable = field(raw, "edit").and_then(Value::as_bool).unwrap_or(true);
    item.view_password = field(raw, "viewPassword")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    item.created = string("creationDate").unwrap_or_default();
    item.revised = string("revisionDate").unwrap_or_default();

    let login = field(raw, "login").filter(|v| v.is_object());
    item.login.username = r.get(login, "username");
    item.login.password = r.get(login, "password");
    item.login.totp = r.get(login, "totp");
    if let Some(uris) = login
        .and_then(|l| field(l, "uris"))
        .and_then(Value::as_array)
    {
        for uri in uris {
            let value = r.get(Some(uri), "uri");
            item.login.uris.push(Uri {
                uri: value,
                match_type: field_u64(uri, "match").map(|m| m as u8),
            });
        }
    }
    if let Some(list) = login
        .and_then(|l| field(l, "fido2Credentials"))
        .and_then(Value::as_array)
    {
        item.login.passkeys = list.len();
        for credential in list {
            // Unreadable passkey text is not counted: saving never rewrites it.
            let mut names = Reader {
                key: key.as_ref(),
                unreadable: 0,
            };
            item.login.passkey_details.push(Passkey {
                credential_id: names.get(Some(credential), "credentialId"),
                rp_id: names.get(Some(credential), "rpId"),
                rp_name: names.get(Some(credential), "rpName"),
                user_name: names.get(Some(credential), "userName"),
                user_display_name: names.get(Some(credential), "userDisplayName"),
                created: field_str(credential, "creationDate")
                    .unwrap_or_default()
                    .to_string(),
            });
        }
    }

    let card = field(raw, "card").filter(|v| v.is_object());
    item.card = Card {
        cardholder_name: r.get(card, "cardholderName"),
        brand: r.get(card, "brand"),
        number: r.get(card, "number"),
        exp_month: r.get(card, "expMonth"),
        exp_year: r.get(card, "expYear"),
        code: r.get(card, "code"),
    };

    let identity = field(raw, "identity").filter(|v| v.is_object());
    for (name, _, _) in IDENTITY_FIELDS {
        let value = r.get(identity, name);
        if !value.is_empty() {
            item.identity.insert(name.to_string(), value);
        }
    }

    let ssh = field(raw, "sshKey").filter(|v| v.is_object());
    item.ssh_key = SshKey {
        private_key: r.get(ssh, "privateKey"),
        public_key: r.get(ssh, "publicKey"),
        fingerprint: r.get(ssh, "keyFingerprint"),
    };

    if let Some(fields) = field(raw, "fields").and_then(Value::as_array) {
        for f in fields {
            item.fields.push(CustomField {
                name: r.get(Some(f), "name"),
                value: r.get(Some(f), "value"),
                kind: FieldType::from_code(field_u64(f, "type").unwrap_or(0)),
                linked_id: field_u64(f, "linkedId"),
            });
        }
    }
    if let Some(history) = field(raw, "passwordHistory").and_then(Value::as_array) {
        for h in history {
            item.password_history.push(PasswordEntry {
                password: r.get(Some(h), "password"),
                last_used: field_str(h, "lastUsedDate").unwrap_or_default().to_string(),
            });
        }
    }
    item.unreadable = r.unreadable;
    // Attachment names are never re-encrypted when the item is saved, so
    // one that cannot be read does not stop the item from being edited.
    let mut names = Reader {
        key: key.as_ref(),
        unreadable: 0,
    };
    if let Some(attachments) = field(raw, "attachments").and_then(Value::as_array) {
        for a in attachments {
            item.attachments.push(Attachment {
                id: field_str(a, "id").unwrap_or_default().to_string(),
                file_name: names.get(Some(a), "fileName"),
                size: number_or_string(a, "size").unwrap_or(0),
                size_name: field_str(a, "sizeName").unwrap_or_default().to_string(),
            });
        }
    }
    item.raw = raw.clone();
    item
}

/// Reads a whole number sent either as a JSON number or as a string, as
/// Vaultwarden and Bitwarden send file sizes as strings.
pub(crate) fn number_or_string(value: &Value, name: &str) -> Option<u64> {
    match field(value, name)? {
        Value::String(s) => s.trim().parse().ok(),
        other => other.as_u64(),
    }
}

/// Encrypts `value`, or gives JSON null for an empty string, as Bitwarden does.
fn enc(key: &SymmetricKey, value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(key.encrypt_str(value))
    }
}

fn sub_object(raw: &Value, name: &str) -> Map<String, Value> {
    field(raw, name)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// Builds the request body that saves `item`. Existing items keep every
/// part of their original JSON that Hushjar does not edit.
pub fn encrypt_item(item: &Item, keys: &Keys) -> Result<Value, VaultError> {
    if !item.kind.editable() {
        return Err(VaultError::ReadOnlyType);
    }
    if item.unreadable > 0 {
        return Err(VaultError::Unreadable);
    }
    let key = if item.raw.is_null() {
        keys.owner(item.organization_id.as_deref()).cloned()
    } else {
        item_key(&item.raw, keys)
    }
    .ok_or(VaultError::MissingKey)?;
    let raw = &item.raw;

    let mut body = Map::new();
    body.insert("type".into(), json!(item.kind.code()));
    body.insert("organizationId".into(), json!(item.organization_id));
    body.insert("folderId".into(), json!(item.folder_id));
    body.insert("name".into(), enc(&key, &item.name));
    body.insert("notes".into(), enc(&key, &item.notes));
    body.insert("favorite".into(), json!(item.favorite));
    body.insert("reprompt".into(), json!(u8::from(item.reprompt)));
    body.insert(
        "key".into(),
        field(raw, "key").cloned().unwrap_or(Value::Null),
    );
    if let Some(revision) = field_str(raw, "revisionDate") {
        body.insert("lastKnownRevisionDate".into(), json!(revision));
    }
    // Vaultwarden unarchives an item whose update carries no archive date,
    // so the current one is always sent back.
    body.insert(
        "archivedDate".into(),
        field(raw, "archivedDate").cloned().unwrap_or(Value::Null),
    );
    for name in ["login", "card", "identity", "secureNote", "sshKey"] {
        body.insert(name.into(), Value::Null);
    }

    match item.kind {
        ItemKind::Login => {
            let mut login = sub_object(raw, "login");
            let old_password = login.get("password").cloned();
            login.insert("username".into(), enc(&key, &item.login.username));
            login.insert("password".into(), enc(&key, &item.login.password));
            login.insert("totp".into(), enc(&key, &item.login.totp));
            let uris: Vec<Value> = item
                .login
                .uris
                .iter()
                .filter(|u| !u.uri.is_empty())
                .map(|u| {
                    let checksum = B64.encode(Sha256::digest(u.uri.as_bytes()));
                    json!({ "uri": enc(&key, &u.uri), "match": u.match_type, "uriChecksum": key.encrypt_str(&checksum) })
                })
                .collect();
            login.insert(
                "uri".into(),
                uris.first()
                    .map(|u| u["uri"].clone())
                    .unwrap_or(Value::Null),
            );
            login.insert("uris".into(), Value::Array(uris));
            let previous = decrypt_item(raw, keys).login.password.clone();
            if old_password.is_some() && previous != item.login.password {
                login.insert("passwordRevisionDate".into(), json!(now_iso()));
            }
            body.insert("login".into(), Value::Object(login));
        }
        ItemKind::SecureNote => {
            let mut note = sub_object(raw, "secureNote");
            note.entry("type").or_insert(json!(0));
            body.insert("secureNote".into(), Value::Object(note));
        }
        ItemKind::Card => {
            let mut card = sub_object(raw, "card");
            let c = &item.card;
            for (name, value) in [
                ("cardholderName", &c.cardholder_name),
                ("brand", &c.brand),
                ("number", &c.number),
                ("expMonth", &c.exp_month),
                ("expYear", &c.exp_year),
                ("code", &c.code),
            ] {
                card.insert(name.into(), enc(&key, value));
            }
            body.insert("card".into(), Value::Object(card));
        }
        ItemKind::Identity => {
            let mut identity = sub_object(raw, "identity");
            for (name, _, _) in IDENTITY_FIELDS {
                identity.insert(name.into(), enc(&key, item.identity_value(name)));
            }
            body.insert("identity".into(), Value::Object(identity));
        }
        ItemKind::SshKey => {
            let mut ssh = sub_object(raw, "sshKey");
            ssh.insert("privateKey".into(), enc(&key, &item.ssh_key.private_key));
            ssh.insert("publicKey".into(), enc(&key, &item.ssh_key.public_key));
            ssh.insert(
                "keyFingerprint".into(),
                enc(&key, &item.ssh_key.fingerprint),
            );
            body.insert("sshKey".into(), Value::Object(ssh));
        }
        ItemKind::Other(_) => unreachable!("checked above"),
    }

    let fields: Vec<Value> = item
        .fields
        .iter()
        .map(|f| json!({ "type": f.kind.code(), "name": enc(&key, &f.name), "value": enc(&key, &f.value), "linkedId": f.linked_id }))
        .collect();
    body.insert("fields".into(), Value::Array(fields));
    let history: Vec<Value> = item
        .password_history
        .iter()
        .map(|h| json!({ "password": enc(&key, &h.password), "lastUsedDate": h.last_used }))
        .collect();
    body.insert("passwordHistory".into(), Value::Array(history));
    Ok(Value::Object(body))
}

/// Removes the passkey with `credential_id` from the item's original JSON
/// and from its list of passkeys, so the next save drops it and keeps the
/// others unchanged. Returns whether a passkey was found.
pub fn remove_passkey(item: &mut Item, credential_id: &str) -> bool {
    let Some(position) = item
        .login
        .passkey_details
        .iter()
        .position(|p| p.credential_id == credential_id)
    else {
        return false;
    };
    let Some(login) = item.raw.as_object_mut().and_then(|o| {
        o.iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case("login"))
            .map(|(_, v)| v)
    }) else {
        return false;
    };
    let Some(list) = login.as_object_mut().and_then(|o| {
        o.iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case("fido2Credentials"))
            .and_then(|(_, v)| v.as_array_mut())
    }) else {
        return false;
    };
    if position >= list.len() {
        return false;
    }
    list.remove(position);
    item.login.passkey_details.remove(position);
    item.login.passkeys = list.len();
    true
}

/// Re-encrypts every encrypted string in `value` from one key to another.
fn recrypt(value: &mut Value, from: &SymmetricKey, to: &SymmetricKey) -> Result<(), VaultError> {
    match value {
        Value::String(text) => {
            if let Ok(parsed @ EncString::AesCbcHmac { .. }) = text.parse::<EncString>() {
                let plain = from.decrypt(&parsed).map_err(|_| VaultError::Unreadable)?;
                *text = to.encrypt(&plain).to_string();
            }
        }
        Value::Array(list) => {
            for entry in list {
                recrypt(entry, from, to)?;
            }
        }
        Value::Object(map) => {
            for entry in map.values_mut() {
                recrypt(entry, from, to)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Builds the request that moves a personal item into an organisation.
///
/// As in the Bitwarden clients, an item with its own key keeps its fields
/// and attachments and only has that key re-wrapped with the organisation
/// key. An older item without one gets a new item key: every field is
/// re-encrypted with it, and attachment keys and names are re-wrapped to it.
/// Attachments from before per-file keys cannot be re-wrapped, so the item
/// is refused. The result is the `cipher` part of the share request.
pub fn share_body(item: &Item, keys: &Keys, organization: &str) -> Result<Value, VaultError> {
    let org_key = keys
        .organizations
        .get(organization)
        .ok_or(VaultError::MissingKey)?;
    if item.attachments.iter().any(|a| {
        field(&item.raw, "attachments")
            .and_then(Value::as_array)
            .and_then(|list| {
                list.iter()
                    .find(|x| field_str(x, "id") == Some(a.id.as_str()))
            })
            .and_then(|x| field_str(x, "key"))
            .is_none()
    }) {
        return Err(VaultError::LegacyAttachment);
    }
    let old_key = item_key(&item.raw, keys).ok_or(VaultError::MissingKey)?;
    let mut moved = item.clone();
    moved.organization_id = Some(organization.to_string());
    moved.collection_ids = vec![];
    let mut cipher = encrypt_item(&moved, keys)?;
    let mut attachments = Map::new();
    if field_str(&item.raw, "key").is_some() {
        cipher["key"] = json!(org_key.wrap_key(&old_key));
    } else {
        let new_key = SymmetricKey::generate();
        let Value::Object(map) = &mut cipher else {
            return Err(VaultError::Unreadable);
        };
        for (name, entry) in map.iter_mut() {
            if name != "key" {
                recrypt(entry, &old_key, &new_key)?;
            }
        }
        map.insert("key".into(), json!(org_key.wrap_key(&new_key)));
        for a in field(&item.raw, "attachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(id), Some(name), Some(wrapped)) = (
                field_str(a, "id"),
                field_str(a, "fileName"),
                field_str(a, "key"),
            ) else {
                return Err(VaultError::LegacyAttachment);
            };
            let mut name = json!(name);
            recrypt(&mut name, &old_key, &new_key)?;
            let file_key = old_key
                .unwrap_key(wrapped)
                .map_err(|_| VaultError::Unreadable)?;
            attachments.insert(
                id.to_string(),
                json!({ "fileName": name, "key": new_key.wrap_key(&file_key) }),
            );
        }
        if !attachments.is_empty() {
            cipher["attachments2"] = Value::Object(attachments.clone());
        }
    }
    Ok(cipher)
}

/// The current time as an ISO 8601 UTC timestamp, as Bitwarden uses.
pub fn now_iso() -> String {
    iso_in(0)
}

/// The time `seconds` from now as an ISO 8601 UTC timestamp.
pub fn iso_in(seconds: i64) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
        + seconds;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_date(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The (year, month, day) of a day counted from 1970-01-01, using Howard
/// Hinnant's civil-from-days algorithm.
pub(crate) fn civil_date(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys {
            user: SymmetricKey::generate(),
            organizations: HashMap::new(),
        }
    }

    #[test]
    fn login_round_trip_keeps_unknown_data() {
        let keys = keys();
        let k = &keys.user;
        let raw = json!({
            "id": "abc", "type": 1, "name": k.encrypt_str("Mail"), "notes": null, "favorite": true,
            "revisionDate": "2026-01-01T00:00:00Z",
            "login": {
                "username": k.encrypt_str("sam"), "password": k.encrypt_str("old"),
                "uris": [{ "uri": k.encrypt_str("https://mail.example"), "match": 2 }],
                "fido2Credentials": [{ "credentialId": "kept" }],
            },
            "fields": [{ "type": 1, "name": k.encrypt_str("PIN"), "value": k.encrypt_str("1234") }],
        });
        let original = decrypt_item(&raw, &keys);
        assert_eq!(original.name, "Mail");
        assert_eq!(original.login.uris[0].match_type, Some(2));
        assert_eq!(original.login.passkeys, 1);
        assert_eq!(original.fields[0].kind, FieldType::Hidden);

        let mut edited = original.clone();
        edited.login.password = "new".into();
        edited.note_password_change(&original);
        let body = encrypt_item(&edited, &keys).unwrap();
        assert_eq!(body["login"]["fido2Credentials"][0]["credentialId"], "kept");
        assert_eq!(body["lastKnownRevisionDate"], "2026-01-01T00:00:00Z");
        assert!(body["login"]["passwordRevisionDate"].is_string());

        // What the server would store decrypts to the edit.
        let mut stored = body.clone();
        stored["id"] = json!("abc");
        let back = decrypt_item(&stored, &keys);
        assert_eq!(back.login.password, "new");
        assert_eq!(back.password_history[0].password, "old");
        assert_eq!(back.login.uris[0].uri, "https://mail.example");
        let checksum = keys
            .user
            .decrypt_str(stored["login"]["uris"][0]["uriChecksum"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            checksum.as_str(),
            B64.encode(Sha256::digest(b"https://mail.example"))
        );
    }

    #[test]
    fn item_keys_are_used_and_kept() {
        let keys = keys();
        let item_key = SymmetricKey::generate();
        let raw = json!({
            "id": "x", "type": 2, "key": keys.user.wrap_key(&item_key),
            "name": item_key.encrypt_str("Note"), "secureNote": { "type": 0 },
        });
        let item = decrypt_item(&raw, &keys);
        assert_eq!(item.name, "Note");
        let body = encrypt_item(&item, &keys).unwrap();
        assert_eq!(body["key"], raw["key"]);
        assert_eq!(
            item_key
                .decrypt_str(body["name"].as_str().unwrap())
                .unwrap()
                .as_str(),
            "Note"
        );
    }

    #[test]
    fn attachments_are_listed_and_left_alone_by_edits() {
        let keys = keys();
        let item_key = SymmetricKey::generate();
        let other = SymmetricKey::generate();
        let raw = json!({
            "id": "x", "type": 2, "key": keys.user.wrap_key(&item_key),
            "name": item_key.encrypt_str("Note"), "secureNote": { "type": 0 },
            "attachments": [
                { "id": "a1", "fileName": item_key.encrypt_str("scan.pdf"), "key": item_key.wrap_key(&SymmetricKey::generate()),
                  "size": "1234", "sizeName": "1.21 KB", "url": "https://x" },
                { "id": "a2", "fileName": other.encrypt_str("lost.txt"), "key": null, "size": 99, "sizeName": "99 Bytes" },
            ],
        });
        let item = decrypt_item(&raw, &keys);
        assert_eq!(item.attachments.len(), 2);
        assert_eq!(item.attachments[0].file_name, "scan.pdf");
        assert_eq!(item.attachments[0].size, 1234);
        assert_eq!(item.attachments[0].size_name, "1.21 KB");
        assert_eq!(item.attachments[1].file_name, UNREADABLE);
        assert_eq!(item.attachments[1].size, 99);
        // An unreadable attachment name does not block editing the item,
        // and the save request does not touch attachments at all.
        assert_eq!(item.unreadable, 0);
        let body = encrypt_item(&item, &keys).unwrap();
        assert!(body.get("attachments").is_none() && body.get("attachments2").is_none());
    }

    #[test]
    fn unreadable_items_are_not_saved() {
        let keys = keys();
        let other = SymmetricKey::generate();
        let raw = json!({ "id": "x", "type": 2, "name": other.encrypt_str("Secret") });
        let item = decrypt_item(&raw, &keys);
        assert_eq!(item.name, UNREADABLE);
        assert!(matches!(
            encrypt_item(&item, &keys),
            Err(VaultError::Unreadable)
        ));
    }

    #[test]
    fn unknown_types_are_read_only() {
        let keys = keys();
        let raw = json!({ "id": "x", "type": 9, "name": keys.user.encrypt_str("Bank") });
        let item = decrypt_item(&raw, &keys);
        assert_eq!(item.kind, ItemKind::Other(9));
        assert!(matches!(
            encrypt_item(&item, &keys),
            Err(VaultError::ReadOnlyType)
        ));
    }

    fn passkey(key: &SymmetricKey, id: &str, site: &str) -> Value {
        json!({
            "credentialId": key.encrypt_str(id), "keyType": key.encrypt_str("public-key"),
            "keyValue": key.encrypt_str("not-a-real-key"), "rpId": key.encrypt_str(site),
            "rpName": key.encrypt_str("Example"), "userName": key.encrypt_str("sam"),
            "userDisplayName": key.encrypt_str("Sam Example"),
            "creationDate": "2026-02-03T04:05:06.789Z",
        })
    }

    #[test]
    fn passkeys_are_listed_and_removed_alone() {
        let keys = keys();
        let k = &keys.user;
        let raw = json!({
            "id": "p", "type": 1, "name": k.encrypt_str("Site"),
            "login": { "fido2Credentials": [passkey(k, "one", "a.example"), passkey(k, "two", "b.example")] },
        });
        let mut item = decrypt_item(&raw, &keys);
        assert_eq!(item.login.passkeys, 2);
        let details = &item.login.passkey_details;
        assert_eq!(details[1].rp_id, "b.example");
        assert_eq!(details[1].user_display_name, "Sam Example");
        assert_eq!(details[1].created, "2026-02-03T04:05:06.789Z");

        assert!(!remove_passkey(&mut item, "nope"));
        assert!(remove_passkey(&mut item, "one"));
        assert_eq!(item.login.passkeys, 1);
        assert_eq!(item.login.passkey_details[0].credential_id, "two");
        let body = encrypt_item(&item, &keys).unwrap();
        assert_eq!(
            body["login"]["fido2Credentials"],
            json!([raw["login"]["fido2Credentials"][1].clone()])
        );
    }

    #[test]
    fn saving_keeps_the_archive_date() {
        let keys = keys();
        let raw = json!({
            "id": "a", "type": 2, "name": keys.user.encrypt_str("Old"),
            "archivedDate": "2026-03-04T05:06:07.000Z",
        });
        let item = decrypt_item(&raw, &keys);
        assert!(item.archived);
        let body = encrypt_item(&item, &keys).unwrap();
        assert_eq!(body["archivedDate"], "2026-03-04T05:06:07.000Z");
    }

    fn with_org() -> (Keys, SymmetricKey) {
        let mut keys = keys();
        let org = SymmetricKey::generate();
        keys.organizations.insert("org".into(), org.clone());
        (keys, org)
    }

    #[test]
    fn sharing_an_item_with_a_key_only_rewraps_the_key() {
        let (keys, org) = with_org();
        let item_key = SymmetricKey::generate();
        let file_key = SymmetricKey::generate();
        let raw = json!({
            "id": "x", "type": 2, "key": keys.user.wrap_key(&item_key),
            "name": item_key.encrypt_str("Note"), "secureNote": { "type": 0 },
            "attachments": [{ "id": "a1", "fileName": item_key.encrypt_str("f"), "key": item_key.wrap_key(&file_key) }],
        });
        let item = decrypt_item(&raw, &keys);
        let body = share_body(&item, &keys, "org").unwrap();
        assert_eq!(body["organizationId"], "org");
        assert!(body.get("attachments2").is_none());
        let unwrapped = org.unwrap_key(body["key"].as_str().unwrap()).unwrap();
        assert_eq!(unwrapped.to_bytes(), item_key.to_bytes());
        assert_eq!(
            unwrapped
                .decrypt_str(body["name"].as_str().unwrap())
                .unwrap()
                .as_str(),
            "Note"
        );
    }

    #[test]
    fn sharing_an_item_without_a_key_gives_it_one() {
        let (keys, org) = with_org();
        let k = &keys.user;
        let file_key = SymmetricKey::generate();
        let raw = json!({
            "id": "x", "type": 1, "name": k.encrypt_str("Site"),
            "login": { "username": k.encrypt_str("sam"), "fido2Credentials": [passkey(k, "one", "a.example")] },
            "attachments": [{ "id": "a1", "fileName": k.encrypt_str("f.txt"), "key": k.wrap_key(&file_key) }],
        });
        let item = decrypt_item(&raw, &keys);
        let body = share_body(&item, &keys, "org").unwrap();
        let new_key = org.unwrap_key(body["key"].as_str().unwrap()).unwrap();
        // The server copy decrypts with the organisation key and the new item key.
        let mut stored = body.clone();
        stored["id"] = json!("x");
        let back = decrypt_item(&stored, &keys);
        assert_eq!(back.name, "Site");
        assert_eq!(back.login.username, "sam");
        assert_eq!(back.login.passkey_details[0].rp_id, "a.example");
        assert_eq!(back.unreadable, 0);
        // Its attachment's name and key are re-wrapped to the new item key.
        let moved = &body["attachments2"]["a1"];
        assert_eq!(
            new_key
                .decrypt_str(moved["fileName"].as_str().unwrap())
                .unwrap()
                .as_str(),
            "f.txt"
        );
        let file = new_key.unwrap_key(moved["key"].as_str().unwrap()).unwrap();
        assert_eq!(file.to_bytes(), file_key.to_bytes());
    }

    #[test]
    fn old_style_attachments_block_a_move() {
        let (keys, _) = with_org();
        let raw = json!({
            "id": "x", "type": 2, "name": keys.user.encrypt_str("Note"), "secureNote": { "type": 0 },
            "attachments": [{ "id": "a1", "fileName": keys.user.encrypt_str("f"), "key": null }],
        });
        let item = decrypt_item(&raw, &keys);
        assert!(matches!(
            share_body(&item, &keys, "org"),
            Err(VaultError::LegacyAttachment)
        ));
        assert!(matches!(
            share_body(&item, &keys, "other"),
            Err(VaultError::MissingKey)
        ));
    }

    #[test]
    fn iso_time_shape() {
        let now = now_iso();
        assert_eq!(now.len(), 24);
        assert!(now.ends_with(".000Z") && now.starts_with("20"));
    }
}
