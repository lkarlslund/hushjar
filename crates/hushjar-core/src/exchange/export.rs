//! Export of the vault in Bitwarden's formats, so Bitwarden and other tools
//! can import the files again.
//!
//! The layouts mirror Bitwarden's clients (bitwarden/clients on GitHub):
//! - `libs/tools/export-vault-core/src/services/individual-vault-export.service.ts`
//!   and `org-vault-export.service.ts`: which items and folders or collections
//!   go in, the `encrypted` flag, and `encKeyValidation_DO_NOT_EDIT`.
//! - `libs/tools/export-vault-core/src/services/base-vault-export.service.ts`:
//!   the CSV columns and the password-protected wrapper.
//! - `libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts`
//!   and `bitwarden-csv-export-type.ts`: the document shapes.
//! - `libs/common/src/models/export/*.export.ts` (cipher, login, login-uri,
//!   fido2-credential, field, card, identity, secure-note, ssh-key,
//!   password-history, collection): the per-item layout.
//! - `libs/legacy-crypto/src/services/default-key-generation.service.ts`
//!   (`deriveVaultExportKey`): the KDF over the password with the base64 salt
//!   text as salt, then HKDF stretching.
//!
//! JSON exports are built from each item's original server JSON rather than
//! from the editing model, so passkeys, newer item types and anything else
//! Hushjar does not edit are exported too. Deleted items are left out, as in
//! Bitwarden.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::ExchangeError;
use crate::api::{field, field_str, field_u64};
use crate::crypto::{self, Kdf, SymmetricKey};
use crate::vault::{Item, ItemKind, Keys, Vault};

/// Whose items an export covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope<'a> {
    /// The personal vault: items without an organisation, with folders.
    Personal,
    /// One organisation: its items, with collections instead of folders.
    Organization(&'a str),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Plain,
    Encrypted,
}

fn in_scope(item: &Item, scope: Scope) -> bool {
    !item.deleted
        && !item.raw.is_null()
        && match scope {
            Scope::Personal => item.organization_id.is_none(),
            Scope::Organization(id) => item.organization_id.as_deref() == Some(id),
        }
}

/// The key that opens the export's items and names.
fn owner_key<'a>(keys: &'a Keys, scope: Scope) -> Result<&'a SymmetricKey, ExchangeError> {
    match scope {
        Scope::Personal => Ok(&keys.user),
        Scope::Organization(id) => keys
            .organizations
            .get(id)
            .ok_or(ExchangeError::UnknownOrganization),
    }
}

/// Decrypts or passes on the encrypted strings of one item.
struct Converter<'a> {
    key: &'a SymmetricKey,
    mode: Mode,
    item: &'a str,
}

impl Converter<'_> {
    /// An encrypted text value: kept as is in encrypted exports, decrypted
    /// otherwise. Empty values become null.
    fn text(&self, value: Option<&Value>) -> Result<Value, ExchangeError> {
        let Some(Value::String(text)) = value else {
            return Ok(Value::Null);
        };
        if self.mode == Mode::Encrypted {
            return Ok(json!(text));
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        self.key
            .decrypt_str(text)
            .map(|plain| Value::String(plain.to_string()))
            .map_err(|_| ExchangeError::Unreadable(format!("item {}", self.item)))
    }

    /// Copies an object, converting every string value. Used for the item
    /// types whose strings are all encrypted.
    fn all_strings(&self, object: &Value) -> Result<Value, ExchangeError> {
        let mut out = Map::new();
        for (name, value) in object.as_object().into_iter().flatten() {
            out.insert(camel(name), self.text(Some(value))?);
        }
        Ok(Value::Object(out))
    }

    fn pick(&self, object: &Value, names: &[&str]) -> Result<Map<String, Value>, ExchangeError> {
        let mut out = Map::new();
        for name in names {
            out.insert((*name).to_string(), self.text(field(object, name))?);
        }
        Ok(out)
    }

    fn login(&self, login: &Value) -> Result<Value, ExchangeError> {
        let mut out = Map::new();
        let mut uris = Vec::new();
        for uri in field(login, "uris")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut entry = Map::new();
            entry.insert("uri".into(), self.text(field(uri, "uri"))?);
            if self.mode == Mode::Encrypted {
                entry.insert(
                    "uriChecksum".into(),
                    field(uri, "uriChecksum").cloned().unwrap_or(Value::Null),
                );
            }
            entry.insert(
                "match".into(),
                field(uri, "match").cloned().unwrap_or(Value::Null),
            );
            uris.push(Value::Object(entry));
        }
        out.insert("uris".into(), Value::Array(uris));
        for name in ["username", "password", "totp"] {
            out.insert(name.into(), self.text(field(login, name))?);
        }
        if let Some(flag) = field(login, "httpAuthenticationEnabled") {
            out.insert("httpAuthenticationEnabled".into(), flag.clone());
        }
        if let Some(list) = field(login, "fido2Credentials").and_then(Value::as_array) {
            let mut credentials = Vec::new();
            for credential in list {
                let mut entry = self.pick(
                    credential,
                    &[
                        "credentialId",
                        "keyType",
                        "keyAlgorithm",
                        "keyCurve",
                        "keyValue",
                        "rpId",
                        "userHandle",
                        "userName",
                        "counter",
                        "rpName",
                        "userDisplayName",
                        "discoverable",
                    ],
                )?;
                entry.insert(
                    "creationDate".into(),
                    iso_ms(field(credential, "creationDate")),
                );
                credentials.push(Value::Object(entry));
            }
            out.insert("fido2Credentials".into(), Value::Array(credentials));
        }
        Ok(Value::Object(out))
    }
}

/// Lower-cases the first letter, as Bitwarden's JSON names do.
fn camel(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// A date as JavaScript writes it: UTC with exactly three decimals.
fn iso_ms(value: Option<&Value>) -> Value {
    let Some(text) = value.and_then(Value::as_str) else {
        return Value::Null;
    };
    let text = text.trim_end_matches('Z');
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let fraction: String = fraction.chars().chain("000".chars()).take(3).collect();
    json!(format!("{whole}.{fraction}Z"))
}

/// One item in Bitwarden's export layout, from its server JSON. `owner` is
/// the account or organisation key the item belongs to. For encrypted
/// exports the encrypted strings are passed on untouched.
pub(crate) fn item_json(
    raw: &Value,
    owner: &SymmetricKey,
    mode: Mode,
    with_collections: bool,
) -> Result<Value, ExchangeError> {
    let id = field_str(raw, "id").unwrap_or_default();
    let item_key = match field_str(raw, "key") {
        Some(wrapped) => owner
            .unwrap_key(wrapped)
            .map_err(|_| ExchangeError::Unreadable(format!("item {id}")))?,
        None => owner.clone(),
    };
    let c = Converter {
        key: &item_key,
        mode,
        item: id,
    };
    let get = |name: &str| field(raw, name).cloned().unwrap_or(Value::Null);

    let mut out = Map::new();
    out.insert("id".into(), get("id"));
    out.insert("organizationId".into(), get("organizationId"));
    out.insert("folderId".into(), get("folderId"));
    out.insert("type".into(), get("type"));
    out.insert(
        "reprompt".into(),
        json!(field_u64(raw, "reprompt").unwrap_or(0)),
    );
    let name = c.text(field(raw, "name"))?;
    out.insert("name".into(), if name.is_null() { json!("") } else { name });
    out.insert("notes".into(), c.text(field(raw, "notes"))?);
    if mode == Mode::Encrypted
        && let Some(key) = field(raw, "key").filter(|k| k.is_string())
    {
        out.insert("key".into(), key.clone());
    }
    out.insert(
        "favorite".into(),
        json!(
            field(raw, "favorite")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        ),
    );
    if let Some(fields) = field(raw, "fields").and_then(Value::as_array) {
        let mut list = Vec::new();
        for f in fields {
            let mut entry = c.pick(f, &["name", "value"])?;
            entry.insert("type".into(), json!(field_u64(f, "type").unwrap_or(0)));
            entry.insert(
                "linkedId".into(),
                field(f, "linkedId").cloned().unwrap_or(Value::Null),
            );
            list.push(Value::Object(entry));
        }
        out.insert("fields".into(), Value::Array(list));
    }
    if let Some(login) = field(raw, "login").filter(|v| v.is_object()) {
        out.insert("login".into(), c.login(login)?);
    }
    if let Some(note) = field(raw, "secureNote").filter(|v| v.is_object()) {
        out.insert(
            "secureNote".into(),
            json!({ "type": field_u64(note, "type").unwrap_or(0) }),
        );
    }
    for name in [
        "card",
        "identity",
        "sshKey",
        "bankAccount",
        "driversLicense",
        "passport",
    ] {
        if let Some(object) = field(raw, name).filter(|v| v.is_object()) {
            out.insert(name.into(), c.all_strings(object)?);
        }
    }
    if let Some(history) = field(raw, "passwordHistory").and_then(Value::as_array) {
        let mut list = Vec::new();
        for entry in history {
            list.push(json!({
                "password": c.text(field(entry, "password"))?,
                "lastUsedDate": iso_ms(field(entry, "lastUsedDate")),
            }));
        }
        out.insert("passwordHistory".into(), Value::Array(list));
    }
    for (name, source) in [
        ("creationDate", "creationDate"),
        ("revisionDate", "revisionDate"),
        ("deletedDate", "deletedDate"),
        ("archivedDate", "archivedDate"),
    ] {
        out.insert(name.into(), iso_ms(field(raw, source)));
    }
    out.insert(
        "collectionIds".into(),
        if with_collections {
            get("collectionIds")
        } else {
            Value::Null
        },
    );
    Ok(Value::Object(out))
}

/// The whole export document.
fn document(vault: &Vault, keys: &Keys, scope: Scope, mode: Mode) -> Result<Value, ExchangeError> {
    let owner = owner_key(keys, scope)?;
    let mut doc = Map::new();
    doc.insert("encrypted".into(), json!(mode == Mode::Encrypted));
    if mode == Mode::Encrypted {
        doc.insert(
            "encKeyValidation_DO_NOT_EDIT".into(),
            json!(owner.encrypt_str(&uuid::Uuid::new_v4().to_string())),
        );
    }
    let name = |plain: &str| match mode {
        Mode::Plain => json!(plain),
        Mode::Encrypted => json!(owner.encrypt_str(plain)),
    };
    match scope {
        Scope::Personal => {
            let folders: Vec<Value> = vault
                .folders
                .iter()
                .filter(|f| !f.id.is_empty())
                .map(|f| json!({ "id": f.id, "name": name(&f.name) }))
                .collect();
            doc.insert("folders".into(), Value::Array(folders));
        }
        Scope::Organization(org) => {
            let collections: Vec<Value> = vault
                .collections
                .iter()
                .filter(|c| c.organization_id == org)
                .map(|c| {
                    json!({
                        "id": c.id,
                        "organizationId": c.organization_id,
                        "name": name(&c.name),
                        "externalId": null,
                    })
                })
                .collect();
            doc.insert("collections".into(), Value::Array(collections));
        }
    }
    let mut items = Vec::new();
    for item in vault.items.iter().filter(|i| in_scope(i, scope)) {
        let with_collections = matches!(scope, Scope::Organization(_));
        items.push(item_json(&item.raw, owner, mode, with_collections)?);
    }
    doc.insert("items".into(), Value::Array(items));
    Ok(Value::Object(doc))
}

fn pretty(doc: &Value) -> Result<Zeroizing<String>, ExchangeError> {
    Ok(Zeroizing::new(serde_json::to_string_pretty(doc)?))
}

/// Unencrypted JSON. Contains every secret in the clear.
pub fn json(vault: &Vault, keys: &Keys, scope: Scope) -> Result<Zeroizing<String>, ExchangeError> {
    pretty(&document(vault, keys, scope, Mode::Plain)?)
}

/// JSON locked to this account (or organisation): the values stay encrypted
/// with its key and only that account can import it.
pub fn encrypted_json(
    vault: &Vault,
    keys: &Keys,
    scope: Scope,
) -> Result<Zeroizing<String>, ExchangeError> {
    pretty(&document(vault, keys, scope, Mode::Encrypted)?)
}

/// JSON encrypted with a key derived from `password`, using the account's
/// own key derivation settings, as Bitwarden does.
pub fn password_protected_json(
    vault: &Vault,
    keys: &Keys,
    scope: Scope,
    kdf: Kdf,
    password: &str,
) -> Result<Zeroizing<String>, ExchangeError> {
    let clear = json(vault, keys, scope)?;
    protect(&clear, kdf, password)
}

/// The key that protects a password-protected export.
pub(crate) fn export_key(
    password: &str,
    salt: &str,
    kdf: Kdf,
) -> Result<SymmetricKey, ExchangeError> {
    let material = crypto::derive_kdf(password, salt.as_bytes(), kdf)?;
    Ok(crypto::stretch(&material))
}

/// Wraps clear text in Bitwarden's password-protected file format.
pub fn protect(clear: &str, kdf: Kdf, password: &str) -> Result<Zeroizing<String>, ExchangeError> {
    if password.is_empty() {
        return Err(ExchangeError::EmptyPassword);
    }
    let salt = B64.encode(crypto::random_bytes::<16>());
    let key = export_key(password, &salt, kdf)?;
    let mut doc = Map::new();
    doc.insert("encrypted".into(), json!(true));
    doc.insert("passwordProtected".into(), json!(true));
    doc.insert("salt".into(), json!(salt));
    let (kind, iterations) = match kdf {
        Kdf::Pbkdf2 { iterations } => (0, iterations),
        Kdf::Argon2id { iterations, .. } => (1, iterations),
    };
    doc.insert("kdfType".into(), json!(kind));
    doc.insert("kdfIterations".into(), json!(iterations));
    doc.insert(
        "encKeyValidation_DO_NOT_EDIT".into(),
        json!(key.encrypt_str(&uuid::Uuid::new_v4().to_string())),
    );
    doc.insert("data".into(), json!(key.encrypt_str(clear)));
    if let Kdf::Argon2id {
        memory_mib,
        parallelism,
        ..
    } = kdf
    {
        doc.insert("kdfMemory".into(), json!(memory_mib));
        doc.insert("kdfParallelism".into(), json!(parallelism));
    }
    pretty(&Value::Object(doc))
}

/// A CSV of logins and secure notes with Bitwarden's columns. Other item
/// types are not part of Bitwarden's CSV format and are left out.
pub fn csv(vault: &Vault, scope: Scope) -> Result<Zeroizing<String>, ExchangeError> {
    let organization = matches!(scope, Scope::Organization(_));
    let mut header: Vec<&str> = if organization {
        vec!["collections"]
    } else {
        vec!["folder", "favorite"]
    };
    header.extend([
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "archivedDate",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ]);
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(Vec::new());
    writer.write_record(&header)?;
    for item in vault.items.iter().filter(|i| in_scope(i, scope)) {
        if !matches!(item.kind, ItemKind::Login | ItemKind::SecureNote) {
            continue;
        }
        if item.unreadable > 0 {
            return Err(ExchangeError::Unreadable(format!("item {}", item.id)));
        }
        writer.write_record(csv_row(vault, item, organization))?;
    }
    let bytes = writer
        .into_inner()
        .map_err(|e| ExchangeError::Malformed(e.to_string()))?;
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| ExchangeError::Malformed("not valid text".into()))
}

fn csv_row(vault: &Vault, item: &Item, organization: bool) -> Vec<String> {
    let mut row = Vec::new();
    if organization {
        let names: Vec<&str> = item
            .collection_ids
            .iter()
            .filter_map(|id| vault.collections.iter().find(|c| &c.id == id))
            .map(|c| c.name.as_str())
            .collect();
        row.push(names.join(","));
    } else {
        let folder = item
            .folder_id
            .as_ref()
            .and_then(|id| vault.folders.iter().find(|f| &f.id == id));
        row.push(folder.map(|f| f.name.clone()).unwrap_or_default());
        row.push(if item.favorite {
            "1".into()
        } else {
            String::new()
        });
    }
    let login = item.kind == ItemKind::Login;
    row.push(if login { "login" } else { "note" }.into());
    row.push(item.name.clone());
    row.push(item.notes.clone());
    let fields: Vec<String> = item
        .fields
        .iter()
        .map(|f| format!("{}: {}", f.name, f.value))
        .collect();
    row.push(fields.join("\n"));
    row.push(u8::from(item.reprompt).to_string());
    row.push(
        field_str(&item.raw, "archivedDate")
            .map(|d| iso_ms(Some(&json!(d))))
            .and_then(|d| d.as_str().map(str::to_string))
            .unwrap_or_default(),
    );
    if login {
        let uris: Vec<&str> = item.login.uris.iter().map(|u| u.uri.as_str()).collect();
        row.push(uris.join(","));
        row.push(item.login.username.clone());
        row.push(item.login.password.clone());
        row.push(item.login.totp.clone());
    } else {
        row.extend(std::iter::repeat_n(String::new(), 4));
    }
    row
}
