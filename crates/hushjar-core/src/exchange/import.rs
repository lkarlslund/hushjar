//! Reading other password managers' exports and Bitwarden's own formats into
//! a format-neutral list of new items, and building the upload request.
//!
//! Each format follows the matching importer in Bitwarden's clients
//! (bitwarden/clients on GitHub, `libs/importer/src/importers/`):
//! - `bitwarden/bitwarden-json-importer.ts`, `bitwarden-encrypted-json-importer.ts`
//!   and `bitwarden-password-protected-importer.ts`: the three JSON variants,
//!   the `encKeyValidation_DO_NOT_EDIT` check and the KDF bounds
//!   (`password-protected-kdf-config.ts`).
//! - `bitwarden/bitwarden-csv-importer.ts`: columns `folder`, `favorite`,
//!   `type`, `name`, `notes`, `fields`, `reprompt`, `login_uri`,
//!   `login_username`, `login_password`, `login_totp`.
//! - `chrome-csv-importer.ts` (Chrome, Chromium, Edge): `name`, `url`,
//!   `username`, `password`, `note`.
//! - `firefox-csv-importer.ts`: `url` (or `hostname`), `username`, `password`.
//! - `safari-csv-importer.ts`: `Title`, `Url`/`URL`, `Username`, `Password`,
//!   `OTPAuth`, `Notes`.
//! - `keepassx-csv-importer.ts` (KeePassXC): `Group`, `Title`, `Username`,
//!   `Password`, `URL`, `Notes`, `TOTP`.
//! - `lastpass/lastpass-csv-importer.ts`: `url`, `username`, `password`,
//!   `totp`, `extra`, `name`, `grouping`, `fav`, plus the form-fill columns.
//! - `onepassword/onepassword-csv-importer.ts` and its Mac variant: a reduced
//!   version, see [`Format::OnePasswordCsv`].
//! - `base-importer.ts`: URI fix-ups, folder handling, `cleanupCipher`.
//!
//! Bitwarden has no Proton Pass CSV importer (only JSON), so none is offered.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use super::ExchangeError;
use super::export::{Mode, export_key, item_json};
use crate::api::{field, field_str, field_u64};
use crate::crypto::{Kdf, SymmetricKey};
use crate::vault::{
    CustomField, FieldType, IDENTITY_FIELDS, Item, ItemKind, Keys, PasswordEntry, Uri, Vault,
    VaultError,
};

/// The most items one import request may carry, as in Bitwarden's server.
pub const MAX_ITEMS: usize = 7000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Bitwarden JSON: unencrypted, account-locked or password-protected.
    BitwardenJson,
    BitwardenCsv,
    /// Chrome, Chromium and Edge share one CSV layout.
    ChromeCsv,
    FirefoxCsv,
    SafariCsv,
    KeePassXcCsv,
    LastPassCsv,
    /// Logins and notes only; other 1Password types become notes with their
    /// values as custom fields.
    OnePasswordCsv,
}

impl Format {
    pub const ALL: [Format; 8] = [
        Format::BitwardenJson,
        Format::BitwardenCsv,
        Format::ChromeCsv,
        Format::FirefoxCsv,
        Format::SafariCsv,
        Format::KeePassXcCsv,
        Format::LastPassCsv,
        Format::OnePasswordCsv,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Format::BitwardenJson => "Bitwarden (JSON)",
            Format::BitwardenCsv => "Bitwarden (CSV)",
            Format::ChromeCsv => "Chrome, Chromium or Edge (CSV)",
            Format::FirefoxCsv => "Firefox (CSV)",
            Format::SafariCsv => "Safari (CSV)",
            Format::KeePassXcCsv => "KeePassXC (CSV)",
            Format::LastPassCsv => "LastPass (CSV)",
            Format::OnePasswordCsv => "1Password (CSV)",
        }
    }
}

/// One item to create, with what the editing model cannot hold.
#[derive(Clone, Debug)]
pub struct ImportItem {
    pub item: Item,
    /// Index into [`ParsedImport::folders`].
    pub folder: Option<usize>,
    /// Passkeys in Bitwarden's plain export layout, encrypted on upload.
    pub passkeys: Vec<Value>,
}

#[derive(Clone, Debug)]
pub struct ParsedImport {
    pub format: Format,
    pub items: Vec<ImportItem>,
    /// Folder names, including the parents of nested names ("a/b" implies "a").
    pub folders: Vec<String>,
    /// Entries of types Hushjar cannot create yet.
    pub skipped: usize,
}

/// What the parser may need beyond the file: the account's keys to open an
/// account-locked JSON export, and the password of a protected one.
#[derive(Default)]
pub struct Context<'a> {
    pub keys: Option<&'a Keys>,
    pub password: Option<&'a str>,
}

/// Guesses the format from the file's start: JSON by its brace, CSV by its
/// header row.
pub fn detect(text: &str) -> Option<Format> {
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('{') {
        return Some(Format::BitwardenJson);
    }
    let mut reader = csv_reader(text);
    let headers: Vec<String> = reader.headers().ok()?.iter().map(str::to_string).collect();
    let has = |name: &str| headers.iter().any(|h| h == name);
    Some(
        if has("login_uri") || has("login_username") || has("login_password") {
            Format::BitwardenCsv
        } else if has("grouping") && has("extra") {
            Format::LastPassCsv
        } else if has("Group") && has("Title") {
            Format::KeePassXcCsv
        } else if has("httpRealm") || has("formActionOrigin") || has("guid") {
            Format::FirefoxCsv
        } else if has("Title") && (has("Url") || has("URL")) {
            Format::SafariCsv
        } else if has("Title") && has("Password") {
            Format::OnePasswordCsv
        } else if has("name") && has("url") && has("username") && has("password") {
            Format::ChromeCsv
        } else {
            return None;
        },
    )
}

/// Parses an export. With `format` unset the format is detected.
pub fn parse(
    text: &str,
    format: Option<Format>,
    context: &Context,
) -> Result<ParsedImport, ExchangeError> {
    let text = text.trim_start_matches('\u{feff}');
    let format = match format {
        Some(f) => f,
        None => detect(text).ok_or(ExchangeError::UnknownFormat)?,
    };
    if format == Format::BitwardenJson {
        return parse_bitwarden_json(text, context, 0);
    }
    let rows = read_rows(text)?;
    let mut parsed = ParsedImport {
        format,
        items: vec![],
        folders: vec![],
        skipped: 0,
    };
    match format {
        Format::BitwardenCsv => bitwarden_csv(&rows, &mut parsed),
        Format::ChromeCsv => chrome_csv(&rows, &mut parsed),
        Format::FirefoxCsv => firefox_csv(&rows, &mut parsed),
        Format::SafariCsv => safari_csv(&rows, &mut parsed),
        Format::KeePassXcCsv => keepassxc_csv(&rows, &mut parsed),
        Format::LastPassCsv => lastpass_csv(&rows, &mut parsed),
        Format::OnePasswordCsv => onepassword_csv(&rows, &mut parsed),
        Format::BitwardenJson => unreachable!("handled above"),
    }
    Ok(parsed)
}

// ---------------------------------------------------------------- JSON

fn parse_bitwarden_json(
    text: &str,
    context: &Context,
    depth: u8,
) -> Result<ParsedImport, ExchangeError> {
    let doc: Value = serde_json::from_str(text)?;
    let encrypted = field(&doc, "encrypted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let protected = field(&doc, "passwordProtected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if encrypted && protected {
        if depth > 0 {
            return Err(ExchangeError::Malformed("nested protection".into()));
        }
        let inner = open_protected(&doc, context)?;
        return parse_bitwarden_json(&inner, context, depth + 1);
    }
    let Some(items) = field(&doc, "items").and_then(Value::as_array) else {
        return Err(ExchangeError::Malformed("there is no list of items".into()));
    };
    let plain;
    let (items, folders, collections) = if encrypted {
        plain = open_account_locked(&doc, items, context)?;
        (&plain.0, &plain.1, &plain.2)
    } else {
        (
            items,
            &list(&doc, "folders", "id", "name"),
            &list(&doc, "collections", "id", "name"),
        )
    };
    Ok(build_from_json(items, folders, collections))
}

/// `(id, name)` pairs of a list in the document.
fn list(doc: &Value, name: &str, id: &str, label: &str) -> Vec<(String, String)> {
    field(doc, name)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| {
            (
                field_str(entry, id).unwrap_or_default().to_string(),
                field_str(entry, label).unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Decrypts a password-protected file and returns the clear JSON inside.
fn open_protected(doc: &Value, context: &Context) -> Result<String, ExchangeError> {
    let password = context.password.ok_or(ExchangeError::PasswordRequired)?;
    if password.trim().is_empty() {
        return Err(ExchangeError::WrongPassword);
    }
    let text = |name: &str| field_str(doc, name).filter(|s| !s.is_empty());
    let (Some(salt), Some(validation), Some(data)) = (
        text("salt"),
        text("encKeyValidation_DO_NOT_EDIT"),
        text("data"),
    ) else {
        return Err(ExchangeError::Malformed(
            "the protected file is incomplete".into(),
        ));
    };
    let number = |name: &str| field_u64(doc, name).and_then(|n| u32::try_from(n).ok());
    let kdf = Kdf::from_server(
        field_u64(doc, "kdfType")
            .and_then(|n| u8::try_from(n).ok())
            .unwrap_or(u8::MAX),
        number("kdfIterations").unwrap_or(0),
        number("kdfMemory"),
        number("kdfParallelism"),
    )
    .map_err(|_| ExchangeError::UnsupportedKdf)?;
    let key = export_key(password, salt, kdf)?;
    key.decrypt_str(validation)
        .map_err(|_| ExchangeError::WrongPassword)?;
    let clear = key
        .decrypt_str(data)
        .map_err(|_| ExchangeError::Malformed("the protected data is damaged".into()))?;
    Ok(clear.to_string())
}

type Opened = (Vec<Value>, Vec<(String, String)>, Vec<(String, String)>);

/// Decrypts an account-locked export, after checking its validation string
/// against the account's key (or an organisation key).
fn open_account_locked(
    doc: &Value,
    items: &[Value],
    context: &Context,
) -> Result<Opened, ExchangeError> {
    let keys = context.keys.ok_or(ExchangeError::WrongAccount)?;
    let validation = field_str(doc, "encKeyValidation_DO_NOT_EDIT")
        .filter(|s| !s.is_empty())
        .ok_or(ExchangeError::WrongAccount)?;
    let key: &SymmetricKey = std::iter::once(&keys.user)
        .chain(keys.organizations.values())
        .find(|k| k.decrypt_str(validation).is_ok())
        .ok_or(ExchangeError::WrongAccount)?;
    let mut plain = Vec::new();
    for item in items {
        plain.push(item_json(item, key, Mode::Plain, true)?);
    }
    let names = |name: &str| -> Result<Vec<(String, String)>, ExchangeError> {
        let mut out = Vec::new();
        for (id, encrypted) in list(doc, name, "id", "name") {
            let clear = key
                .decrypt_str(&encrypted)
                .map_err(|_| ExchangeError::Unreadable(format!("{name} {id}")))?;
            out.push((id, clear.to_string()));
        }
        Ok(out)
    };
    Ok((plain, names("folders")?, names("collections")?))
}

fn build_from_json(
    items: &[Value],
    folders: &[(String, String)],
    collections: &[(String, String)],
) -> ParsedImport {
    let mut parsed = ParsedImport {
        format: Format::BitwardenJson,
        items: vec![],
        folders: vec![],
        skipped: 0,
    };
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    // An organisation file has collections instead of folders; they become
    // folders, and an item in several lands in the first, as the server keeps
    // one folder per item.
    for (id, name) in folders.iter().chain(collections) {
        // Folder lists in Bitwarden files are complete, so no parents are added.
        if name.trim().is_empty() {
            continue;
        }
        let index = parsed
            .folders
            .iter()
            .position(|f| f == name)
            .unwrap_or_else(|| {
                parsed.folders.push(name.clone());
                parsed.folders.len() - 1
            });
        by_id.insert(id.as_str(), index);
    }
    for value in items {
        let Some(mut entry) = plain_item(value) else {
            parsed.skipped += 1;
            continue;
        };
        let folder = field_str(value, "folderId").and_then(|id| by_id.get(id));
        let collection = field(value, "collectionIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .find_map(|id| by_id.get(id));
        entry.folder = folder.or(collection).copied();
        parsed.items.push(entry);
    }
    parsed
}

/// An item from Bitwarden's plain export layout. None for types that cannot
/// be created here.
fn plain_item(value: &Value) -> Option<ImportItem> {
    let kind = ItemKind::from_code(u8::try_from(field_u64(value, "type")?).ok()?);
    if !kind.editable() || matches!(kind, ItemKind::Other(_)) {
        return None;
    }
    let text = |object: Option<&Value>, name: &str| -> String {
        object
            .and_then(|o| field_str(o, name))
            .unwrap_or_default()
            .to_string()
    };
    let mut item = Item::new(kind, None, None);
    item.name = blank_to(&text(Some(value), "name"), "--");
    item.notes = text(Some(value), "notes");
    item.favorite = field(value, "favorite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    item.reprompt = field_u64(value, "reprompt") == Some(1);
    let mut passkeys = Vec::new();
    match kind {
        ItemKind::Login => {
            let login = field(value, "login");
            item.login.username = text(login, "username");
            item.login.password = text(login, "password");
            item.login.totp = text(login, "totp");
            for uri in login
                .and_then(|l| field(l, "uris"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let uri_text = text(Some(uri), "uri");
                if !uri_text.trim().is_empty() {
                    item.login.uris.push(Uri {
                        uri: uri_text,
                        match_type: field_u64(uri, "match").and_then(|m| u8::try_from(m).ok()),
                    });
                }
            }
            passkeys = login
                .and_then(|l| field(l, "fido2Credentials"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            item.login.passkeys = passkeys.len();
        }
        ItemKind::Card => {
            let card = field(value, "card");
            item.card.cardholder_name = text(card, "cardholderName");
            item.card.brand = text(card, "brand");
            item.card.number = text(card, "number");
            item.card.exp_month = text(card, "expMonth");
            item.card.exp_year = text(card, "expYear");
            item.card.code = text(card, "code");
        }
        ItemKind::Identity => {
            let identity = field(value, "identity");
            for (name, _, _) in IDENTITY_FIELDS {
                let v = text(identity, name);
                if !v.is_empty() {
                    item.identity.insert(name.to_string(), v);
                }
            }
        }
        ItemKind::SshKey => {
            let ssh = field(value, "sshKey");
            item.ssh_key.private_key = text(ssh, "privateKey");
            item.ssh_key.public_key = text(ssh, "publicKey");
            item.ssh_key.fingerprint = text(ssh, "keyFingerprint");
        }
        _ => {}
    }
    for f in field(value, "fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        item.fields.push(CustomField {
            name: text(Some(f), "name"),
            value: text(Some(f), "value"),
            kind: match field_u64(f, "type") {
                Some(1) => FieldType::Hidden,
                Some(2) => FieldType::Boolean,
                Some(3) => FieldType::Linked,
                _ => FieldType::Text,
            },
            linked_id: field_u64(f, "linkedId"),
        });
    }
    // Bitwarden keeps five entries at most.
    for h in field(value, "passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(5)
    {
        item.password_history.push(PasswordEntry {
            password: text(Some(h), "password"),
            last_used: text(Some(h), "lastUsedDate"),
        });
    }
    Some(ImportItem {
        item,
        folder: None,
        passkeys,
    })
}

// ----------------------------------------------------------------- CSV

fn csv_reader(text: &str) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes())
}

/// One CSV row, looked up by column title.
struct Row(HashMap<String, String>);

impl Row {
    /// The value, or "" when the column is missing.
    fn get(&self, name: &str) -> &str {
        self.0.get(name).map(String::as_str).unwrap_or("")
    }

    /// The value unless it is empty or only white space (Bitwarden's
    /// `getValueOrDefault`).
    fn some(&self, name: &str) -> String {
        let v = self.get(name);
        if v.trim().is_empty() {
            String::new()
        } else {
            v.to_string()
        }
    }

    /// The first of several columns that has a value.
    fn first(&self, names: &[&str]) -> String {
        names
            .iter()
            .map(|n| self.some(n))
            .find(|v| !v.is_empty())
            .unwrap_or_default()
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

fn read_rows(text: &str) -> Result<Vec<Row>, ExchangeError> {
    let mut reader = csv_reader(text);
    let headers: Vec<String> = reader.headers()?.iter().map(str::to_string).collect();
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record?;
        let row: HashMap<String, String> = headers
            .iter()
            .cloned()
            .zip(record.iter().map(str::to_string))
            .collect();
        rows.push(Row(row));
    }
    if rows.is_empty() {
        return Err(ExchangeError::Malformed("the file has no entries".into()));
    }
    Ok(rows)
}

fn blank_to(value: &str, default: &str) -> String {
    if value.trim().is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

impl ParsedImport {
    fn push(&mut self, item: Item, folder: Option<usize>) {
        self.items.push(ImportItem {
            item,
            folder,
            passkeys: vec![],
        });
    }

    /// Finds or adds a folder, and the parents of a nested name, as
    /// Bitwarden's `processFolder` does. Backslashes count as slashes.
    fn folder_index(&mut self, name: &str) -> Option<usize> {
        if name.trim().is_empty() {
            return None;
        }
        let name = name.replace('\\', "/");
        let name = name.trim_start_matches('/');
        let index = match self.folders.iter().position(|f| f == name) {
            Some(i) => i,
            None => {
                self.folders.push(name.to_string());
                self.folders.len() - 1
            }
        };
        let parts: Vec<&str> = name.split('/').collect();
        for end in (1..parts.len()).rev() {
            let parent = parts[..end].join("/");
            if !self.folders.contains(&parent) {
                self.folders.push(parent);
            }
        }
        Some(index)
    }
}

/// Bitwarden's `fixUri`: trims, adds a scheme to bare host names, and caps
/// the length.
fn fix_uri(uri: &str) -> String {
    let mut uri = uri.trim().to_string();
    if !uri.contains("://") && uri.contains('.') {
        uri = format!("http://{uri}");
    }
    uri.chars().take(1000).collect()
}

fn uris<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<Uri> {
    values
        .into_iter()
        .map(fix_uri)
        .filter(|u| !u.trim().is_empty())
        .map(|uri| Uri {
            uri,
            match_type: None,
        })
        .collect()
}

/// A host name for naming an item, without "www.".
fn name_from_url(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    Some(host.strip_prefix("www.").unwrap_or(host).to_string())
}

fn login(name: &str, username: String, password: String, uris: Vec<Uri>) -> Item {
    let mut item = Item::new(ItemKind::Login, None, None);
    item.name = blank_to(name, "--");
    item.login.username = username;
    item.login.password = password;
    item.login.uris = uris;
    item
}

/// Bitwarden's `processKvp`: a short single-line value becomes a custom
/// field, anything else is appended to the notes.
fn add_pair(item: &mut Item, key: &str, value: &str, kind: FieldType) {
    if value.trim().is_empty() {
        return;
    }
    if value.chars().count() > 200 || value.trim().contains(['\n', '\r']) {
        let lines: Vec<&str> = value.lines().collect();
        item.notes
            .push_str(&format!("{key}: {}\n", lines.join("\n")));
    } else {
        item.fields.push(CustomField {
            name: key.to_string(),
            value: value.to_string(),
            kind,
            linked_id: None,
        });
    }
}

fn bitwarden_csv(rows: &[Row], out: &mut ParsedImport) {
    for row in rows {
        let folder = out.folder_index(row.get("folder"));
        let is_note = row.get("type").to_lowercase() == "note";
        let mut item = if is_note {
            Item::new(ItemKind::SecureNote, None, None)
        } else {
            let mut item = login(
                "",
                row.first(&["login_username", "username"]),
                row.first(&["login_password", "password"]),
                vec![],
            );
            item.login.totp = row.first(&["login_totp", "totp"]);
            let list = row.first(&["login_uri", "uri"]);
            item.login.uris = uris(single_row(&list).iter().map(String::as_str));
            item
        };
        item.name = blank_to(row.get("name"), "--");
        item.notes = row.some("notes");
        let favorite = blank_to(row.get("favorite"), "0");
        item.favorite = favorite != "0";
        item.reprompt = row.get("reprompt").trim().parse::<u8>() == Ok(1);
        for line in row.get("fields").lines() {
            if line.trim().is_empty() {
                continue;
            }
            // Split at the last ": " as Bitwarden does.
            let Some(at) = line.rfind(": ") else { continue };
            item.fields.push(CustomField {
                name: line[..at].to_string(),
                value: line[at + 2..].to_string(),
                kind: FieldType::Text,
                linked_id: None,
            });
        }
        out.push(item, folder);
    }
}

/// The values of a comma-separated list in one cell (several URIs), also
/// splitting at line breaks as older Bitwarden exports used.
fn single_row(cell: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(cell.as_bytes());
    for record in reader.records().flatten() {
        values.extend(record.iter().map(str::to_string));
    }
    values
}

/// Chrome writes Android apps as `android://<hash>@<package>/`.
fn android_package(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("android://")?;
    let (_, after) = rest.split_once('@')?;
    Some(after.split('/').next().unwrap_or(after))
}

fn chrome_csv(rows: &[Row], out: &mut ParsedImport) {
    for row in rows {
        let url = row.get("url");
        let package = android_package(url);
        let uri = package.map_or_else(|| url.to_string(), |p| format!("androidapp://{p}"));
        let mut name = row.some("name");
        if name.is_empty() {
            name = package.unwrap_or_default().to_string();
        }
        let mut item = login(
            &name,
            row.some("username"),
            row.some("password"),
            uris([uri.as_str()]),
        );
        item.notes = row.some("note");
        out.push(item, None);
    }
}

fn firefox_csv(rows: &[Row], out: &mut ParsedImport) {
    for row in rows
        .iter()
        .filter(|r| r.get("url") != "chrome://FirefoxAccounts")
    {
        let url = row.first(&["url", "hostname"]);
        let name = name_from_url(&url).unwrap_or_default();
        let item = login(
            &name,
            row.some("username"),
            row.some("password"),
            uris([url.as_str()]),
        );
        out.push(item, None);
    }
}

fn safari_csv(rows: &[Row], out: &mut ParsedImport) {
    for row in rows {
        let url = if row.has("Url") {
            row.get("Url")
        } else {
            row.get("URL")
        };
        let mut item = login(
            row.get("Title"),
            row.some("Username"),
            row.some("Password"),
            uris([url]),
        );
        item.login.totp = row.some("OTPAuth");
        item.notes = row.some("Notes");
        out.push(item, None);
    }
}

fn keepassxc_csv(rows: &[Row], out: &mut ParsedImport) {
    for row in rows {
        if row.get("Title").trim().is_empty() {
            continue;
        }
        let group = row.get("Group");
        let group = group.strip_prefix("Root/").unwrap_or(group);
        let folder = out.folder_index(group);
        let mut item = login(
            row.get("Title"),
            row.some("Username"),
            row.some("Password"),
            uris([row.get("URL")]),
        );
        item.notes = row.some("Notes");
        item.login.totp = row.some("TOTP");
        out.push(item, folder);
    }
}

fn lastpass_csv(rows: &[Row], out: &mut ParsedImport) {
    for row in rows {
        let grouping: String = row
            .get("grouping")
            .replace('\\', "/")
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let folder = if grouping == "(none)" {
            None
        } else {
            out.folder_index(&grouping)
        };
        let form_fill = row.has("profilename") && row.has("profilelanguage");
        if form_fill {
            lastpass_form(row, folder, out);
            continue;
        }
        let name = blank_to(row.get("name"), "--");
        let favorite = row.get("fav") == "1";
        let mut item = if row.get("url") == "http://sn" {
            lastpass_note(row)
        } else {
            let mut item = login(
                &name,
                row.some("username"),
                row.some("password"),
                uris([row.get("url")]),
            );
            item.login.totp = row.some("totp");
            item.notes = row.some("extra");
            item
        };
        item.name = name;
        item.favorite = favorite;
        out.push(item, folder);
    }
}

/// A LastPass form-fill profile: an identity when it has personal details,
/// a card otherwise, plus a separate card when an identity also has one.
fn lastpass_form(row: &Row, folder: Option<usize>, out: &mut ParsedImport) {
    let name = blank_to(row.get("profilename"), "--");
    let personal = [
        "title",
        "firstname",
        "lastname",
        "address1",
        "phone",
        "username",
        "email",
    ]
    .iter()
    .any(|c| !row.get(c).trim().is_empty());
    let has_card = !row.get("ccnum").trim().is_empty();
    if personal {
        let mut item = Item::new(ItemKind::Identity, None, None);
        item.name = name.clone();
        item.notes = row.some("notes");
        for (key, column) in [
            ("title", "title"),
            ("firstName", "firstname"),
            ("middleName", "middlename"),
            ("lastName", "lastname"),
            ("username", "username"),
            ("company", "company"),
            ("ssn", "ssn"),
            ("address1", "address1"),
            ("address2", "address2"),
            ("address3", "address3"),
            ("city", "city"),
            ("state", "state"),
            ("postalCode", "zip"),
            ("country", "country"),
            ("email", "email"),
            ("phone", "phone"),
        ] {
            let mut value = row.some(column);
            if key == "title" {
                value = capitalise(&value);
            }
            if !value.is_empty() {
                item.identity.insert(key.to_string(), value);
            }
        }
        out.push(item, folder);
        if has_card {
            out.push(lastpass_card(row, &name), folder);
        }
    } else {
        out.push(lastpass_card(row, &name), folder);
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn lastpass_card(row: &Row, name: &str) -> Item {
    let mut item = Item::new(ItemKind::Card, None, None);
    item.name = name.to_string();
    item.notes = row.some("notes");
    item.card.cardholder_name = row.some("ccname");
    item.card.number = row.some("ccnum");
    item.card.code = row.some("cccsc");
    item.card.brand = card_brand(&item.card.number);
    let expiry = row.get("ccexp");
    if let Some((year, month)) = expiry.split_once('-') {
        item.card.exp_year = year.to_string();
        item.card.exp_month = month.strip_prefix('0').unwrap_or(month).to_string();
    }
    item
}

/// Bitwarden's brand names, found from the leading digits of a card number.
fn card_brand(number: &str) -> String {
    let n: String = number.chars().filter(char::is_ascii_digit).collect();
    let prefix = |len: usize| {
        n.get(..len)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0)
    };
    let brand = if n.starts_with('4') {
        "Visa"
    } else if (51..=55).contains(&prefix(2)) || (2221..=2720).contains(&prefix(4)) {
        "Mastercard"
    } else if matches!(prefix(2), 34 | 37) {
        "Amex"
    } else if prefix(4) == 6011 || prefix(2) == 65 || (644..=649).contains(&prefix(3)) {
        "Discover"
    } else if prefix(2) == 35 {
        "JCB"
    } else if prefix(2) == 62 {
        "UnionPay"
    } else {
        ""
    };
    brand.to_string()
}

/// A LastPass secure note. Notes that hold a card or an address as
/// `NoteType:` lines become those items; everything else stays a note.
fn lastpass_note(row: &Row) -> Item {
    let extra = row.get("extra");
    let mut lines = extra.lines();
    let kind = lines
        .next()
        .and_then(|l| l.strip_prefix("NoteType:"))
        .map(str::trim);
    let mut item = Item::new(ItemKind::SecureNote, None, None);
    let (card, address) = (kind == Some("Credit Card"), kind == Some("Address"));
    if !card && !address {
        item.notes = row.some("extra");
        return item;
    }
    if card {
        item.kind = ItemKind::Card;
    } else {
        item.kind = ItemKind::Identity;
    }
    let mut in_notes = false;
    for line in lines {
        if in_notes {
            item.notes.push('\n');
            item.notes.push_str(line);
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().is_empty() || value.trim().is_empty() {
            continue;
        }
        if key == "Notes" {
            item.notes = value.to_string();
            in_notes = true;
            continue;
        }
        let mapped = if card {
            match key {
                "Number" => Some("number"),
                "Name on Card" => Some("cardholderName"),
                "Security Code" => Some("code"),
                "Expiration Date" => Some("expiry"),
                _ => None,
            }
        } else {
            match key {
                "Title" => Some("title"),
                "First Name" => Some("firstName"),
                "Last Name" => Some("lastName"),
                "Middle Name" => Some("middleName"),
                "Company" => Some("company"),
                "Address 1" => Some("address1"),
                "Address 2" => Some("address2"),
                "Address 3" => Some("address3"),
                "City / Town" => Some("city"),
                "State" => Some("state"),
                "Zip / Postal Code" => Some("postalCode"),
                "Country" => Some("country"),
                "Email Address" => Some("email"),
                "Username" => Some("username"),
                _ => None,
            }
        };
        match mapped {
            Some("number") => item.card.number = value.to_string(),
            Some("cardholderName") => item.card.cardholder_name = value.to_string(),
            Some("code") => item.card.code = value.to_string(),
            // LastPass writes "June,2020".
            Some("expiry") => {
                if let Some((month, year)) = value.split_once(',') {
                    item.card.exp_month = month_number(month).unwrap_or_default();
                    item.card.exp_year = year.trim().to_string();
                }
            }
            Some(name) => {
                item.identity.insert(name.to_string(), value.to_string());
            }
            None => add_pair(&mut item, key, value, FieldType::Text),
        }
    }
    if card {
        item.card.brand = card_brand(&item.card.number);
    }
    item
}

fn month_number(name: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let lower = name.trim().to_lowercase();
    let at = MONTHS.iter().position(|m| lower.starts_with(m))?;
    Some((at + 1).to_string())
}

/// 1Password: the title, username, password, URLs, one-time password and
/// notes become login values; other columns become custom fields. A row with
/// no login values is saved as a note. Cards and identities are not mapped.
fn onepassword_csv(rows: &[Row], out: &mut ParsedImport) {
    const SKIPPED: [&str; 12] = [
        "ainfo",
        "autosubmit",
        "notesplain",
        "ps",
        "scope",
        "tags",
        "title",
        "uuid",
        "notes",
        "type",
        "archived",
        "favorite",
    ];
    for row in rows {
        let by_lower: Vec<(String, &str, &String)> = row
            .0
            .iter()
            .map(|(k, v)| (k.to_lowercase(), k.as_str(), v))
            .collect();
        let find = |names: &[&str]| -> String {
            by_lower
                .iter()
                .find(|(l, _, v)| names.contains(&l.as_str()) && !v.trim().is_empty())
                .map(|(_, _, v)| (*v).clone())
                .unwrap_or_default()
        };
        let title = find(&["title"]);
        if title.trim().is_empty() {
            continue;
        }
        let urls: Vec<String> = find(&["urls", "url", "website", "login url"])
            .lines()
            .map(str::to_string)
            .collect();
        let mut item = login(
            &title,
            find(&["username"]),
            find(&["password"]),
            uris(urls.iter().map(String::as_str)),
        );
        item.login.totp = find(&["otpauth", "one-time password"]);
        item.favorite = find(&["favorite"]) == "1";
        item.notes = [find(&["notesplain"]), find(&["notes"])]
            .iter()
            .filter(|n| !n.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let mut sorted = by_lower.clone();
        sorted.sort_by(|a, b| a.1.cmp(b.1));
        for (lower, original, value) in sorted {
            let used = [
                "username",
                "password",
                "urls",
                "url",
                "website",
                "login url",
                "otpauth",
                "one-time password",
            ];
            if value.trim().is_empty()
                || SKIPPED.contains(&lower.as_str())
                || used.contains(&lower.as_str())
                || lower.starts_with("section:")
                || lower.starts_with("section ")
            {
                continue;
            }
            let secret = ["password", "key", "secret"]
                .iter()
                .any(|w| lower.contains(w));
            let kind = if secret {
                FieldType::Hidden
            } else {
                FieldType::Text
            };
            add_pair(&mut item, original, value, kind);
        }
        if item.login.username.trim().is_empty()
            && item.login.password.trim().is_empty()
            && item.login.uris.is_empty()
        {
            item.kind = ItemKind::SecureNote;
            item.login = Default::default();
        }
        out.push(item, None);
    }
}

// -------------------------------------------------------------- upload

/// What an import did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub items: usize,
    pub skipped: usize,
    pub folders_created: usize,
    pub folders_reused: usize,
}

/// The request body for `POST /ciphers/import`: encrypted items, folders
/// (existing folders of the same name are reused by id) and the item to
/// folder relationships.
pub(crate) fn request(
    parsed: &ParsedImport,
    vault: &Vault,
    keys: &Keys,
) -> Result<(Value, ImportSummary), VaultError> {
    let mut summary = ImportSummary {
        skipped: parsed.skipped,
        ..Default::default()
    };
    let mut ciphers = Vec::new();
    let mut relationships = Vec::new();
    for (index, entry) in parsed.items.iter().enumerate() {
        ciphers.push(cipher_body(entry, keys)?);
        if let Some(folder) = entry.folder {
            relationships.push(json!({ "key": index, "value": folder }));
        }
    }
    summary.items = ciphers.len();
    let mut folders = Vec::new();
    for name in &parsed.folders {
        let mut folder = Map::new();
        folder.insert("name".into(), json!(keys.user.encrypt_str(name)));
        match vault.folders.iter().find(|f| &f.name == name) {
            Some(existing) => {
                folder.insert("id".into(), json!(existing.id));
                summary.folders_reused += 1;
            }
            None => summary.folders_created += 1,
        }
        folders.push(Value::Object(folder));
    }
    let body = json!({
        "ciphers": ciphers,
        "folders": folders,
        "folderRelationships": relationships,
    });
    Ok((body, summary))
}

const PASSKEY_TEXT: [&str; 12] = [
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
];

/// One encrypted item, with its passkeys.
fn cipher_body(entry: &ImportItem, keys: &Keys) -> Result<Value, VaultError> {
    let mut body = crate::vault::encrypt_item(&entry.item, keys)?;
    if entry.passkeys.is_empty() {
        return Ok(body);
    }
    let mut credentials = Vec::new();
    for passkey in &entry.passkeys {
        let mut encrypted = Map::new();
        for name in PASSKEY_TEXT {
            let value = field_str(passkey, name)
                .map_or(Value::Null, |text| json!(keys.user.encrypt_str(text)));
            encrypted.insert(name.into(), value);
        }
        encrypted.insert(
            "creationDate".into(),
            field(passkey, "creationDate")
                .cloned()
                .unwrap_or(Value::Null),
        );
        credentials.push(Value::Object(encrypted));
    }
    if let Some(login) = body.get_mut("login").and_then(Value::as_object_mut) {
        login.insert("fido2Credentials".into(), Value::Array(credentials));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats_from_headers() {
        let cases = [
            ("name,url,username,password,note\n", Format::ChromeCsv),
            ("name,url,username,password\n", Format::ChromeCsv),
            (
                "url,username,password,httpRealm,formActionOrigin,guid\n",
                Format::FirefoxCsv,
            ),
            (
                "Title,URL,Username,Password,Notes,OTPAuth\n",
                Format::SafariCsv,
            ),
            (
                "Group,Title,Username,Password,URL,Notes,TOTP\n",
                Format::KeePassXcCsv,
            ),
            (
                "url,username,password,totp,extra,name,grouping,fav\n",
                Format::LastPassCsv,
            ),
            (
                "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
                Format::BitwardenCsv,
            ),
            ("{\"items\":[]}", Format::BitwardenJson),
            (
                "Title,Website,Username,Password,Notes,Type\n",
                Format::OnePasswordCsv,
            ),
        ];
        for (text, format) in cases {
            assert_eq!(detect(text), Some(format), "{text}");
        }
        assert_eq!(detect("a,b,c\n1,2,3\n"), None);
    }

    #[test]
    fn host_names_and_uris() {
        assert_eq!(
            name_from_url("https://www.example.com:8443/x"),
            Some("example.com".into())
        );
        assert_eq!(name_from_url("android"), Some("android".into()));
        assert_eq!(fix_uri(" example.org "), "http://example.org");
        assert_eq!(fix_uri("androidapp://com.x"), "androidapp://com.x");
    }

    #[test]
    fn nested_folders_add_parents() {
        let mut parsed = ParsedImport {
            format: Format::KeePassXcCsv,
            items: vec![],
            folders: vec![],
            skipped: 0,
        };
        assert_eq!(parsed.folder_index("\\a\\b\\c"), Some(0));
        assert_eq!(parsed.folders, ["a/b/c", "a/b", "a"]);
        assert_eq!(parsed.folder_index("a/b"), Some(1));
    }
}
