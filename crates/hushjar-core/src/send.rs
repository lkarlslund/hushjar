//! Bitwarden Send: text or a file shared through a link that holds the key.
//!
//! Each Send has 16 bytes of key material, stored on the server wrapped
//! with the user key and put in the share link after the `#`. The fields
//! and the file are encrypted with a key derived from that material
//! ([`crypto::send_key`]), so whoever has the link can read the Send and
//! the server cannot.

use std::fmt;

use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::api::{field, field_str, field_u64};
use crate::crypto::{self, SymmetricKey};
use crate::vault::{UNREADABLE, VaultError, iso_in, number_or_string};

/// How long a new Send lives before the server deletes it, as in the
/// Bitwarden clients' default: seven days.
pub const DEFAULT_LIFETIME_SECS: i64 = 7 * 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendKind {
    Text,
    File,
    /// A type this version does not understand; shown read-only.
    Other(u8),
}

impl SendKind {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => SendKind::Text,
            1 => SendKind::File,
            n => SendKind::Other(n),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            SendKind::Text => 0,
            SendKind::File => 1,
            SendKind::Other(n) => n,
        }
    }
}

/// A Send's 16 bytes of key material. `Debug` does not show them.
#[derive(Clone, PartialEq, Eq)]
pub struct SendKey(Zeroizing<[u8; 16]>);

impl fmt::Debug for SendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SendKey([redacted])")
    }
}

impl SendKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(crypto::random_bytes::<16>()))
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let array: [u8; 16] = bytes.try_into().ok()?;
        Some(Self(Zeroizing::new(array)))
    }

    pub fn material(&self) -> &[u8; 16] {
        &self.0
    }

    /// The key that encrypts the Send's fields and file.
    pub fn cipher_key(&self) -> SymmetricKey {
        crypto::send_key(&self.0)
    }
}

/// The file of a file Send.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct SendFile {
    #[zeroize(skip)]
    pub id: String,
    pub file_name: String,
    /// Size of the encrypted file in bytes, as the server reports it.
    #[zeroize(skip)]
    pub size: u64,
    #[zeroize(skip)]
    pub size_name: String,
}

/// A decrypted Send. Named `SendEntry` so it never hides the standard
/// `Send` marker trait where both are in scope.
#[derive(Clone, PartialEq)]
pub struct SendEntry {
    pub id: String,
    /// The public identifier used in the share link.
    pub access_id: String,
    pub kind: SendKind,
    pub name: String,
    pub notes: String,
    /// The shared text, for text Sends.
    pub text: String,
    /// Whether the recipient must click to reveal the text.
    pub hide_text: bool,
    /// The shared file, for file Sends.
    pub file: Option<SendFile>,
    /// The key material, or `None` if it could not be decrypted.
    pub key: Option<SendKey>,
    /// Whether an access password is set. The password itself is never
    /// known to the client after it is set.
    pub has_password: bool,
    pub max_access_count: Option<u64>,
    pub access_count: u64,
    pub revision_date: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: bool,
    pub hide_email: bool,
    /// Values that could not be decrypted.
    pub unreadable: usize,
    /// The encrypted Send as the server sent it. Null for new Sends.
    pub raw: Value,
}

impl fmt::Debug for SendEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendEntry")
            .field("id", &self.id)
            .field("access_id", &self.access_id)
            .field("kind", &self.kind)
            .field("has_password", &self.has_password)
            .field("deletion_date", &self.deletion_date)
            .field("disabled", &self.disabled)
            .finish_non_exhaustive()
    }
}

impl Drop for SendEntry {
    fn drop(&mut self) {
        self.name.zeroize();
        self.notes.zeroize();
        self.text.zeroize();
        if let Some(file) = &mut self.file {
            file.zeroize();
        }
    }
}

impl SendEntry {
    /// A new, unsaved Send with fresh key material, deleted by the server
    /// after [`DEFAULT_LIFETIME_SECS`].
    pub fn new(kind: SendKind) -> Self {
        Self {
            id: String::new(),
            access_id: String::new(),
            kind,
            name: String::new(),
            notes: String::new(),
            text: String::new(),
            hide_text: false,
            file: None,
            key: Some(SendKey::generate()),
            has_password: false,
            max_access_count: None,
            access_count: 0,
            revision_date: String::new(),
            expiration_date: None,
            deletion_date: iso_in(DEFAULT_LIFETIME_SECS),
            disabled: false,
            hide_email: false,
            unreadable: 0,
            raw: Value::Null,
        }
    }

    pub fn is_new(&self) -> bool {
        self.id.is_empty()
    }
}

/// Decrypts one Send from the sync reply or a Send endpoint.
pub fn decrypt_send(raw: &Value, user: &SymmetricKey) -> SendEntry {
    let string = |name: &str| field_str(raw, name).unwrap_or_default().to_string();
    let kind = SendKind::from_code(field_u64(raw, "type").unwrap_or(0) as u8);
    let key = field_str(raw, "key")
        .and_then(|k| user.decrypt(&k.parse().ok()?).ok())
        .and_then(|m| SendKey::from_slice(&m));
    let cipher_key = key.as_ref().map(SendKey::cipher_key);
    let mut unreadable = 0;
    let mut get = |object: Option<&Value>, name: &str| -> String {
        let Some(value) = object.and_then(|o| field_str(o, name)) else {
            return String::new();
        };
        match cipher_key.as_ref().map(|k| k.decrypt_str(value)) {
            Some(Ok(plain)) => plain.to_string(),
            _ => {
                unreadable += 1;
                UNREADABLE.to_string()
            }
        }
    };
    let text = field(raw, "text").filter(|v| v.is_object());
    let file = field(raw, "file").filter(|v| v.is_object());
    let mut send = SendEntry {
        id: string("id"),
        access_id: string("accessId"),
        kind,
        name: get(Some(raw), "name"),
        notes: get(Some(raw), "notes"),
        text: get(text, "text"),
        hide_text: text
            .and_then(|t| field(t, "hidden"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        file: file.map(|f| SendFile {
            id: field_str(f, "id").unwrap_or_default().to_string(),
            file_name: get(Some(f), "fileName"),
            size: number_or_string(f, "size").unwrap_or(0),
            size_name: field_str(f, "sizeName").unwrap_or_default().to_string(),
        }),
        key: None,
        has_password: field(raw, "password").is_some_and(|p| !p.is_null()),
        max_access_count: field_u64(raw, "maxAccessCount"),
        access_count: field_u64(raw, "accessCount").unwrap_or(0),
        revision_date: string("revisionDate"),
        expiration_date: field_str(raw, "expirationDate").map(str::to_string),
        deletion_date: string("deletionDate"),
        disabled: field(raw, "disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        hide_email: field(raw, "hideEmail")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        unreadable,
        raw: raw.clone(),
    };
    if key.is_none() {
        send.unreadable += 1;
    }
    send.key = key;
    send
}

/// Encrypts `value`, or gives JSON null for an empty string.
fn enc(key: &SymmetricKey, value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(key.encrypt_str(value))
    }
}

/// Builds the request body that creates or updates `send`, starting from
/// the server's copy so fields Hushjar does not edit are kept.
///
/// `password` sets a new access password. Without one, `password` is sent
/// as null, which leaves an existing password unchanged (Vaultwarden
/// `update_send_from_data`: "Only change the value if it's present"); use
/// the remove-password request to clear it. For a new file Send, the file
/// name must be set in `send.file`.
pub fn encrypt_send(
    send: &SendEntry,
    user: &SymmetricKey,
    password: Option<&str>,
) -> Result<Value, VaultError> {
    if matches!(send.kind, SendKind::Other(_)) {
        return Err(VaultError::ReadOnlyType);
    }
    if send.unreadable > 0 {
        return Err(VaultError::Unreadable);
    }
    let material = send.key.as_ref().ok_or(VaultError::MissingKey)?;
    let key = material.cipher_key();
    let mut body: Map<String, Value> = send.raw.as_object().cloned().unwrap_or_default();
    // The reply's password field is the server's own hash; sending it back
    // would set it as the new password.
    for name in ["password", "id", "accessId", "accessCount", "object"] {
        body.remove(name);
    }
    body.insert("type".into(), json!(send.kind.code()));
    body.insert("name".into(), enc(&key, &send.name));
    body.insert("notes".into(), enc(&key, &send.notes));
    if field_str(&send.raw, "key").is_none() {
        body.insert(
            "key".into(),
            json!(user.encrypt(material.material()).to_string()),
        );
    }
    body.insert("maxAccessCount".into(), json!(send.max_access_count));
    body.insert("expirationDate".into(), json!(send.expiration_date));
    body.insert("deletionDate".into(), json!(send.deletion_date));
    body.insert("disabled".into(), json!(send.disabled));
    body.insert("hideEmail".into(), json!(send.hide_email));
    body.insert(
        "password".into(),
        match password {
            Some(p) => json!(crypto::send_password_hash(p, material.material()).as_str()),
            None => Value::Null,
        },
    );
    match send.kind {
        SendKind::Text => {
            body.insert(
                "text".into(),
                json!({ "text": enc(&key, &send.text), "hidden": send.hide_text }),
            );
            body.insert("file".into(), Value::Null);
        }
        SendKind::File => {
            // The file cannot change after upload; keep the server's record.
            if send.raw.is_null() {
                let name = send.file.as_ref().map_or("", |f| f.file_name.as_str());
                if name.is_empty() {
                    return Err(VaultError::MissingFileName);
                }
                body.insert("file".into(), json!({ "fileName": key.encrypt_str(name) }));
            }
            body.insert("text".into(), Value::Null);
        }
        SendKind::Other(_) => unreachable!("checked above"),
    }
    Ok(Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    /// The Send from bitwarden/sdk-internal `bitwarden-send/src/send.rs`,
    /// `test_decrypt`, as the server would send it.
    #[test]
    fn decrypts_the_sdk_test_send() {
        let user = SymmetricKey::from_bytes(&B64.decode("bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg==").unwrap()).unwrap();
        let raw = json!({
            "id": "3d80dd72-2d14-4f26-812c-b0f0018aa144",
            "accessId": "ct2APRQtJk-BLLDwAYqhRA",
            "type": 0,
            "name": "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=",
            "notes": null,
            "text": { "text": "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=", "hidden": false },
            "file": null,
            "key": "2.KLv/j0V4Ebs0dwyPdtt4vw==|jcrFuNYN1Qb3onBlwvtxUV/KpdnR1LPRL4EsCoXNAt4=|gHSywGy4Rj/RsCIZFwze4s2AACYKBtqDXTrQXjkgtIE=",
            "maxAccessCount": null, "accessCount": 0, "password": null,
            "disabled": false, "hideEmail": false,
            "revisionDate": "2024-01-07T23:56:48.207363Z",
            "deletionDate": "2024-01-14T23:56:48Z", "expirationDate": null,
        });
        let send = decrypt_send(&raw, &user);
        assert_eq!(send.unreadable, 0);
        assert_eq!(send.name, "Test");
        assert_eq!(send.text, "This is a test");
        assert!(!send.has_password);
        let link_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(send.key.as_ref().unwrap().material());
        assert_eq!(link_key, "Pgui0FK85cNhBGWHAlBHBw");
        assert!(!format!("{send:?}").contains("This is a test"));
    }

    #[test]
    fn text_round_trip_and_password_handling() {
        let user = SymmetricKey::generate();
        let mut send = SendEntry::new(SendKind::Text);
        send.name = "Wi-Fi".into();
        send.text = "honeycomb".into();
        send.hide_text = true;
        let body = encrypt_send(&send, &user, Some("open sesame")).unwrap();
        let material = send.key.as_ref().unwrap().material();
        assert_eq!(
            body["password"],
            json!(crypto::send_password_hash("open sesame", material).as_str())
        );
        assert!(body["file"].is_null());

        // What the server would store decrypts to the same Send.
        let mut stored = body.clone();
        stored["id"] = json!("s1");
        stored["password"] = json!("c2VydmVyLWhhc2g");
        let back = decrypt_send(&stored, &user);
        assert_eq!(back.name, "Wi-Fi");
        assert_eq!(back.text, "honeycomb");
        assert!(back.hide_text && back.has_password);
        assert_eq!(back.key, send.key);

        // Editing keeps the key and never echoes the server's hash.
        let mut edited = back.clone();
        edited.text = "beehive".into();
        let body = encrypt_send(&edited, &user, None).unwrap();
        assert_eq!(body["key"], stored["key"]);
        assert!(body["password"].is_null());
        assert!(body.get("id").is_none());
    }

    #[test]
    fn unreadable_sends_are_not_saved() {
        let user = SymmetricKey::generate();
        let mut send = SendEntry::new(SendKind::Text);
        send.name = "x".into();
        let body = encrypt_send(&send, &user, None).unwrap();
        let other = SymmetricKey::generate();
        let back = decrypt_send(&body, &other);
        assert!(back.key.is_none());
        assert_eq!(back.name, UNREADABLE);
        assert!(matches!(
            encrypt_send(&back, &other, None),
            Err(VaultError::Unreadable)
        ));
    }

    #[test]
    fn file_send_needs_a_name_and_sizes_may_be_strings() {
        let user = SymmetricKey::generate();
        let mut send = SendEntry::new(SendKind::File);
        assert!(matches!(
            encrypt_send(&send, &user, None),
            Err(VaultError::MissingFileName)
        ));
        send.file = Some(SendFile {
            id: String::new(),
            file_name: "notes.txt".into(),
            size: 0,
            size_name: String::new(),
        });
        let mut stored = encrypt_send(&send, &user, None).unwrap();
        stored["file"]["size"] = json!("1234");
        stored["file"]["id"] = json!("f1");
        let back = decrypt_send(&stored, &user);
        let file = back.file.as_ref().unwrap();
        assert_eq!(file.file_name, "notes.txt");
        assert_eq!(file.size, 1234);
        assert!(back.text.is_empty());
    }
}
