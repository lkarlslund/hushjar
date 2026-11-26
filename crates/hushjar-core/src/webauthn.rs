//! Two-step login with a FIDO2/WebAuthn security key (provider 7).
//!
//! When login needs a second factor, the server's reply carries WebAuthn
//! request options for each account with a registered key
//! ([`TwoFactorChallenge::webauthn_options`](crate::api::TwoFactorChallenge::webauthn_options)).
//! Hushjar acts as the browser would: it builds the client data with the
//! web vault's origin, asks the key for an assertion over its hash, and
//! sends the result as JSON in `twoFactorToken`, in the shape of Bitwarden's
//! web connector (`apps/web/src/connectors/common-webauthn.ts`), which is
//! also what Vaultwarden parses (`PublicKeyCredentialCopy`).
//!
//! Talking to the key sits behind [`SecurityKey`], so everything else is
//! tested without hardware. [`usb::UsbSecurityKey`] is the real one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::{Server, field, field_str};

#[cfg(feature = "security-key")]
pub mod usb;

/// How long to wait for a touch when the server suggests no timeout.
/// Vaultwarden's challenges last a minute.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum WebAuthnError {
    #[error("the server sent security key options Hushjar cannot use")]
    BadOptions,
    #[error("security key sign-in was cancelled")]
    Cancelled,
    #[error("no security key was touched in time")]
    TimedOut,
    #[error("this security key is not registered for the account")]
    NotRegistered,
    #[error("security key error: {0}")]
    Device(String),
    #[error("this build of Hushjar cannot use security keys")]
    Unsupported,
}

/// Whether the key should check a PIN or fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    Discouraged,
    Preferred,
    Required,
}

/// One assertion to ask a security key for, built from the server's
/// options.
#[derive(Clone, Debug)]
pub struct AssertionRequest {
    pub rp_id: String,
    /// The web vault's origin, which the server checks in the client data.
    pub origin: String,
    /// The client data exactly as hashed and sent.
    pub client_data_json: String,
    pub client_data_hash: [u8; 32],
    /// Credential IDs registered for the account.
    pub allow_credentials: Vec<Vec<u8>>,
    /// The legacy U2F application ID, for keys registered before WebAuthn.
    pub app_id: Option<String>,
    pub user_verification: UserVerification,
    pub timeout: Duration,
}

/// What a security key returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    /// Whether the key matched through the legacy application ID.
    pub used_app_id: bool,
}

/// Cancels a running security key request from another thread, for
/// example when the user closes the prompt.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A device that can produce WebAuthn assertions.
pub trait SecurityKey {
    /// Asks for an assertion. Blocks until the key is touched, the request
    /// times out after `request.timeout`, or `cancel` is triggered.
    fn get_assertion(
        &self,
        request: &AssertionRequest,
        cancel: &Cancel,
    ) -> Result<Assertion, WebAuthnError>;
}

/// The origin a browser would report for the web vault of this server:
/// `vault.bitwarden.com` or `.eu` for Bitwarden's cloud, otherwise the
/// scheme, host and port of the server address.
pub fn origin_for(server: &Server) -> String {
    if let Some(region) = server.identity.strip_prefix("https://identity.bitwarden.") {
        return format!("https://vault.bitwarden.{region}");
    }
    let base = server.api.trim_end_matches("/api");
    match base.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split('/').next().unwrap_or_default();
            format!("{scheme}://{host}")
        }
        None => base.to_string(),
    }
}

/// Decodes base64url or standard base64, with or without padding; servers
/// differ.
fn decode_any(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .ok()
        .or_else(|| STANDARD.decode(text.trim()).ok())
        .or_else(|| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(trimmed)
                .ok()
        })
}

/// The host part of an origin, the default relying party ID.
fn origin_host(origin: &str) -> String {
    let rest = origin.split_once("://").map(|(_, r)| r).unwrap_or(origin);
    let host = rest.split('/').next().unwrap_or_default();
    if host.starts_with('[') {
        host.split(']').next().unwrap_or_default().to_string() + "]"
    } else {
        host.split(':').next().unwrap_or_default().to_string()
    }
}

/// Builds the assertion request from the server's WebAuthn options.
pub fn request_from_options(
    options: &Value,
    origin: &str,
) -> Result<AssertionRequest, WebAuthnError> {
    let challenge = field_str(options, "challenge")
        .and_then(decode_any)
        .filter(|c| !c.is_empty())
        .ok_or(WebAuthnError::BadOptions)?;
    let rp_id = field_str(options, "rpId")
        .map(str::to_string)
        .unwrap_or_else(|| origin_host(origin));
    let allow_credentials: Vec<Vec<u8>> = field(options, "allowCredentials")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|c| field_str(c, "id").and_then(decode_any))
                .collect()
        })
        .unwrap_or_default();
    // A second factor must name the account's keys.
    if allow_credentials.is_empty() {
        return Err(WebAuthnError::BadOptions);
    }
    let app_id = field(options, "extensions")
        .and_then(|e| field_str(e, "appid"))
        .map(str::to_string);
    let user_verification = match field_str(options, "userVerification") {
        Some("required") => UserVerification::Required,
        Some("preferred") => UserVerification::Preferred,
        _ => UserVerification::Discouraged,
    };
    let timeout = field(options, "timeout")
        .and_then(Value::as_u64)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_TIMEOUT)
        .clamp(Duration::from_secs(10), Duration::from_secs(300));
    let client_data_json = json!({
        "type": "webauthn.get",
        "challenge": URL_SAFE_NO_PAD.encode(&challenge),
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string();
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).into();
    Ok(AssertionRequest {
        rp_id,
        origin: origin.to_string(),
        client_data_json,
        client_data_hash,
        allow_credentials,
        app_id,
        user_verification,
        timeout,
    })
}

/// The `twoFactorToken` for provider 7: the assertion as JSON, in the
/// shape Bitwarden's web connector sends.
pub fn token(request: &AssertionRequest, assertion: &Assertion) -> Zeroizing<String> {
    let id = URL_SAFE_NO_PAD.encode(&assertion.credential_id);
    let extensions = if request.app_id.is_some() {
        json!({ "appid": assertion.used_app_id })
    } else {
        json!({})
    };
    let mut response = json!({
        "authenticatorData": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
        "clientDataJson": URL_SAFE_NO_PAD.encode(request.client_data_json.as_bytes()),
        "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
    });
    if let Some(handle) = &assertion.user_handle {
        response["userHandle"] = json!(URL_SAFE_NO_PAD.encode(handle));
    }
    Zeroizing::new(
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "extensions": extensions,
            "response": response,
        })
        .to_string(),
    )
}

/// Runs the whole exchange: options in, `twoFactorToken` out. Use it with
/// [`SecondFactor`](crate::api::SecondFactor) and
/// [`TwoFactorProvider::WebAuthn`](crate::api::TwoFactorProvider::WebAuthn).
pub fn sign(
    options: &Value,
    server: &Server,
    key: &dyn SecurityKey,
    cancel: &Cancel,
) -> Result<Zeroizing<String>, WebAuthnError> {
    let request = request_from_options(options, &origin_for(server))?;
    let assertion = key.get_assertion(&request, cancel)?;
    if !request.allow_credentials.contains(&assertion.credential_id) {
        return Err(WebAuthnError::NotRegistered);
    }
    Ok(token(&request, &assertion))
}

/// The security key on this computer's USB ports, when this build has
/// security key support.
pub fn usb_key() -> Result<Box<dyn SecurityKey>, WebAuthnError> {
    #[cfg(feature = "security-key")]
    {
        Ok(Box::new(usb::UsbSecurityKey))
    }
    #[cfg(not(feature = "security-key"))]
    {
        Err(WebAuthnError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Options in the shape Vaultwarden 1.37 sends (webauthn-rs
    /// `PublicKeyCredentialRequestOptions` with the U2F appid added).
    fn vaultwarden_options() -> Value {
        json!({
            "challenge": "q2Xc0Vh5S4yq7l1kz8bJmJ9u0gXQm2b0n3Yy4tH0Q2c",
            "timeout": 60000,
            "rpId": "vault.example.org",
            "allowCredentials": [
                { "type": "public-key", "id": "AQIDBA" },
                { "type": "public-key", "id": "BQYHCA" }
            ],
            "userVerification": "discouraged",
            "extensions": { "appid": "https://vault.example.org/app-id.json" }
        })
    }

    /// Records the request and answers with a fixed assertion.
    struct FakeKey {
        seen: RefCell<Option<AssertionRequest>>,
        answer: Assertion,
    }

    impl SecurityKey for FakeKey {
        fn get_assertion(
            &self,
            request: &AssertionRequest,
            cancel: &Cancel,
        ) -> Result<Assertion, WebAuthnError> {
            if cancel.is_cancelled() {
                return Err(WebAuthnError::Cancelled);
            }
            *self.seen.borrow_mut() = Some(request.clone());
            Ok(self.answer.clone())
        }
    }

    fn fake(credential_id: &[u8]) -> FakeKey {
        FakeKey {
            seen: RefCell::new(None),
            answer: Assertion {
                credential_id: credential_id.to_vec(),
                authenticator_data: vec![0xAA; 37],
                signature: vec![0x30, 0x44, 0x02],
                user_handle: None,
                used_app_id: false,
            },
        }
    }

    #[test]
    fn origins() {
        let cloud = Server::parse("bitwarden.eu").unwrap();
        assert_eq!(origin_for(&cloud), "https://vault.bitwarden.eu");
        let own = Server::parse("https://vault.example.org:8443/bw").unwrap();
        assert_eq!(origin_for(&own), "https://vault.example.org:8443");
        let local = Server::parse("http://localhost:18299").unwrap();
        assert_eq!(origin_for(&local), "http://localhost:18299");
    }

    #[test]
    fn builds_request_from_vaultwarden_options() {
        let request =
            request_from_options(&vaultwarden_options(), "https://vault.example.org").unwrap();
        assert_eq!(request.rp_id, "vault.example.org");
        assert_eq!(
            request.allow_credentials,
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]
        );
        assert_eq!(
            request.app_id.as_deref(),
            Some("https://vault.example.org/app-id.json")
        );
        assert_eq!(request.user_verification, UserVerification::Discouraged);
        assert_eq!(request.timeout, Duration::from_secs(60));
        let client: Value = serde_json::from_str(&request.client_data_json).unwrap();
        assert_eq!(client["type"], "webauthn.get");
        assert_eq!(client["origin"], "https://vault.example.org");
        assert_eq!(
            client["challenge"],
            "q2Xc0Vh5S4yq7l1kz8bJmJ9u0gXQm2b0n3Yy4tH0Q2c"
        );
        let hash: [u8; 32] = Sha256::digest(request.client_data_json.as_bytes()).into();
        assert_eq!(request.client_data_hash, hash);
    }

    #[test]
    fn accepts_padded_standard_base64_and_defaults() {
        // Bitwarden's server has sent standard base64 in some versions.
        let options = json!({
            "challenge": "+/+/AA==",
            "allowCredentials": [{ "type": "public-key", "id": "AQID" }]
        });
        let request = request_from_options(&options, "https://vault.example.org:8443").unwrap();
        let client: Value = serde_json::from_str(&request.client_data_json).unwrap();
        assert_eq!(client["challenge"], "-_-_AA");
        assert_eq!(request.rp_id, "vault.example.org");
        assert_eq!(request.app_id, None);
        assert_eq!(request.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn refuses_unusable_options() {
        let origin = "https://vault.example.org";
        assert!(request_from_options(&json!({}), origin).is_err());
        let no_keys = json!({ "challenge": "AAAA", "allowCredentials": [] });
        assert!(request_from_options(&no_keys, origin).is_err());
    }

    #[test]
    fn token_has_the_web_connector_shape() {
        let server = Server::parse("https://vault.example.org").unwrap();
        let key = fake(&[5, 6, 7, 8]);
        let token = sign(&vaultwarden_options(), &server, &key, &Cancel::new()).unwrap();
        let value: Value = serde_json::from_str(&token).unwrap();
        assert_eq!(value["id"], "BQYHCA");
        assert_eq!(value["rawId"], "BQYHCA");
        assert_eq!(value["type"], "public-key");
        assert_eq!(value["extensions"], json!({ "appid": false }));
        let response = &value["response"];
        assert_eq!(
            response["authenticatorData"],
            URL_SAFE_NO_PAD.encode([0xAA; 37])
        );
        assert_eq!(response["signature"], "MEQC");
        assert!(response.get("userHandle").is_none());
        // The client data sent is the one whose hash the key signed.
        let seen = key.seen.borrow().clone().unwrap();
        let sent = URL_SAFE_NO_PAD
            .decode(response["clientDataJson"].as_str().unwrap())
            .unwrap();
        assert_eq!(sent, seen.client_data_json.as_bytes());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&sent)),
            seen.client_data_hash
        );
    }

    #[test]
    fn rejects_unknown_credentials_and_honours_cancel() {
        let server = Server::parse("https://vault.example.org").unwrap();
        assert!(matches!(
            sign(&vaultwarden_options(), &server, &fake(&[9]), &Cancel::new()),
            Err(WebAuthnError::NotRegistered)
        ));
        let cancel = Cancel::new();
        cancel.cancel();
        assert!(matches!(
            sign(
                &vaultwarden_options(),
                &server,
                &fake(&[1, 2, 3, 4]),
                &cancel
            ),
            Err(WebAuthnError::Cancelled)
        ));
    }
}
