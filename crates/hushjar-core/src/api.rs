//! HTTP client for the Bitwarden and Vaultwarden APIs.
//!
//! Requests are blocking; the app runs them on worker threads. HTTPS is
//! required except for loopback addresses, which test servers use.

use std::time::Duration;

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::crypto::Kdf;

mod auth_requests;
pub use auth_requests::AuthRequest;

/// The client name and version sent to servers. Vaultwarden hides newer item
/// types, such as SSH keys, from clients that report older versions.
pub const CLIENT_ID: &str = "hushjar";
const CLIENT_VERSION: &str = "2024.12.0";
const SYNC_LIMIT: u64 = 64 << 20;
const SMALL_LIMIT: u64 = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("could not reach the server: {0}")]
    Network(String),
    #[error("the server address is not valid: {0}")]
    BadUrl(String),
    #[error("{0}")]
    Rejected(String),
    #[error("two-step login is required")]
    TwoFactorRequired(TwoFactorChallenge),
    /// Bitwarden emailed a code to confirm this new device; sign in again
    /// with it in [`PasswordGrant::new_device_code`].
    #[error("enter the code sent to your email to confirm this new device")]
    NewDeviceVerificationRequired,
    #[error("the session has expired; sign in again")]
    Unauthorized,
    #[error("the server sent an unexpected reply")]
    Decode,
    #[error("unsupported key derivation settings")]
    Kdf,
}

/// Two-step login methods Hushjar can complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TwoFactorProvider {
    Authenticator,
    Email,
    /// A YubiKey one-time password: the token is the 44-character string the
    /// key types when touched.
    YubiKey,
    /// A FIDO2/WebAuthn security key; see [`crate::webauthn`].
    WebAuthn,
    Other(u8),
}

impl TwoFactorProvider {
    pub fn code(self) -> u8 {
        match self {
            TwoFactorProvider::Authenticator => 0,
            TwoFactorProvider::Email => 1,
            TwoFactorProvider::YubiKey => 3,
            TwoFactorProvider::WebAuthn => 7,
            TwoFactorProvider::Other(n) => n,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            0 => TwoFactorProvider::Authenticator,
            1 => TwoFactorProvider::Email,
            3 => TwoFactorProvider::YubiKey,
            7 => TwoFactorProvider::WebAuthn,
            n => TwoFactorProvider::Other(n),
        }
    }

    pub fn supported(self) -> bool {
        !matches!(self, TwoFactorProvider::Other(_))
    }
}

/// What the server asked for when two-step login is required: the methods
/// the account has set up and any details each one needs to continue.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TwoFactorChallenge {
    /// The account's methods, ordered by provider number.
    pub providers: Vec<TwoFactorProvider>,
    /// `TwoFactorProviders2` from the reply: provider number to details.
    details: Map<String, Value>,
}

impl TwoFactorChallenge {
    /// Reads a login rejection. `None` when it is not a two-step request.
    pub fn from_response(body: &Value) -> Option<Self> {
        let details = field(body, "TwoFactorProviders2")?.as_object()?.clone();
        let mut providers: Vec<TwoFactorProvider> = details
            .keys()
            .filter_map(|k| k.parse::<u8>().ok())
            .map(TwoFactorProvider::from_code)
            .collect();
        providers.sort_by_key(|p| p.code());
        Some(Self { providers, details })
    }

    /// The server's details for one method, if it sent any.
    pub fn details(&self, provider: TwoFactorProvider) -> Option<&Value> {
        self.details
            .get(&provider.code().to_string())
            .filter(|v| !v.is_null())
    }

    /// The WebAuthn request options for a security key. Vaultwarden only
    /// offers them when its domain is a host name, not an IP address.
    pub fn webauthn_options(&self) -> Option<&Value> {
        self.details(TwoFactorProvider::WebAuthn)
    }

    /// The partly hidden address that email codes go to, for display.
    pub fn email_hint(&self) -> Option<&str> {
        self.details(TwoFactorProvider::Email)
            .and_then(|d| field_str(d, "Email"))
    }

    /// Whether the registered YubiKey can be read over NFC.
    pub fn yubikey_nfc(&self) -> bool {
        self.details(TwoFactorProvider::YubiKey)
            .and_then(|d| field(d, "Nfc"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

/// Where a server's services live.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Server {
    /// What the user typed or picked, for display.
    pub name: String,
    pub api: String,
    pub identity: String,
}

impl Server {
    /// Resolves a server choice. `bitwarden.com` and `bitwarden.eu` use
    /// Bitwarden's separate service hosts; anything else is self-hosted.
    pub fn parse(input: &str) -> Result<Self, ApiError> {
        let trimmed = input.trim().trim_end_matches('/');
        let lower = trimmed.to_ascii_lowercase();
        let cloud = |region: &str| Server {
            name: format!("bitwarden.{region}"),
            api: format!("https://api.bitwarden.{region}"),
            identity: format!("https://identity.bitwarden.{region}"),
        };
        match lower.as_str() {
            "" | "bitwarden.com" | "https://bitwarden.com" | "https://vault.bitwarden.com" => {
                return Ok(cloud("com"));
            }
            "bitwarden.eu" | "https://bitwarden.eu" | "https://vault.bitwarden.eu" => {
                return Ok(cloud("eu"));
            }
            _ => {}
        }
        let base = if lower.starts_with("https://") || lower.starts_with("http://") {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };
        let rest = base.split_once("://").map(|(_, r)| r).unwrap_or_default();
        let host_port = rest.split('/').next().unwrap_or_default();
        if host_port.is_empty()
            || host_port.contains('@')
            || base.contains('?')
            || base.contains('#')
        {
            return Err(ApiError::BadUrl(input.into()));
        }
        let host = if host_port.starts_with('[') {
            host_port
                .split(']')
                .next()
                .map(|h| format!("{h}]"))
                .unwrap_or_default()
        } else {
            host_port.split(':').next().unwrap_or_default().to_string()
        };
        let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
        if base.to_ascii_lowercase().starts_with("http://") && !loopback {
            return Err(ApiError::BadUrl(
                "plain http is only allowed for this computer (localhost)".into(),
            ));
        }
        let name = base
            .split_once("://")
            .map(|(_, r)| r.to_string())
            .unwrap_or_else(|| base.clone());
        Ok(Server {
            name,
            api: format!("{base}/api"),
            identity: format!("{base}/identity"),
        })
    }
}

/// This installation's identity towards the server. The identifier is
/// random and stored per account so the server can recognise the device.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub identifier: String,
    pub name: String,
}

impl Device {
    pub fn new() -> Self {
        Self {
            identifier: uuid::Uuid::new_v4().to_string(),
            name: "Hushjar".into(),
        }
    }

    pub fn kind() -> u8 {
        if cfg!(target_os = "windows") {
            6
        } else if cfg!(target_os = "macos") {
            7
        } else {
            8
        }
    }
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

/// Tokens and keys returned by a successful login.
pub struct Login {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_in: u64,
    /// The user key, encrypted with the stretched master key.
    pub key: String,
    /// The RSA private key, encrypted with the user key, if the account has one.
    pub private_key: Option<String>,
    /// A token that skips two-step login on this device next time.
    pub two_factor_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Login([redacted])")
    }
}

pub struct Tokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_in: u64,
}

/// A second factor supplied with a login attempt.
pub struct SecondFactor<'a> {
    pub provider: TwoFactorProvider,
    pub token: &'a str,
    pub remember: bool,
}

/// A password grant at the identity server. Besides the master password
/// hash, the secret can be the access code of an approved login request.
pub struct PasswordGrant<'a> {
    pub email: &'a str,
    /// The master password hash, or the access code with `auth_request`.
    pub secret: &'a str,
    pub device: &'a Device,
    pub second: Option<SecondFactor<'a>>,
    /// The code Bitwarden emailed to confirm a new device.
    pub new_device_code: Option<&'a str>,
    /// The ID of an approved login request (log in with a device).
    pub auth_request: Option<&'a str>,
}

/// The `ErrorModel.Message` Bitwarden sends when a new device must be
/// confirmed with an emailed code. Bitwarden's clients match it exactly.
const NEW_DEVICE_MESSAGE: &str = "new device verification required";

/// Sorts a rejected login into the cases the user can act on.
fn login_rejection(status: u16, body: &Value) -> ApiError {
    if let Some(challenge) = TwoFactorChallenge::from_response(body) {
        return ApiError::TwoFactorRequired(challenge);
    }
    let message = field(body, "ErrorModel").and_then(|m| field_str(m, "Message"));
    if status == 400 && message.is_some_and(|m| m.eq_ignore_ascii_case(NEW_DEVICE_MESSAGE)) {
        return ApiError::NewDeviceVerificationRequired;
    }
    Client::rejection(status, body)
}

/// Looks a key up ignoring case, since servers differ in JSON casing.
pub fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let object = value.as_object()?;
    object.get(key).or_else(|| {
        object
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })
}

pub fn field_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    field(value, key).and_then(Value::as_str)
}

pub fn field_u64(value: &Value, key: &str) -> Option<u64> {
    field(value, key).and_then(Value::as_u64)
}

pub struct Client {
    agent: ureq::Agent,
    pub server: Server,
}

impl Client {
    pub fn new(server: Server) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .user_agent(format!("Hushjar/{}", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            server,
        }
    }

    fn read(
        mut response: ureq::http::Response<ureq::Body>,
        limit: u64,
    ) -> Result<(u16, Value), ApiError> {
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_string()
            .map_err(|e| ApiError::Network(e.to_string()))?;
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|_| ApiError::Decode)?
        };
        Ok((status, value))
    }

    fn net(e: ureq::Error) -> ApiError {
        ApiError::Network(e.to_string())
    }

    /// Turns an error reply into a readable message.
    fn rejection(status: u16, body: &Value) -> ApiError {
        if status == 401 {
            return ApiError::Unauthorized;
        }
        // Vaultwarden sends an empty error_description beside the message.
        let message = [
            field_str(body, "error_description"),
            field(body, "ErrorModel").and_then(|m| field_str(m, "Message")),
            field_str(body, "message"),
        ]
        .into_iter()
        .flatten()
        .find(|m| !m.trim().is_empty())
        .unwrap_or("the server refused the request");
        ApiError::Rejected(message.to_string())
    }

    pub fn prelogin(&self, email: &str) -> Result<Kdf, ApiError> {
        let response = self
            .agent
            .post(format!("{}/accounts/prelogin", self.server.identity))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .send_json(json!({ "email": email }))
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if status != 200 {
            return Err(Self::rejection(status, &body));
        }
        let kind = field_u64(&body, "kdf").ok_or(ApiError::Decode)? as u8;
        let iterations = field_u64(&body, "kdfIterations").ok_or(ApiError::Decode)? as u32;
        let memory = field_u64(&body, "kdfMemory").map(|v| v as u32);
        let parallelism = field_u64(&body, "kdfParallelism").map(|v| v as u32);
        Kdf::from_server(kind, iterations, memory, parallelism).map_err(|_| ApiError::Kdf)
    }

    /// Logs in with the master password hash.
    pub fn login(
        &self,
        email: &str,
        password_hash: &str,
        device: &Device,
        second: Option<SecondFactor<'_>>,
    ) -> Result<Login, ApiError> {
        self.password_grant(&PasswordGrant {
            email,
            secret: password_hash,
            device,
            second,
            new_device_code: None,
            auth_request: None,
        })
    }

    /// Runs a password grant: a master password login, optionally with a
    /// second factor or new-device code, or the final step of logging in
    /// with an approved request from another device.
    pub fn password_grant(&self, grant: &PasswordGrant<'_>) -> Result<Login, ApiError> {
        let PasswordGrant {
            email,
            secret,
            device,
            ..
        } = *grant;
        let kind = Device::kind().to_string();
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "password".into()),
            ("scope", "api offline_access".into()),
            ("client_id", CLIENT_ID.into()),
            ("username", email.into()),
            ("password", secret.into()),
            ("deviceIdentifier", device.identifier.clone()),
            ("deviceName", device.name.clone()),
            ("deviceType", kind),
        ];
        if let Some(second) = &grant.second {
            form.push(("twoFactorToken", second.token.into()));
            form.push(("twoFactorProvider", second.provider.code().to_string()));
            form.push((
                "twoFactorRemember",
                if second.remember { "1" } else { "0" }.into(),
            ));
        }
        if let Some(code) = grant.new_device_code {
            form.push(("newDeviceOtp", code.trim().into()));
        }
        if let Some(id) = grant.auth_request {
            form.push(("authRequest", id.into()));
        }
        let auth_email =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, email);
        let response = self
            .agent
            .post(format!("{}/connect/token", self.server.identity))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .header("Auth-Email", auth_email)
            .header("Device-Type", Device::kind().to_string())
            .send_form(form.iter().map(|(k, v)| (*k, v.as_str())))
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if status != 200 {
            return Err(login_rejection(status, &body));
        }
        let string = |key: &str| field_str(&body, key).map(str::to_string);
        Ok(Login {
            access_token: Zeroizing::new(string("access_token").ok_or(ApiError::Decode)?),
            refresh_token: Zeroizing::new(string("refresh_token").ok_or(ApiError::Decode)?),
            expires_in: field_u64(&body, "expires_in").unwrap_or(3600),
            key: string("Key").ok_or(ApiError::Decode)?,
            private_key: string("PrivateKey"),
            two_factor_token: string("TwoFactorToken").map(Zeroizing::new),
        })
    }

    /// Asks the server to email a two-step login code.
    pub fn send_email_code(
        &self,
        email: &str,
        password_hash: &str,
        device: &Device,
    ) -> Result<(), ApiError> {
        let response = self
            .agent
            .post(format!("{}/two-factor/send-email-login", self.server.api))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .send_json(json!({
                "email": email,
                "masterPasswordHash": password_hash,
                "deviceIdentifier": device.identifier,
            }))
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if status == 200 {
            Ok(())
        } else {
            Err(Self::rejection(status, &body))
        }
    }

    /// Asks Bitwarden to email a new code for confirming this device.
    /// Bitwarden answers the same way whether or not the details are right.
    pub fn resend_new_device_code(
        &self,
        email: &str,
        password_hash: &str,
        device: &Device,
    ) -> Result<(), ApiError> {
        let response = self
            .agent
            .post(format!(
                "{}/accounts/resend-new-device-otp",
                self.server.api
            ))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .header("Device-Identifier", &device.identifier)
            .header("Device-Type", Device::kind().to_string())
            .send_json(json!({
                "email": email,
                "masterPasswordHash": password_hash,
            }))
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(Self::rejection(status, &body))
        }
    }

    pub fn refresh(&self, refresh_token: &str) -> Result<Tokens, ApiError> {
        let response = self
            .agent
            .post(format!("{}/connect/token", self.server.identity))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .send_form([
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT_ID),
                ("refresh_token", refresh_token),
            ])
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if status != 200 {
            return Err(if status == 400 || status == 401 {
                ApiError::Unauthorized
            } else {
                Self::rejection(status, &body)
            });
        }
        Ok(Tokens {
            access_token: Zeroizing::new(
                field_str(&body, "access_token")
                    .ok_or(ApiError::Decode)?
                    .into(),
            ),
            refresh_token: Zeroizing::new(
                field_str(&body, "refresh_token")
                    .ok_or(ApiError::Decode)?
                    .into(),
            ),
            expires_in: field_u64(&body, "expires_in").unwrap_or(3600),
        })
    }

    fn authed(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<&Value>,
        limit: u64,
    ) -> Result<Value, ApiError> {
        let url = format!("{}{path}", self.server.api);
        let bearer = format!("Bearer {token}");
        let result = match (method, body) {
            ("GET", _) => self
                .agent
                .get(&url)
                .header("Authorization", &bearer)
                .header("Bitwarden-Client-Version", CLIENT_VERSION)
                .call(),
            ("DELETE", _) => self
                .agent
                .delete(&url)
                .header("Authorization", &bearer)
                .header("Bitwarden-Client-Version", CLIENT_VERSION)
                .call(),
            ("POST", Some(b)) => self
                .agent
                .post(&url)
                .header("Authorization", &bearer)
                .header("Bitwarden-Client-Version", CLIENT_VERSION)
                .send_json(b),
            ("PUT", Some(b)) => self
                .agent
                .put(&url)
                .header("Authorization", &bearer)
                .header("Bitwarden-Client-Version", CLIENT_VERSION)
                .send_json(b),
            ("PUT", None) => self
                .agent
                .put(&url)
                .header("Authorization", &bearer)
                .header("Bitwarden-Client-Version", CLIENT_VERSION)
                .send_empty(),
            _ => return Err(ApiError::Decode),
        };
        let (status, value) = Self::read(result.map_err(Self::net)?, limit)?;
        if (200..300).contains(&status) {
            Ok(value)
        } else {
            Err(Self::rejection(status, &value))
        }
    }

    pub fn sync(&self, token: &str) -> Result<Value, ApiError> {
        self.authed("GET", "/sync?excludeDomains=true", token, None, SYNC_LIMIT)
    }

    /// Creates a personal item. Returns the server's copy.
    pub fn create_cipher(&self, token: &str, cipher: &Value) -> Result<Value, ApiError> {
        self.authed("POST", "/ciphers", token, Some(cipher), SMALL_LIMIT * 16)
    }

    /// Creates an organisation item in the given collections.
    pub fn create_org_cipher(
        &self,
        token: &str,
        cipher: &Value,
        collections: &[String],
    ) -> Result<Value, ApiError> {
        let body = json!({ "cipher": cipher, "collectionIds": collections });
        self.authed(
            "POST",
            "/ciphers/create",
            token,
            Some(&body),
            SMALL_LIMIT * 16,
        )
    }

    pub fn update_cipher(&self, token: &str, id: &str, cipher: &Value) -> Result<Value, ApiError> {
        self.authed(
            "PUT",
            &format!("/ciphers/{id}"),
            token,
            Some(cipher),
            SMALL_LIMIT * 16,
        )
    }

    /// Moves an item to the trash.
    pub fn trash_cipher(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed(
            "PUT",
            &format!("/ciphers/{id}/delete"),
            token,
            None,
            SMALL_LIMIT,
        )
        .map(|_| ())
    }

    pub fn restore_cipher(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed(
            "PUT",
            &format!("/ciphers/{id}/restore"),
            token,
            None,
            SMALL_LIMIT,
        )
        .map(|_| ())
    }

    /// Deletes an item permanently.
    pub fn delete_cipher(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed(
            "DELETE",
            &format!("/ciphers/{id}"),
            token,
            None,
            SMALL_LIMIT,
        )
        .map(|_| ())
    }

    pub fn create_folder(&self, token: &str, encrypted_name: &str) -> Result<Value, ApiError> {
        let body = json!({ "name": encrypted_name });
        self.authed("POST", "/folders", token, Some(&body), SMALL_LIMIT)
    }
}

/// Copies an object and returns it as a map, for editing JSON in place.
pub fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_choices() {
        let com = Server::parse("").unwrap();
        assert_eq!(com.api, "https://api.bitwarden.com");
        assert_eq!(
            Server::parse("bitwarden.eu").unwrap().identity,
            "https://identity.bitwarden.eu"
        );
        let own = Server::parse("vault.example.org/").unwrap();
        assert_eq!(own.api, "https://vault.example.org/api");
        assert_eq!(own.name, "vault.example.org");
        assert!(Server::parse("http://127.0.0.1:18281").is_ok());
        assert!(
            Server::parse("http://vault.example.org").is_err(),
            "plain http only for loopback"
        );
        assert!(Server::parse("https://user@vault.example.org").is_err());
    }

    #[test]
    fn two_step_challenge_from_vaultwarden() {
        // The shape of Vaultwarden 1.37's json_err_twofactor.
        let body = json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "1", "3", "7"],
            "TwoFactorProviders2": {
                "0": null,
                "1": { "Email": "a***@example.invalid" },
                "3": { "Nfc": true },
                "7": { "challenge": "AAAA", "rpId": "vault.example.org", "allowCredentials": [] }
            },
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" }
        });
        let ApiError::TwoFactorRequired(challenge) = login_rejection(400, &body) else {
            panic!("expected two-step login");
        };
        assert_eq!(
            challenge.providers,
            vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::Email,
                TwoFactorProvider::YubiKey,
                TwoFactorProvider::WebAuthn,
            ]
        );
        assert!(challenge.providers.iter().all(|p| p.supported()));
        assert_eq!(challenge.email_hint(), Some("a***@example.invalid"));
        assert!(challenge.yubikey_nfc());
        assert_eq!(
            challenge
                .webauthn_options()
                .and_then(|o| field_str(o, "rpId")),
            Some("vault.example.org")
        );
        assert_eq!(challenge.details(TwoFactorProvider::Authenticator), None);
    }

    #[test]
    fn new_device_verification_is_its_own_error() {
        // Bitwarden's DeviceValidator.BuildDeviceErrorResult.
        let body = json!({
            "error": "device_error",
            "error_description": "New device verification required",
            "ErrorModel": { "Message": "new device verification required", "Object": "error" }
        });
        assert!(matches!(
            login_rejection(400, &body),
            ApiError::NewDeviceVerificationRequired
        ));
        let wrong = json!({
            "error": "device_error",
            "error_description": "Invalid New Device OTP",
            "ErrorModel": { "Message": "invalid new device otp", "Object": "error" }
        });
        assert!(
            matches!(login_rejection(400, &wrong), ApiError::Rejected(m) if m == "Invalid New Device OTP")
        );
        // Vaultwarden 1.37's wrong-password reply, with an empty description.
        let password = json!({
            "message": "Username or password is incorrect. Try again",
            "errorModel": { "message": "Username or password is incorrect. Try again", "object": "error" },
            "error": "",
            "error_description": "",
            "object": "error"
        });
        assert!(matches!(
            login_rejection(400, &password),
            ApiError::Rejected(m) if m == "Username or password is incorrect. Try again"
        ));
    }

    #[test]
    fn case_insensitive_fields() {
        let v = json!({ "Kdf": 1, "kdfIterations": 3 });
        assert_eq!(field_u64(&v, "kdf"), Some(1));
        assert_eq!(field_u64(&v, "KdfIterations"), Some(3));
    }
}
