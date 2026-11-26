//! HTTP client for the Bitwarden and Vaultwarden APIs.
//!
//! Requests are blocking; the app runs them on worker threads. HTTPS is
//! required except for loopback addresses, which test servers use.

use std::time::Duration;

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::crypto::Kdf;

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
    TwoFactorRequired(Vec<TwoFactorProvider>),
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
    YubiKey,
    Other(u8),
}

impl TwoFactorProvider {
    pub fn code(self) -> u8 {
        match self {
            TwoFactorProvider::Authenticator => 0,
            TwoFactorProvider::Email => 1,
            TwoFactorProvider::YubiKey => 3,
            TwoFactorProvider::Other(n) => n,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            0 => TwoFactorProvider::Authenticator,
            1 => TwoFactorProvider::Email,
            3 => TwoFactorProvider::YubiKey,
            n => TwoFactorProvider::Other(n),
        }
    }

    pub fn supported(self) -> bool {
        !matches!(self, TwoFactorProvider::Other(_))
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
        let message = field_str(body, "error_description")
            .or_else(|| field(body, "ErrorModel").and_then(|m| field_str(m, "Message")))
            .or_else(|| field_str(body, "message"))
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
        let kind = Device::kind().to_string();
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "password".into()),
            ("scope", "api offline_access".into()),
            ("client_id", CLIENT_ID.into()),
            ("username", email.into()),
            ("password", password_hash.into()),
            ("deviceIdentifier", device.identifier.clone()),
            ("deviceName", device.name.clone()),
            ("deviceType", kind),
        ];
        if let Some(second) = &second {
            form.push(("twoFactorToken", second.token.into()));
            form.push(("twoFactorProvider", second.provider.code().to_string()));
            form.push((
                "twoFactorRemember",
                if second.remember { "1" } else { "0" }.into(),
            ));
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
            if let Some(providers) = field(&body, "TwoFactorProviders2").and_then(Value::as_object)
            {
                let mut list: Vec<TwoFactorProvider> = providers
                    .keys()
                    .filter_map(|k| k.parse::<u8>().ok())
                    .map(TwoFactorProvider::from_code)
                    .collect();
                list.sort_by_key(|p| p.code());
                return Err(ApiError::TwoFactorRequired(list));
            }
            return Err(Self::rejection(status, &body));
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

    /// Uploads a batch of imported items and folders in one request.
    pub fn import_ciphers(&self, token: &str, body: &Value) -> Result<(), ApiError> {
        self.authed("POST", "/ciphers/import", token, Some(body), SMALL_LIMIT)
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
    fn case_insensitive_fields() {
        let v = json!({ "Kdf": 1, "kdfIterations": 3 });
        assert_eq!(field_u64(&v, "kdf"), Some(1));
        assert_eq!(field_u64(&v, "KdfIterations"), Some(3));
    }
}
