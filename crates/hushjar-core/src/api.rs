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
    #[error("the server does not know this request")]
    NotFound,
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

    /// The base address of the server's notification service, which pushes
    /// vault changes over a websocket at `<base>/hub`. Bitwarden's cloud runs
    /// it on its own host; self-hosted servers serve it under
    /// `/notifications`. Derived rather than stored, so saved profiles need no
    /// new field.
    pub fn notifications(&self) -> String {
        if let Some(region) = self.api.strip_prefix("https://api.bitwarden.") {
            return format!("https://notifications.bitwarden.{region}");
        }
        let base = self.api.strip_suffix("/api").unwrap_or(&self.api);
        format!("{base}/notifications")
    }

    /// Which Bitwarden cloud region this is, if any.
    fn cloud_region(&self) -> Option<&'static str> {
        match self.api.as_str() {
            "https://api.bitwarden.com" => Some("com"),
            "https://api.bitwarden.eu" => Some("eu"),
            _ => None,
        }
    }

    /// The web vault's address: Bitwarden's vault host for the cloud, the
    /// server's own address when self-hosted.
    pub fn web_vault(&self) -> String {
        match self.cloud_region() {
            Some(region) => format!("https://vault.bitwarden.{region}"),
            None => self
                .api
                .strip_suffix("/api")
                .unwrap_or(&self.api)
                .to_string(),
        }
    }

    /// The share link for a Send: `{send url}{access id}/{key}`, the key
    /// material in unpadded URL-safe base64 after the `#` so it never
    /// reaches a server.
    ///
    /// The Send address follows the Bitwarden clients'
    /// `DefaultEnvironmentService.getSendUrl` (libs/common/src/platform/
    /// services/default-environment.service.ts): the US cloud uses
    /// `https://send.bitwarden.com/#`, the EU cloud
    /// `https://vault.bitwarden.eu/#/send/`, and self-hosted servers
    /// `{web vault}/#/send/`. The link itself is built as in
    /// libs/tools/share/src/services/share-link.service.ts.
    pub fn send_link(&self, access_id: &str, key_material: &[u8]) -> String {
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            key_material,
        );
        let prefix = match self.cloud_region() {
            Some("com") => "https://send.bitwarden.com/#".to_string(),
            _ => format!("{}/#/send/", self.web_vault()),
        };
        format!("{prefix}{access_id}/{key}")
    }

    /// Scheme, host and port of the API address, such as
    /// `http://127.0.0.1:8000`.
    fn origin(&self) -> &str {
        let after_scheme = self.api.find("://").map_or(0, |i| i + 3);
        match self.api[after_scheme..].find('/') {
            Some(slash) => &self.api[..after_scheme + slash],
            None => &self.api,
        }
    }
}

/// Where an uploaded file goes, from the server's reply to a new
/// attachment or file Send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileUpload {
    /// Post the file to the server itself as `multipart/form-data`.
    Direct,
    /// Put the file to an Azure blob storage address signed by the server
    /// (bitwarden.com and bitwarden.eu).
    Azure(String),
}

impl FileUpload {
    /// Reads `fileUploadType` (0 direct, 1 Azure) and `url` from a reply.
    pub fn from_reply(reply: &Value) -> Result<Self, ApiError> {
        match field_u64(reply, "fileUploadType") {
            Some(0) => Ok(FileUpload::Direct),
            Some(1) => field_str(reply, "url")
                .map(|u| FileUpload::Azure(u.to_string()))
                .ok_or(ApiError::Decode),
            _ => Err(ApiError::Decode),
        }
    }
}

/// Largest file Bitwarden accepts as an attachment or Send: 500 MiB, the
/// clients' limit (`fileSize > 524288000` is refused before upload).
pub const MAX_FILE_BYTES: usize = 500 << 20;
/// Largest encrypted file read from a server: the limit above plus room
/// for the encryption overhead, which is at most 65 bytes.
const FILE_LIMIT: u64 = (MAX_FILE_BYTES + 4096) as u64;
/// Above this size Azure uploads go in a block and a block list, as the
/// Bitwarden clients do (`MAX_SINGLE_BLOB_UPLOAD_SIZE`).
const AZURE_SINGLE_PUT_LIMIT: usize = 256 << 20;

/// A `multipart/form-data` body with one file part, as the Bitwarden
/// clients send it (`BitwardenFileUploadService`): field `data`, the
/// encrypted file name as the file name, `application/octet-stream`.
/// Returns the content type, with its random boundary, and the body.
pub fn multipart_body(
    field_name: &str,
    file_name: &str,
    data: &[u8],
) -> Result<(String, Vec<u8>), ApiError> {
    let unsafe_char = |c: char| c == '"' || c == '\\' || c.is_control();
    if field_name.chars().any(unsafe_char) || file_name.chars().any(unsafe_char) {
        return Err(ApiError::Decode);
    }
    let boundary = format!(
        "hushjar-{}",
        crate::crypto::random_bytes::<16>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let head = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    let tail = format!("\r\n--{boundary}--\r\n");
    let mut body = Vec::with_capacity(head.len() + data.len() + tail.len());
    body.extend_from_slice(head.as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(tail.as_bytes());
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}

/// A date in the HTTP format (RFC 9110 IMF-fixdate), for `x-ms-date`.
fn http_date(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (unix / 86_400) as i64;
    let rem = unix % 86_400;
    let (year, month, day) = crate::vault::civil_date(days);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// One query parameter of a URL, undecoded.
fn query_param<'a>(url: &'a str, name: &str) -> Option<&'a str> {
    let query = url.split_once('?')?.1.split('#').next()?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// The Azure block id the Bitwarden clients use for block 0: base64 of the
/// index left-padded with zeros to 48 characters (`encodedBlockId`).
fn azure_block_id(index: usize) -> String {
    let padded = format!("{index:0>48}");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, padded)
}

/// Percent-encodes the characters of a base64 value that are not safe in
/// a query string.
fn query_escape(value: &str) -> String {
    value
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
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
    /// For file uploads and downloads, which may take longer than the
    /// overall limit for API calls. Stalls are still cut off per read and
    /// write.
    files: ureq::Agent,
    pub server: Server,
}

impl Client {
    pub fn new(server: Server) -> Self {
        let user_agent = format!("Hushjar/{}", env!("CARGO_PKG_VERSION"));
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .user_agent(user_agent.clone())
            .build();
        let files = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60 * 60)))
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_per_read(Some(Duration::from_secs(120)))
            .timeout_per_write(Some(Duration::from_secs(120)))
            .http_status_as_error(false)
            .user_agent(user_agent)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            files: ureq::Agent::new_with_config(files),
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
            match serde_json::from_str(&text) {
                Ok(value) => value,
                // Error pages from proxies and unknown routes are not JSON.
                Err(_) if !(200..300).contains(&status) => Value::Null,
                Err(_) => return Err(ApiError::Decode),
            }
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
        if status == 404 || status == 405 {
            return ApiError::NotFound;
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

    /// Archives an item. Servers without archiving answer `NotFound`.
    pub fn archive_cipher(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed(
            "PUT",
            &format!("/ciphers/{id}/archive"),
            token,
            None,
            SMALL_LIMIT * 16,
        )
        .map(|_| ())
    }

    /// Takes an item out of the archive.
    pub fn unarchive_cipher(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed(
            "PUT",
            &format!("/ciphers/{id}/unarchive"),
            token,
            None,
            SMALL_LIMIT * 16,
        )
        .map(|_| ())
    }

    /// Moves a personal item into an organisation and its collections:
    /// `{cipher, collectionIds}`. Returns the server's copy.
    pub fn share_cipher(&self, token: &str, id: &str, body: &Value) -> Result<Value, ApiError> {
        self.authed(
            "PUT",
            &format!("/ciphers/{id}/share"),
            token,
            Some(body),
            SMALL_LIMIT * 16,
        )
    }

    /// Replaces the collections an organisation item is in.
    pub fn set_cipher_collections(
        &self,
        token: &str,
        id: &str,
        collections: &[String],
    ) -> Result<Value, ApiError> {
        let body = json!({ "collectionIds": collections });
        self.authed(
            "PUT",
            &format!("/ciphers/{id}/collections"),
            token,
            Some(&body),
            SMALL_LIMIT * 16,
        )
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

    pub fn rename_folder(
        &self,
        token: &str,
        id: &str,
        encrypted_name: &str,
    ) -> Result<Value, ApiError> {
        let body = json!({ "name": encrypted_name });
        self.authed(
            "PUT",
            &format!("/folders/{id}"),
            token,
            Some(&body),
            SMALL_LIMIT,
        )
    }

    /// Deletes a folder. Its items stay, without a folder.
    pub fn delete_folder(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed(
            "DELETE",
            &format!("/folders/{id}"),
            token,
            None,
            SMALL_LIMIT,
        )
        .map(|_| ())
    }

    /// Asks where to download an attachment. The reply carries a `url`,
    /// and the attachment's current `key` and `fileName`.
    pub fn attachment_info(
        &self,
        token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<Value, ApiError> {
        self.authed(
            "GET",
            &format!("/ciphers/{cipher_id}/attachment/{attachment_id}"),
            token,
            None,
            SMALL_LIMIT,
        )
    }

    /// Registers a new attachment: `{key, fileName, fileSize, ...}`. The
    /// reply names the attachment and says where to upload it
    /// (`attachmentId`, `fileUploadType`, `url`, `cipherResponse`).
    pub fn create_attachment(
        &self,
        token: &str,
        cipher_id: &str,
        body: &Value,
    ) -> Result<Value, ApiError> {
        self.authed(
            "POST",
            &format!("/ciphers/{cipher_id}/attachment/v2"),
            token,
            Some(body),
            SMALL_LIMIT * 16,
        )
    }

    /// Uploads an attachment's encrypted contents to the server itself.
    /// Same route in Vaultwarden (`post_attachment_v2_data` in
    /// src/api/core/ciphers.rs) and Bitwarden (`postAttachmentFile`).
    pub fn upload_attachment(
        &self,
        token: &str,
        cipher_id: &str,
        attachment_id: &str,
        encrypted_name: &str,
        data: &[u8],
    ) -> Result<(), ApiError> {
        self.post_file(
            token,
            &format!("/ciphers/{cipher_id}/attachment/{attachment_id}"),
            encrypted_name,
            data,
        )
    }

    pub fn delete_attachment(
        &self,
        token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<(), ApiError> {
        self.authed(
            "DELETE",
            &format!("/ciphers/{cipher_id}/attachment/{attachment_id}"),
            token,
            None,
            SMALL_LIMIT * 16,
        )
        .map(|_| ())
    }

    /// Creates a text Send. Returns the server's copy.
    pub fn create_send(&self, token: &str, send: &Value) -> Result<Value, ApiError> {
        self.authed("POST", "/sends", token, Some(send), SMALL_LIMIT * 16)
    }

    /// Registers a file Send; the body carries `fileLength`. The reply says
    /// where to upload (`fileUploadType`, `url`) and holds `sendResponse`.
    pub fn create_file_send(&self, token: &str, send: &Value) -> Result<Value, ApiError> {
        self.authed(
            "POST",
            "/sends/file/v2",
            token,
            Some(send),
            SMALL_LIMIT * 16,
        )
    }

    /// Uploads a file Send's encrypted contents to the server itself.
    /// Vaultwarden checks that the file name equals the encrypted name it
    /// stored (`post_send_file_v2_data` in src/api/core/sends.rs).
    pub fn upload_send_file(
        &self,
        token: &str,
        send_id: &str,
        file_id: &str,
        encrypted_name: &str,
        data: &[u8],
    ) -> Result<(), ApiError> {
        self.post_file(
            token,
            &format!("/sends/{send_id}/file/{file_id}"),
            encrypted_name,
            data,
        )
    }

    pub fn update_send(&self, token: &str, id: &str, send: &Value) -> Result<Value, ApiError> {
        self.authed(
            "PUT",
            &format!("/sends/{id}"),
            token,
            Some(send),
            SMALL_LIMIT * 16,
        )
    }

    pub fn remove_send_password(&self, token: &str, id: &str) -> Result<Value, ApiError> {
        self.authed(
            "PUT",
            &format!("/sends/{id}/remove-password"),
            token,
            None,
            SMALL_LIMIT * 16,
        )
    }

    pub fn delete_send(&self, token: &str, id: &str) -> Result<(), ApiError> {
        self.authed("DELETE", &format!("/sends/{id}"), token, None, SMALL_LIMIT)
            .map(|_| ())
    }

    /// Posts one encrypted file as `multipart/form-data` to an API path.
    fn post_file(
        &self,
        token: &str,
        path: &str,
        encrypted_name: &str,
        data: &[u8],
    ) -> Result<(), ApiError> {
        let (content_type, body) = multipart_body("data", encrypted_name, data)?;
        let response = self
            .files
            .post(format!("{}{path}", self.server.api))
            .header("Authorization", format!("Bearer {token}"))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .header("Content-Type", content_type)
            .send(&body[..])
            .map_err(Self::net)?;
        let (status, value) = Self::read(response, SMALL_LIMIT)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(Self::rejection(status, &value))
        }
    }

    /// Turns a file address from the server into an absolute URL. Relative
    /// addresses are taken as relative to the API. Plain http is allowed
    /// only on the server's own origin, which `Server::parse` already
    /// limits to this computer.
    fn file_url(&self, url: &str) -> Result<String, ApiError> {
        let absolute = if url.starts_with('/') {
            format!("{}{url}", self.server.api)
        } else {
            url.to_string()
        };
        let lower = absolute.to_ascii_lowercase();
        let origin = self.server.origin().to_ascii_lowercase();
        let same_origin = lower == origin
            || lower
                .strip_prefix(&origin)
                .is_some_and(|rest| rest.starts_with(['/', '?']));
        if lower.starts_with("https://") || same_origin {
            Ok(absolute)
        } else {
            Err(ApiError::BadUrl(
                "the server gave an unsafe file address".into(),
            ))
        }
    }

    /// Downloads an encrypted file from an address the server handed out.
    /// No access token is sent: the address carries its own short-lived
    /// grant, and may belong to a storage service rather than the server.
    pub fn download(&self, url: &str) -> Result<Vec<u8>, ApiError> {
        let url = self.file_url(url)?;
        let mut response = self.files.get(&url).call().map_err(Self::net)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(ApiError::Rejected(format!(
                "the file could not be downloaded (status {status})"
            )));
        }
        response
            .body_mut()
            .with_config()
            .limit(FILE_LIMIT)
            .read_to_vec()
            .map_err(|e| ApiError::Network(e.to_string()))
    }

    /// Uploads an encrypted file to a signed Azure blob address, as the
    /// Bitwarden clients' `AzureFileUploadService` does: one `PUT` with
    /// `x-ms-blob-type: BlockBlob` up to 256 MiB, otherwise one block and
    /// a block list. Azure answers 201 Created.
    pub fn upload_azure(&self, url: &str, data: &[u8]) -> Result<(), ApiError> {
        self.upload_azure_in_parts(url, data, AZURE_SINGLE_PUT_LIMIT)
    }

    fn upload_azure_in_parts(
        &self,
        url: &str,
        data: &[u8],
        single_put_limit: usize,
    ) -> Result<(), ApiError> {
        let url = self.file_url(url)?;
        let url = url.as_str();
        let version = query_param(url, "sv").unwrap_or("").to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let put = |target: &str, body: &[u8], blob_header: bool| {
            let mut request = self
                .files
                .put(target)
                .header("x-ms-date", http_date(now))
                .header("x-ms-version", &version);
            if blob_header {
                request = request.header("x-ms-blob-type", "BlockBlob");
            }
            let response = request.send(body).map_err(Self::net)?;
            match response.status().as_u16() {
                201 => Ok(()),
                status => Err(ApiError::Rejected(format!(
                    "the file storage refused the upload (status {status})"
                ))),
            }
        };
        if data.len() <= single_put_limit {
            return put(url, data, true);
        }
        let block = azure_block_id(0);
        let joiner = if url.contains('?') { '&' } else { '?' };
        put(
            &format!("{url}{joiner}comp=block&blockid={}", query_escape(&block)),
            data,
            false,
        )?;
        let list = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{block}</Latest></BlockList>"
        );
        put(
            &format!("{url}{joiner}comp=blocklist"),
            list.as_bytes(),
            false,
        )
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
    fn notification_addresses() {
        let at = |input: &str| Server::parse(input).unwrap().notifications();
        assert_eq!(at("bitwarden.com"), "https://notifications.bitwarden.com");
        assert_eq!(at("bitwarden.eu"), "https://notifications.bitwarden.eu");
        assert_eq!(
            at("vault.example.org/bw"),
            "https://vault.example.org/bw/notifications"
        );
        assert_eq!(
            at("http://127.0.0.1:18281"),
            "http://127.0.0.1:18281/notifications"
        );
    }

    #[test]
    fn case_insensitive_fields() {
        let v = json!({ "Kdf": 1, "kdfIterations": 3 });
        assert_eq!(field_u64(&v, "kdf"), Some(1));
        assert_eq!(field_u64(&v, "KdfIterations"), Some(3));
    }

    #[test]
    fn web_vault_and_send_links() {
        let key = [
            0x3e, 0x0b, 0xa2, 0xd0, 0x52, 0xbc, 0xe5, 0xc3, 0x61, 0x04, 0x65, 0x87, 0x02, 0x50,
            0x47, 0x07,
        ];
        let com = Server::parse("bitwarden.com").unwrap();
        assert_eq!(com.web_vault(), "https://vault.bitwarden.com");
        assert_eq!(
            com.send_link("ct2APRQtJk-BLLDwAYqhRA", &key),
            "https://send.bitwarden.com/#ct2APRQtJk-BLLDwAYqhRA/Pgui0FK85cNhBGWHAlBHBw"
        );
        let eu = Server::parse("bitwarden.eu").unwrap();
        assert_eq!(eu.web_vault(), "https://vault.bitwarden.eu");
        assert_eq!(
            eu.send_link("abc", &key),
            "https://vault.bitwarden.eu/#/send/abc/Pgui0FK85cNhBGWHAlBHBw"
        );
        let own = Server::parse("https://vault.example.org/vw/").unwrap();
        assert_eq!(own.web_vault(), "https://vault.example.org/vw");
        assert_eq!(
            own.send_link("abc", &key),
            "https://vault.example.org/vw/#/send/abc/Pgui0FK85cNhBGWHAlBHBw"
        );
        assert_eq!(own.origin(), "https://vault.example.org");
    }

    #[test]
    fn multipart_layout() {
        let (content_type, body) =
            multipart_body("data", "2.aa+/|bb==|cc", b"\x00\x01bytes").unwrap();
        let boundary = content_type
            .strip_prefix("multipart/form-data; boundary=")
            .unwrap();
        let expected = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"2.aa+/|bb==|cc\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01bytes\r\n--{boundary}--\r\n"
        );
        assert_eq!(body, expected.as_bytes());
        assert!(multipart_body("data", "bad\"name", b"").is_err());
        assert!(multipart_body("data", "bad\r\nname", b"").is_err());
        let (other, _) = multipart_body("data", "x", b"").unwrap();
        assert_ne!(other, content_type, "boundaries are random");
    }

    #[test]
    fn small_helpers() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        let url = "https://x.blob.core.windows.net/c/f?sv=2020-04-08&se=2026&sig=a%2Fb";
        assert_eq!(query_param(url, "sv"), Some("2020-04-08"));
        assert_eq!(query_param(url, "sig"), Some("a%2Fb"));
        assert_eq!(query_param(url, "none"), None);
        assert_eq!(
            azure_block_id(0),
            "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
        );
        assert_eq!(query_escape("a+b/c="), "a%2Bb%2Fc%3D");
        assert_eq!(
            FileUpload::from_reply(&json!({ "fileUploadType": 0, "url": "/x" })).unwrap(),
            FileUpload::Direct
        );
        assert_eq!(
            FileUpload::from_reply(&json!({ "FileUploadType": 1, "Url": "https://blob" })).unwrap(),
            FileUpload::Azure("https://blob".into())
        );
        assert!(FileUpload::from_reply(&json!({ "fileUploadType": 7 })).is_err());
    }

    #[test]
    fn file_addresses_must_be_safe() {
        let local = Client::new(Server::parse("http://127.0.0.1:18281").unwrap());
        assert_eq!(
            local.file_url("/attachments/a/b?token=t").unwrap(),
            "http://127.0.0.1:18281/api/attachments/a/b?token=t"
        );
        assert!(
            local
                .file_url("http://127.0.0.1:18281/attachments/a")
                .is_ok()
        );
        assert!(
            local
                .file_url("http://127.0.0.1:18281.evil.example/a")
                .is_err()
        );
        assert!(local.file_url("http://127.0.0.1:9/a").is_err());
        assert!(local.file_url("https://storage.example/a").is_ok());
        let remote = Client::new(Server::parse("vault.example.org").unwrap());
        assert!(remote.file_url("http://vault.example.org/a").is_err());
        assert!(remote.file_url("file:///etc/passwd").is_err());
    }

    /// A request seen by the mock server: request line, headers, body.
    type Seen = (String, Vec<(String, String)>, Vec<u8>);

    /// A tiny HTTP server that answers every request with `status` and
    /// returns what it received: (request line, headers, body).
    fn mock_server(status: u16, requests: usize) -> (String, std::thread::JoinHandle<Vec<Seen>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            while seen.len() < requests {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                while seen.len() < requests {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 {
                        break;
                    }
                    let mut headers = Vec::new();
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        let (k, v) = h.split_once(':').unwrap();
                        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
                    }
                    let length: usize = headers
                        .iter()
                        .find(|(k, _)| k == "content-length")
                        .map_or(0, |(_, v)| v.parse().unwrap());
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    seen.push((line.trim_end().to_string(), headers, body));
                    write!(writer, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").unwrap();
                }
            }
            seen
        });
        (base, handle)
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn azure_single_put() {
        let (base, server) = mock_server(201, 1);
        let client = Client::new(Server::parse(&base).unwrap());
        let url = format!("{base}/container/file?sv=2024-08-04&sig=abc");
        client.upload_azure(&url, b"encrypted bytes").unwrap();
        let seen = server.join().unwrap();
        let (line, headers, body) = &seen[0];
        assert_eq!(line, "PUT /container/file?sv=2024-08-04&sig=abc HTTP/1.1");
        assert_eq!(header(headers, "x-ms-blob-type"), Some("BlockBlob"));
        assert_eq!(header(headers, "x-ms-version"), Some("2024-08-04"));
        assert!(header(headers, "x-ms-date").unwrap().ends_with(" GMT"));
        assert!(header(headers, "authorization").is_none());
        assert_eq!(body, b"encrypted bytes");
    }

    #[test]
    fn azure_block_upload_for_large_files() {
        let (base, server) = mock_server(201, 2);
        let client = Client::new(Server::parse(&base).unwrap());
        let url = format!("{base}/c/f?sv=2024-08-04&sig=abc");
        client
            .upload_azure_in_parts(&url, b"0123456789", 4)
            .unwrap();
        let seen = server.join().unwrap();
        let block = azure_block_id(0);
        assert_eq!(
            seen[0].0,
            format!("PUT /c/f?sv=2024-08-04&sig=abc&comp=block&blockid={block} HTTP/1.1")
        );
        assert_eq!(header(&seen[0].1, "x-ms-blob-type"), None);
        assert_eq!(seen[0].2, b"0123456789");
        assert_eq!(
            seen[1].0,
            "PUT /c/f?sv=2024-08-04&sig=abc&comp=blocklist HTTP/1.1"
        );
        assert_eq!(
            String::from_utf8(seen[1].2.clone()).unwrap(),
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{block}</Latest></BlockList>"
            )
        );
    }

    #[test]
    fn azure_refusal_is_an_error() {
        let (base, server) = mock_server(403, 1);
        let client = Client::new(Server::parse(&base).unwrap());
        assert!(
            client
                .upload_azure(&format!("{base}/c/f?sv=1"), b"x")
                .is_err()
        );
        server.join().unwrap();
        assert!(
            client
                .upload_azure("http://elsewhere.example/c", b"x")
                .is_err()
        );
    }

    #[test]
    fn missing_archive_endpoint_is_not_found() {
        let (base, server) = mock_server(404, 2);
        let client = Client::new(Server::parse(&base).unwrap());
        assert!(matches!(
            client.archive_cipher("t", "id"),
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            client.unarchive_cipher("t", "id"),
            Err(ApiError::NotFound)
        ));
        let seen = server.join().unwrap();
        assert!(seen[0].0.starts_with("PUT /api/ciphers/id/archive"));
        assert!(seen[1].0.starts_with("PUT /api/ciphers/id/unarchive"));
    }
}
