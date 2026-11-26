//! Login requests between devices ("log in with a device").
//!
//! A device without the master password posts a request carrying a fresh
//! RSA public key and a random access code. Another signed-in device of the
//! same account approves it by sending the user key encrypted to that public
//! key. The requesting device then logs in with the access code as password.

use serde_json::{Value, json};

use super::{ApiError, CLIENT_VERSION, Client, Device, SMALL_LIMIT, field, field_str};

/// Request type 0 asks for both authentication and the user key.
const AUTHENTICATE_AND_UNLOCK: u8 = 0;

/// A login request as the server reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub id: String,
    /// The requesting device's RSA public key, SubjectPublicKeyInfo DER in
    /// standard base64.
    pub public_key: String,
    /// The requesting device type as the server names it, such as "Linux".
    pub device_type: String,
    pub ip_address: String,
    /// When the request was made, as the server's ISO 8601 text.
    pub created: String,
    /// The user key (or, from old clients, the master key) encrypted to the
    /// public key; set once approved.
    pub key: Option<String>,
    /// Set when the approver shared the master key instead of the user key.
    pub master_password_hash: Option<String>,
    /// `None` while pending; Bitwarden sends `false` when denied.
    pub approved: Option<bool>,
}

impl AuthRequest {
    fn from_json(value: &Value) -> Option<Self> {
        let text = |k: &str| field_str(value, k).map(str::to_string);
        let id = text("id")?;
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
        Some(Self {
            id,
            public_key: text("publicKey")?,
            device_type: text("requestDeviceType").unwrap_or_default(),
            ip_address: text("requestIpAddress").unwrap_or_default(),
            created: text("creationDate").unwrap_or_default(),
            key: text("key").filter(|k| !k.is_empty()),
            master_password_hash: text("masterPasswordHash").filter(|k| !k.is_empty()),
            approved: field(value, "requestApproved").and_then(Value::as_bool),
        })
    }
}

/// Request IDs go into URL paths, so only UUID characters are allowed.
fn check_id(id: &str) -> Result<(), ApiError> {
    if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        Ok(())
    } else {
        Err(ApiError::Decode)
    }
}

impl Client {
    /// Posts a login request without signing in. Vaultwarden accepts it only
    /// from a device that has signed in to the account before.
    pub fn create_auth_request(
        &self,
        email: &str,
        public_key_b64: &str,
        device: &Device,
        access_code: &str,
    ) -> Result<AuthRequest, ApiError> {
        let response = self
            .agent
            .post(format!("{}/auth-requests", self.server.api))
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .header("Device-Type", Device::kind().to_string())
            .header("Device-Identifier", &device.identifier)
            .send_json(json!({
                "email": email,
                "publicKey": public_key_b64,
                "deviceIdentifier": device.identifier,
                "accessCode": access_code,
                "type": AUTHENTICATE_AND_UNLOCK,
            }))
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if status != 200 {
            return Err(Self::rejection(status, &body));
        }
        AuthRequest::from_json(&body).ok_or(ApiError::Decode)
    }

    /// Checks a login request this device made, proving it with the access
    /// code. Needs no sign-in.
    pub fn auth_request_response(
        &self,
        id: &str,
        access_code: &str,
    ) -> Result<AuthRequest, ApiError> {
        check_id(id)?;
        let response = self
            .agent
            .get(format!("{}/auth-requests/{id}/response", self.server.api))
            .query("code", access_code)
            .header("Bitwarden-Client-Version", CLIENT_VERSION)
            .header("Device-Type", Device::kind().to_string())
            .call()
            .map_err(Self::net)?;
        let (status, body) = Self::read(response, SMALL_LIMIT)?;
        if status != 200 {
            return Err(Self::rejection(status, &body));
        }
        AuthRequest::from_json(&body).ok_or(ApiError::Decode)
    }

    /// Login requests for the signed-in account that nobody has answered.
    pub fn pending_auth_requests(&self, token: &str) -> Result<Vec<AuthRequest>, ApiError> {
        let body = self.authed("GET", "/auth-requests/pending", token, None, SMALL_LIMIT)?;
        Ok(field(&body, "data")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(AuthRequest::from_json).collect())
            .unwrap_or_default())
    }

    /// Approves or denies a login request. `key` is the user key encrypted to
    /// the request's public key; it is empty when denying.
    pub fn answer_auth_request(
        &self,
        token: &str,
        id: &str,
        key: &str,
        device: &Device,
        approve: bool,
    ) -> Result<(), ApiError> {
        check_id(id)?;
        // Vaultwarden requires a key string even for a denial.
        let body = json!({
            "key": key,
            "masterPasswordHash": null,
            "deviceIdentifier": device.identifier,
            "requestApproved": approve,
        });
        self.authed(
            "PUT",
            &format!("/auth-requests/{id}"),
            token,
            Some(&body),
            SMALL_LIMIT,
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_vaultwarden_request() {
        let pending = json!({
            "id": "0f8c2a51-1111-4c2e-9d55-6f1ad3b0c001",
            "publicKey": "MIIBIjAN",
            "requestDeviceType": "Linux",
            "requestIpAddress": "127.0.0.1",
            "key": null,
            "masterPasswordHash": null,
            "creationDate": "2026-11-26T10:00:00.000000Z",
            "responseDate": null,
            "requestApproved": null,
            "origin": "http://127.0.0.1:18281",
            "object": "auth-request"
        });
        let request = AuthRequest::from_json(&pending).unwrap();
        assert_eq!(request.device_type, "Linux");
        assert_eq!(request.approved, None);
        assert_eq!(request.key, None);
        let mut approved = pending.clone();
        approved["key"] = json!("4.AAAA");
        approved["requestApproved"] = json!(true);
        let request = AuthRequest::from_json(&approved).unwrap();
        assert_eq!(request.approved, Some(true));
        assert_eq!(request.key.as_deref(), Some("4.AAAA"));
    }

    #[test]
    fn refuses_ids_that_would_change_the_path() {
        let bad = json!({ "id": "../accounts", "publicKey": "x" });
        assert!(AuthRequest::from_json(&bad).is_none());
        assert!(check_id("a/b").is_err());
        assert!(check_id("").is_err());
    }
}
