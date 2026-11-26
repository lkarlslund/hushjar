//! Import and export of vault data in the formats other password managers
//! and Bitwarden use. Everything here works on strings; the app chooses the
//! files. Formats follow Bitwarden's own clients (see the module docs of
//! [`export`] and [`import`] for the source files each part mirrors).

pub mod export;
pub mod import;

use crate::crypto::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("this file is not in a format Hushjar can read: {0}")]
    Malformed(String),
    #[error("the file format could not be recognised; choose it by hand")]
    UnknownFormat,
    #[error("this file is protected with a password; enter it to continue")]
    PasswordRequired,
    #[error("wrong file password")]
    WrongPassword,
    #[error("this export is locked to a different account and cannot be opened here")]
    WrongAccount,
    #[error("the file uses key derivation settings Hushjar does not accept")]
    UnsupportedKdf,
    #[error("an item could not be decrypted ({0}); nothing was exported or imported")]
    Unreadable(String),
    #[error("the organisation is not available to this account")]
    UnknownOrganization,
    #[error("a file password is required")]
    EmptyPassword,
    #[error("encryption failed: {0}")]
    Crypto(#[from] CryptoError),
}

impl From<serde_json::Error> for ExchangeError {
    fn from(error: serde_json::Error) -> Self {
        ExchangeError::Malformed(error.to_string())
    }
}

impl From<csv::Error> for ExchangeError {
    fn from(error: csv::Error) -> Self {
        ExchangeError::Malformed(error.to_string())
    }
}

use zeroize::Zeroizing;

use crate::session::Session;

use export::Scope;

/// Export and import for an unlocked account, using its own keys and key
/// derivation settings.
impl Session {
    pub fn export_json(&self, scope: Scope) -> Result<Zeroizing<String>, ExchangeError> {
        export::json(&self.vault, self.keys(), scope)
    }

    pub fn export_csv(&self, scope: Scope) -> Result<Zeroizing<String>, ExchangeError> {
        export::csv(&self.vault, scope)
    }

    pub fn export_encrypted_json(&self, scope: Scope) -> Result<Zeroizing<String>, ExchangeError> {
        export::encrypted_json(&self.vault, self.keys(), scope)
    }

    pub fn export_password_protected_json(
        &self,
        scope: Scope,
        password: &str,
    ) -> Result<Zeroizing<String>, ExchangeError> {
        export::password_protected_json(&self.vault, self.keys(), scope, self.profile.kdf, password)
    }

    /// Parses an import file with this account's keys, so account-locked
    /// Bitwarden exports can be opened.
    pub fn parse_import(
        &self,
        text: &str,
        format: Option<import::Format>,
        password: Option<&str>,
    ) -> Result<import::ParsedImport, ExchangeError> {
        let context = import::Context {
            keys: Some(self.keys()),
            password,
        };
        import::parse(text, format, &context)
    }
}
