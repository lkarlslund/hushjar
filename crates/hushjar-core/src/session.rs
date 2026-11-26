//! An unlocked account: signing in, offline unlock, sync and saving.
//!
//! A session is used from one worker thread at a time; the app sends it
//! commands and receives copies of the decrypted vault.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::api::{
    ApiError, Client, Device, SecondFactor, Server, TwoFactorProvider, field, field_str,
};
use crate::crypto::{self, CryptoError, HashPurpose, PrivateKey};
use crate::store::{Profile, Store};
use crate::vault::{self, Item, Keys, Vault, VaultError};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("wrong master password")]
    WrongPassword,
    #[error("two-step login is required")]
    TwoFactorRequired(Vec<TwoFactorProvider>),
    #[error("sign in again to reconnect this account")]
    SignInRequired,
    #[error("{0}")]
    Api(ApiError),
    #[error("{0}")]
    Vault(#[from] VaultError),
    #[error("encryption failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("could not save to disk: {0}")]
    Storage(#[from] std::io::Error),
    #[error("there is no offline copy of this account yet; connect to sign in")]
    NoOfflineCopy,
    #[error("the server could not confirm whether the item was saved; check after syncing")]
    SaveUncertain,
    #[error("this item is read-only for your account")]
    ReadOnly,
}

impl From<ApiError> for SessionError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::TwoFactorRequired(p) => SessionError::TwoFactorRequired(p),
            ApiError::Unauthorized => SessionError::SignInRequired,
            other => SessionError::Api(other),
        }
    }
}

/// Avatar colours handed out to accounts in turn.
const TINTS: [[u8; 3]; 6] = [
    [0x2f, 0x6f, 0xdb],
    [0x1d, 0x8f, 0x58],
    [0xb0, 0x47, 0x9b],
    [0xc9, 0x6a, 0x12],
    [0x13, 0x86, 0x93],
    [0x8a, 0x5c, 0xd6],
];

struct Online {
    access: Zeroizing<String>,
    expires: Instant,
}

pub struct Session {
    pub profile: Profile,
    client: Client,
    keys: Keys,
    pub vault: Vault,
    sync: Value,
    online: Option<Online>,
    refresh: Option<Zeroizing<String>>,
    remember: Option<Zeroizing<String>>,
    pub synced_at: Option<u64>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_key(user: &crypto::SymmetricKey, profile: &Profile) -> Zeroizing<[u8; 32]> {
    user.derive_local(
        b"hushjar-cache",
        &format!("hushjar/cache/v1/{}", profile.id),
    )
}

fn cache_aad(profile: &Profile) -> Vec<u8> {
    format!("hushjar-cache-v1|{}|{}", profile.id, profile.user_id).into_bytes()
}

impl Session {
    /// Asks the server to email a two-step login code for this sign-in.
    pub fn send_email_code(
        server: &Server,
        email: &str,
        password: &str,
        device: &Device,
    ) -> Result<(), SessionError> {
        let client = Client::new(server.clone());
        let kdf = client.prelogin(email)?;
        let master = crypto::master_key(password, email, kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        client.send_email_code(email, &hash, device)?;
        Ok(())
    }

    /// Signs in online. With `existing`, reconnects that saved account and
    /// keeps its local identity; otherwise creates a new profile.
    pub fn sign_in(
        store: &Store,
        server: Server,
        email: &str,
        password: &str,
        second: Option<SecondFactor<'_>>,
        existing: Option<&Profile>,
    ) -> Result<Session, SessionError> {
        let email = crypto::normalize_email(email);
        let client = Client::new(server.clone());
        let kdf = client.prelogin(&email)?;
        let master = crypto::master_key(password, &email, kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        let device = existing.map(|p| p.device.clone()).unwrap_or_default();
        let login = client.login(&email, &hash, &device, second)?;
        let user = crypto::stretch(&master)
            .unwrap_key(&login.key)
            .map_err(|_| SessionError::WrongPassword)?;
        let private = login
            .private_key
            .as_deref()
            .map(|k| PrivateKey::unwrap(&user, k))
            .transpose()?;

        let issued = Instant::now();
        let sync = client.sync(&login.access_token)?;
        let user_id = field(&sync, "profile")
            .and_then(|p| field_str(p, "id"))
            .unwrap_or_default()
            .to_string();
        if let Some(previous) = existing
            && previous.user_id != user_id
        {
            return Err(SessionError::Api(ApiError::Rejected(
                "this sign-in belongs to a different account".into(),
            )));
        }
        let profile = Profile {
            id: existing
                .map(|p| p.id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            email,
            server,
            kdf,
            user_id,
            encrypted_user_key: login.key.clone(),
            encrypted_private_key: login.private_key.clone(),
            device,
            tint: existing
                .map(|p| p.tint)
                .unwrap_or(TINTS[store.profiles().len() % TINTS.len()]),
        };
        let keys = Keys::new(user, private.as_ref(), &sync);
        let vault = vault::decrypt_sync(&sync, &keys);
        let session = Session {
            profile,
            client,
            keys,
            vault,
            sync,
            online: Some(Online {
                access: login.access_token,
                expires: issued + Duration::from_secs(login.expires_in),
            }),
            refresh: Some(login.refresh_token),
            remember: login.two_factor_token,
            synced_at: Some(unix_now()),
        };
        store.save_profile(&session.profile)?;
        session.persist(store)?;
        Ok(session)
    }

    /// Unlocks a saved account from its offline copy. The master password is
    /// checked by opening the stored user key; nothing is sent anywhere.
    pub fn unlock(
        store: &Store,
        profile: &Profile,
        password: &str,
    ) -> Result<Session, SessionError> {
        let master = crypto::master_key(password, &profile.email, profile.kdf)?;
        let user = crypto::stretch(&master)
            .unwrap_key(&profile.encrypted_user_key)
            .map_err(|_| SessionError::WrongPassword)?;
        let sealed = store
            .read_cache(&profile.id)
            .map_err(|_| SessionError::NoOfflineCopy)?;
        let plain = crypto::open(&cache_key(&user, profile), &cache_aad(profile), &sealed)?;
        let cache: Value = serde_json::from_slice(&plain).map_err(|_| CryptoError::Malformed)?;
        let sync = cache.get("sync").cloned().unwrap_or(Value::Null);
        let private = profile
            .encrypted_private_key
            .as_deref()
            .map(|k| PrivateKey::unwrap(&user, k))
            .transpose()?;
        let keys = Keys::new(user, private.as_ref(), &sync);
        let vault = vault::decrypt_sync(&sync, &keys);
        let secret = |name: &str| {
            cache
                .get(name)
                .and_then(Value::as_str)
                .map(|s| Zeroizing::new(s.to_string()))
        };
        Ok(Session {
            profile: profile.clone(),
            client: Client::new(profile.server.clone()),
            keys,
            vault,
            refresh: secret("refresh_token"),
            remember: secret("remember_token"),
            synced_at: cache.get("synced_at").and_then(Value::as_u64),
            sync,
            online: None,
        })
    }

    /// Signs in again for an unlocked account whose tokens have expired.
    pub fn reconnect(
        &mut self,
        store: &Store,
        password: &str,
        second: Option<SecondFactor<'_>>,
    ) -> Result<(), SessionError> {
        let master = crypto::master_key(password, &self.profile.email, self.profile.kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        let remembered;
        let second = match (second, &self.remember) {
            (Some(s), _) => Some(s),
            (None, Some(token)) => {
                remembered = token.clone();
                Some(SecondFactor {
                    provider: TwoFactorProvider::Other(5),
                    token: &remembered,
                    remember: false,
                })
            }
            (None, None) => None,
        };
        let login =
            match self
                .client
                .login(&self.profile.email, &hash, &self.profile.device, second)
            {
                Err(ApiError::TwoFactorRequired(p)) => {
                    self.remember = None;
                    return Err(SessionError::TwoFactorRequired(p));
                }
                other => other?,
            };
        self.online = Some(Online {
            access: login.access_token,
            expires: Instant::now() + Duration::from_secs(login.expires_in),
        });
        self.refresh = Some(login.refresh_token);
        if login.two_factor_token.is_some() {
            self.remember = login.two_factor_token;
        }
        self.persist(store)
    }

    pub fn is_online(&self) -> bool {
        self.online
            .as_ref()
            .is_some_and(|o| o.expires > Instant::now())
    }

    /// A valid access token, refreshing it when needed.
    fn token(&mut self) -> Result<Zeroizing<String>, SessionError> {
        if let Some(online) = &self.online
            && online.expires > Instant::now() + Duration::from_secs(30)
        {
            return Ok(online.access.clone());
        }
        let refresh = self.refresh.clone().ok_or(SessionError::SignInRequired)?;
        match self.client.refresh(&refresh) {
            Ok(tokens) => {
                let access = tokens.access_token.clone();
                self.online = Some(Online {
                    access: tokens.access_token,
                    expires: Instant::now() + Duration::from_secs(tokens.expires_in),
                });
                self.refresh = Some(tokens.refresh_token);
                Ok(access)
            }
            Err(ApiError::Unauthorized) => {
                self.refresh = None;
                self.online = None;
                Err(SessionError::SignInRequired)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Runs an authenticated request, retrying once with a fresh token if the
    /// access token was rejected. Never used for requests that create items.
    fn with_token<T>(
        &mut self,
        mut call: impl FnMut(&Client, &str) -> Result<T, ApiError>,
    ) -> Result<T, SessionError> {
        let token = self.token()?;
        match call(&self.client, &token) {
            Err(ApiError::Unauthorized) => {
                self.online = None;
                let token = self.token()?;
                Ok(call(&self.client, &token)?)
            }
            other => Ok(other?),
        }
    }

    pub fn sync(&mut self, store: &Store) -> Result<(), SessionError> {
        let sync = self.with_token(|c, t| c.sync(t))?;
        let private = self
            .profile
            .encrypted_private_key
            .as_deref()
            .map(|k| PrivateKey::unwrap(&self.keys.user, k))
            .transpose()?;
        self.keys = Keys::new(self.keys.user.clone(), private.as_ref(), &sync);
        self.vault = vault::decrypt_sync(&sync, &self.keys);
        self.sync = sync;
        self.synced_at = Some(unix_now());
        self.persist(store)
    }

    /// Writes the encrypted offline copy.
    fn persist(&self, store: &Store) -> Result<(), SessionError> {
        let cache = json!({
            "sync": self.sync,
            "refresh_token": self.refresh.as_deref().map(String::as_str),
            "remember_token": self.remember.as_deref().map(String::as_str),
            "synced_at": self.synced_at,
        });
        let plain = Zeroizing::new(serde_json::to_vec(&cache).map_err(std::io::Error::other)?);
        let sealed = crypto::seal(
            &cache_key(&self.keys.user, &self.profile),
            &cache_aad(&self.profile),
            &plain,
        );
        store.write_cache(&self.profile.id, &sealed)?;
        Ok(())
    }

    /// Replaces or adds one item in the stored sync data and the vault.
    fn apply_cipher(&mut self, store: &Store, raw: Value) -> Result<Item, SessionError> {
        let id = field_str(&raw, "id").unwrap_or_default().to_string();
        if let Some(list) = self.sync.get_mut("ciphers").and_then(Value::as_array_mut) {
            match list
                .iter_mut()
                .find(|c| field_str(c, "id") == Some(id.as_str()))
            {
                Some(slot) => *slot = raw.clone(),
                None => list.push(raw.clone()),
            }
        }
        let item = vault::decrypt_item(&raw, &self.keys);
        match self.vault.items.iter_mut().find(|i| i.id == id) {
            Some(slot) => *slot = item.clone(),
            None => self.vault.items.push(item.clone()),
        }
        self.persist(store)?;
        Ok(item)
    }

    /// Saves an edited or new item and returns the server's copy.
    ///
    /// A new item is posted once. If the reply is lost, the result is
    /// [`SessionError::SaveUncertain`] and nothing is retried: sync first to
    /// see whether it arrived, so no duplicate is created.
    pub fn save(&mut self, store: &Store, item: &Item) -> Result<Item, SessionError> {
        if !item.editable {
            return Err(SessionError::ReadOnly);
        }
        let body = vault::encrypt_item(item, &self.keys)?;
        let reply = if item.is_new() {
            let token = self.token()?;
            let result = match &item.organization_id {
                Some(_) => self
                    .client
                    .create_org_cipher(&token, &body, &item.collection_ids),
                None => self.client.create_cipher(&token, &body),
            };
            match result {
                Ok(reply) => reply,
                Err(ApiError::Network(_)) | Err(ApiError::Decode) => {
                    return Err(SessionError::SaveUncertain);
                }
                Err(other) => return Err(other.into()),
            }
        } else {
            let id = item.id.clone();
            self.with_token(|c, t| c.update_cipher(t, &id, &body))?
        };
        self.apply_cipher(store, reply)
    }

    pub fn trash(&mut self, store: &Store, id: &str) -> Result<(), SessionError> {
        self.with_token(|c, t| c.trash_cipher(t, id))?;
        self.sync(store)
    }

    pub fn restore(&mut self, store: &Store, id: &str) -> Result<(), SessionError> {
        self.with_token(|c, t| c.restore_cipher(t, id))?;
        self.sync(store)
    }

    pub fn delete(&mut self, store: &Store, id: &str) -> Result<(), SessionError> {
        self.with_token(|c, t| c.delete_cipher(t, id))?;
        self.sync(store)
    }

    pub fn create_folder(&mut self, store: &Store, name: &str) -> Result<String, SessionError> {
        let encrypted = self.keys.user.encrypt_str(name);
        let reply = self.with_token(|c, t| c.create_folder(t, &encrypted))?;
        let id = field_str(&reply, "id").unwrap_or_default().to_string();
        self.sync(store)?;
        Ok(id)
    }
}
