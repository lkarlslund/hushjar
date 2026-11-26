//! Files on disk: one folder per account with a profile (no secrets beyond
//! the server-encrypted user key) and an encrypted cache holding the last
//! sync and the tokens needed to reconnect.
//!
//! On Unix the folders are 0700 and the files 0600. Files are replaced
//! atomically: written to a temporary file, synced, then renamed.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::api::{Device, Server};
use crate::crypto::Kdf;

/// What Hushjar remembers about an account between runs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    /// Local identifier, also the folder name.
    pub id: String,
    pub email: String,
    pub server: Server,
    pub kdf: Kdf,
    pub user_id: String,
    /// The user key encrypted with the stretched master key, as the server
    /// sends it. The master password opens it, which is how offline unlock
    /// checks the password.
    pub encrypted_user_key: String,
    pub encrypted_private_key: Option<String>,
    pub device: Device,
    /// Avatar colour as RGB.
    pub tint: [u8; 3],
}

pub struct Store {
    root: PathBuf,
}

/// The default data folder for this platform.
pub fn default_root() -> Option<PathBuf> {
    let env = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(target_os = "windows") {
        env("APPDATA").map(|p| p.join("Hushjar"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|p| p.join("Library/Application Support/Hushjar"))
    } else {
        env("XDG_DATA_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".local/share")))
            .map(|p| p.join("hushjar"))
    }
}

fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent()
        && let Ok(dir) = fs::File::open(dir)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

impl Store {
    pub fn open(root: PathBuf) -> io::Result<Self> {
        private_dir(&root)?;
        private_dir(&root.join("accounts"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn account_dir(&self, id: &str) -> io::Result<PathBuf> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad account id",
            ));
        }
        Ok(self.root.join("accounts").join(id))
    }

    /// Every saved account, in the order they were added.
    pub fn profiles(&self) -> Vec<Profile> {
        let mut found: Vec<(std::time::SystemTime, Profile)> = Vec::new();
        let Ok(entries) = fs::read_dir(self.root.join("accounts")) else {
            return vec![];
        };
        for entry in entries.flatten() {
            let path = entry.path().join("profile.json");
            if let Ok(text) = fs::read_to_string(&path)
                && let Ok(profile) = serde_json::from_str::<Profile>(&text)
            {
                let added =
                    fs::metadata(entry.path()).and_then(|m| m.created().or_else(|_| m.modified()));
                found.push((added.unwrap_or(std::time::UNIX_EPOCH), profile));
            }
        }
        found.sort_by_key(|(t, _)| *t);
        found.into_iter().map(|(_, p)| p).collect()
    }

    pub fn save_profile(&self, profile: &Profile) -> io::Result<()> {
        let dir = self.account_dir(&profile.id)?;
        private_dir(&dir)?;
        let json = serde_json::to_vec_pretty(profile).map_err(io::Error::other)?;
        write_atomic(&dir.join("profile.json"), &json)
    }

    pub fn write_cache(&self, id: &str, sealed: &[u8]) -> io::Result<()> {
        let dir = self.account_dir(id)?;
        private_dir(&dir)?;
        write_atomic(&dir.join("cache.bin"), sealed)
    }

    pub fn read_cache(&self, id: &str) -> io::Result<Vec<u8>> {
        fs::read(self.account_dir(id)?.join("cache.bin"))
    }

    /// Forgets an account on this device.
    pub fn remove(&self, id: &str) -> io::Result<()> {
        let dir = self.account_dir(id)?;
        if dir.exists() {
            fs::remove_dir_all(dir)
        } else {
            Ok(())
        }
    }

    /// Small app settings as JSON, outside any account.
    pub fn read_settings(&self) -> serde_json::Value {
        fs::read_to_string(self.root.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(serde_json::Value::Null)
    }

    pub fn write_settings(&self, value: &serde_json::Value) -> io::Result<()> {
        write_atomic(
            &self.root.join("settings.json"),
            &serde_json::to_vec_pretty(value).map_err(io::Error::other)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_round_trip_with_private_permissions() {
        let dir =
            std::env::temp_dir().join(format!("hushjar-store-{}", uuid::Uuid::new_v4().simple()));
        let store = Store::open(dir.clone()).unwrap();
        let profile = Profile {
            id: "abc-1".into(),
            email: "a@example.invalid".into(),
            server: Server::parse("bitwarden.eu").unwrap(),
            kdf: Kdf::Pbkdf2 {
                iterations: 600_000,
            },
            user_id: "u".into(),
            encrypted_user_key: "2.x|y|z".into(),
            encrypted_private_key: None,
            device: Device::new(),
            tint: [1, 2, 3],
        };
        store.save_profile(&profile).unwrap();
        store.write_cache("abc-1", b"sealed").unwrap();
        assert_eq!(store.profiles()[0].email, "a@example.invalid");
        assert_eq!(store.read_cache("abc-1").unwrap(), b"sealed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(dir.join("accounts/abc-1/cache.bin")), 0o600);
            assert_eq!(mode(dir.join("accounts/abc-1")), 0o700);
        }
        assert!(
            store
                .save_profile(&Profile {
                    id: "../evil".into(),
                    ..profile
                })
                .is_err()
        );
        store.remove("abc-1").unwrap();
        assert!(store.profiles().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
