//! Tests against a real Vaultwarden server. They run only when
//! HUSHJAR_INTEROP is set to the server's address; see tests/interop/README.md.
//! Every account is invented and lives only in the test server's memory.

use hushjar_core::api::{Client, Device, Server};
use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
use serde_json::{Value, json};

fn server() -> Option<String> {
    let url = std::env::var("HUSHJAR_INTEROP").ok();
    if url.is_none() {
        eprintln!("skipped: set HUSHJAR_INTEROP to a Vaultwarden test server");
    }
    url
}

fn unique_email(tag: &str) -> String {
    format!("{tag}-{}@example.invalid", uuid::Uuid::new_v4().simple())
}

/// Registers an invented account and returns its user key.
fn register(base: &str, email: &str, password: &str, kdf: Kdf) -> SymmetricKey {
    let master = crypto::master_key(password, email, kdf).unwrap();
    let hash = crypto::password_hash(&master, password, HashPurpose::Server);
    let user_key = SymmetricKey::generate();
    let wrapped = crypto::stretch(&master).wrap_key(&user_key);
    let mut body = json!({
        "email": email,
        "name": "Hushjar interop test",
        "masterPasswordHash": hash.as_str(),
        "key": wrapped,
    });
    match kdf {
        Kdf::Pbkdf2 { iterations } => {
            body["kdf"] = json!(0);
            body["kdfIterations"] = json!(iterations);
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            body["kdf"] = json!(1);
            body["kdfIterations"] = json!(iterations);
            body["kdfMemory"] = json!(memory_mib);
            body["kdfParallelism"] = json!(parallelism);
        }
    }
    let response = ureq::post(format!("{base}/identity/accounts/register"))
        .send_json(&body)
        .unwrap();
    assert_eq!(response.status().as_u16(), 200, "registration failed");
    user_key
}

/// Prints a JSON value's structure with every leaf replaced by its type.
fn shape(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), shape(v))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().take(1).map(shape).collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        Value::Null => Value::Null,
    }
}

#[test]
#[ignore = "prints response shapes for development"]
fn print_shapes() {
    let Some(base) = server() else { return };
    let email = unique_email("shape");
    let kdf = Kdf::Pbkdf2 {
        iterations: 600_000,
    };
    let user_key = register(&base, &email, "correct horse battery staple", kdf);
    let client = Client::new(Server::parse(&base).unwrap());
    let master = crypto::master_key(
        "correct horse battery staple",
        &email,
        client.prelogin(&email).unwrap(),
    )
    .unwrap();
    let hash = crypto::password_hash(&master, "correct horse battery staple", HashPurpose::Server);
    let login = client.login(&email, &hash, &Device::new(), None).unwrap();
    let cipher = json!({
        "type": 1,
        "name": user_key.encrypt_str("Example"),
        "notes": null,
        "favorite": false,
        "login": { "username": user_key.encrypt_str("user"), "password": user_key.encrypt_str("pw"), "uris": [{ "uri": user_key.encrypt_str("https://example.org"), "match": null }] },
        "fields": [{ "type": 0, "name": user_key.encrypt_str("f"), "value": user_key.encrypt_str("v") }],
    });
    let created = client.create_cipher(&login.access_token, &cipher).unwrap();
    println!(
        "CREATED {}",
        serde_json::to_string_pretty(&shape(&created)).unwrap()
    );
    let synced = client.sync(&login.access_token).unwrap();
    println!(
        "SYNC {}",
        serde_json::to_string_pretty(&shape(&synced)).unwrap()
    );
}

mod end_to_end {
    use super::*;
    use hushjar_core::api::{SecondFactor, TwoFactorProvider};
    use hushjar_core::session::{Session, SessionError};
    use hushjar_core::store::Store;
    use hushjar_core::vault::{CustomField, FieldType, Item, ItemKind, Uri};

    const PASSWORD: &str = "invented interop password";

    fn temp_store() -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("hushjar-interop-{}", uuid::Uuid::new_v4().simple()));
        (Store::open(dir.clone()).unwrap(), dir)
    }

    fn sign_in_new(base: &str, kdf: Kdf) -> (Store, std::path::PathBuf, Session) {
        let email = unique_email("e2e");
        register(base, &email, PASSWORD, kdf);
        let (store, dir) = temp_store();
        let session = Session::sign_in(
            &store,
            Server::parse(base).unwrap(),
            &email,
            PASSWORD,
            None,
            None,
        )
        .unwrap();
        (store, dir, session)
    }

    fn sample_items() -> Vec<Item> {
        let mut login = Item::new(ItemKind::Login, None, None);
        login.name = "Example login".into();
        login.login.username = "sam".into();
        login.login.password = "first password".into();
        login.login.totp = "JBSWY3DPEHPK3PXP".into();
        login.login.uris = vec![Uri {
            uri: "https://example.org".into(),
            match_type: None,
        }];
        login.fields = vec![CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            kind: FieldType::Hidden,
            linked_id: None,
        }];
        let mut note = Item::new(ItemKind::SecureNote, None, None);
        note.name = "A note".into();
        note.notes = "line one\nline two".into();
        let mut card = Item::new(ItemKind::Card, None, None);
        card.name = "Test card".into();
        card.card.number = "4111111111111111".into();
        card.card.brand = "Visa".into();
        let mut identity = Item::new(ItemKind::Identity, None, None);
        identity.name = "Me".into();
        identity.identity.insert("firstName".into(), "Sam".into());
        identity
            .identity
            .insert("passportNumber".into(), "X1".into());
        let mut ssh = Item::new(ItemKind::SshKey, None, None);
        ssh.name = "Key".into();
        ssh.ssh_key.private_key = "(not a real key)".into();
        ssh.ssh_key.public_key = "ssh-ed25519 AAAA test".into();
        ssh.ssh_key.fingerprint = "SHA256:test".into();
        vec![login, note, card, identity, ssh]
    }

    #[test]
    fn create_edit_sync_and_unlock_offline() {
        let Some(base) = server() else { return };
        for kdf in [
            Kdf::Pbkdf2 {
                iterations: 600_000,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4,
            },
        ] {
            let (store, dir, mut session) = sign_in_new(&base, kdf);
            assert!(session.vault.items.is_empty());
            for item in sample_items() {
                let saved = session.save(&store, &item).unwrap();
                assert!(!saved.id.is_empty());
                assert_eq!(saved.name, item.name);
            }
            session.sync(&store).unwrap();
            assert_eq!(session.vault.items.len(), 5);
            let ssh = session
                .vault
                .items
                .iter()
                .find(|i| i.kind == ItemKind::SshKey)
                .expect("SSH keys are visible");
            assert_eq!(ssh.ssh_key.public_key, "ssh-ed25519 AAAA test");

            // Edit the login: the old password goes to the history.
            let mut login = session
                .vault
                .items
                .iter()
                .find(|i| i.kind == ItemKind::Login)
                .unwrap()
                .clone();
            let before = login.clone();
            login.login.password = "second password".into();
            login.note_password_change(&before);
            session.save(&store, &login).unwrap();
            session.sync(&store).unwrap();
            let login = session.vault.item(&login.id).unwrap();
            assert_eq!(login.login.password, "second password");
            assert_eq!(login.password_history[0].password, "first password");
            assert_eq!(login.fields[0].value, "1234");

            // Trash, restore and delete.
            let note = session
                .vault
                .items
                .iter()
                .find(|i| i.kind == ItemKind::SecureNote)
                .unwrap()
                .id
                .clone();
            session.trash(&store, &note).unwrap();
            assert!(session.vault.item(&note).unwrap().deleted);
            session.restore(&store, &note).unwrap();
            assert!(!session.vault.item(&note).unwrap().deleted);
            session.delete(&store, &note).unwrap();
            assert!(session.vault.item(&note).is_none());

            // A new run: unlock from disk only, then reconnect with the refresh token.
            let profile = store.profiles().pop().unwrap();
            drop(session);
            let store = Store::open(dir.clone()).unwrap();
            assert!(matches!(
                Session::unlock(&store, &profile, "wrong"),
                Err(SessionError::WrongPassword)
            ));
            let mut session = Session::unlock(&store, &profile, PASSWORD).unwrap();
            assert_eq!(session.vault.items.len(), 4);
            assert!(!session.is_online());
            session.sync(&store).unwrap();
            assert!(session.is_online());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn wrong_password_is_rejected_online() {
        let Some(base) = server() else { return };
        let email = unique_email("wrong");
        register(
            &base,
            &email,
            PASSWORD,
            Kdf::Pbkdf2 {
                iterations: 600_000,
            },
        );
        let (store, dir) = temp_store();
        let result = Session::sign_in(
            &store,
            Server::parse(&base).unwrap(),
            &email,
            "not it",
            None,
            None,
        );
        assert!(
            matches!(result, Err(SessionError::Api(_))),
            "{:?}",
            result.err()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authenticator_two_step_login() {
        let Some(base) = server() else { return };
        let (store, dir, session) = sign_in_new(
            &base,
            Kdf::Pbkdf2 {
                iterations: 600_000,
            },
        );
        let email = session.profile.email.clone();
        // Turn on authenticator two-step login for the invented account.
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        let master = crypto::master_key(PASSWORD, &email, session.profile.kdf).unwrap();
        let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
        let client = Client::new(Server::parse(&base).unwrap());
        let login = client.login(&email, &hash, &Device::new(), None).unwrap();
        let code = hushjar_core::totp::generate(secret, now()).unwrap().value;
        let response = ureq::put(format!("{base}/api/two-factor/authenticator"))
            .header(
                "Authorization",
                format!("Bearer {}", login.access_token.as_str()),
            )
            .send_json(json!({ "key": secret, "token": code, "masterPasswordHash": hash.as_str() }))
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            200,
            "enabling the authenticator failed"
        );

        let server = Server::parse(&base).unwrap();
        let providers = match Session::sign_in(&store, server.clone(), &email, PASSWORD, None, None)
        {
            Err(SessionError::TwoFactorRequired(p)) => p,
            other => panic!("expected two-step login, got {:?}", other.err()),
        };
        assert!(providers.contains(&TwoFactorProvider::Authenticator));
        // Codes may not be reused within a period; wait for the next one.
        std::thread::sleep(std::time::Duration::from_secs(31 - now() % 30));
        let code = hushjar_core::totp::generate(secret, now()).unwrap().value;
        let second = SecondFactor {
            provider: TwoFactorProvider::Authenticator,
            token: &code,
            remember: true,
        };
        let session =
            Session::sign_in(&store, server, &email, PASSWORD, Some(second), None).unwrap();
        assert_eq!(session.profile.email, email);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
