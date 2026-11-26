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

/// Creates an invented demo account with sample items and signs it in to the
/// data folder in HUSHJAR_SEED_DIR, for trying the app and taking screenshots.
#[test]
#[ignore = "creates a demo account; run on request"]
fn seed_demo_account() {
    use hushjar_core::session::Session;
    use hushjar_core::store::Store;
    use hushjar_core::vault::{CustomField, FieldType, Item, ItemKind, Uri};
    let (Some(base), Some(dir)) = (server(), std::env::var_os("HUSHJAR_SEED_DIR")) else {
        eprintln!("skipped: set HUSHJAR_INTEROP and HUSHJAR_SEED_DIR");
        return;
    };
    let password = "hushjar demo password";
    let email = unique_email("demo");
    register(
        &base,
        &email,
        password,
        Kdf::Pbkdf2 {
            iterations: 600_000,
        },
    );
    let store = Store::open(dir.into()).unwrap();
    let mut session = Session::sign_in(
        &store,
        Server::parse(&base).unwrap(),
        &email,
        password,
        None,
        None,
    )
    .unwrap();
    let mut folder = |name: &str| session.create_folder(&store, name).unwrap();
    let work = folder("Work");
    let code = folder("Work/Code");
    let home = folder("Home");
    let money = folder("Finance");
    let login = |name: &str, folder: &str, user: &str, pass: &str, totp: &str, site: &str| {
        let mut item = Item::new(ItemKind::Login, None, Some(folder.to_string()));
        item.name = name.into();
        item.login.username = user.into();
        item.login.password = pass.into();
        item.login.totp = totp.into();
        item.login.uris = vec![Uri {
            uri: site.into(),
            match_type: None,
        }];
        item
    };
    let mut github = login(
        "GitHub",
        &code,
        "sam-dev",
        "correct-horse-battery-staple-42",
        "JBSWY3DPEHPK3PXP",
        "https://github.com",
    );
    github.favorite = true;
    github.notes = "Recovery codes are printed and kept in the fireproof box.".into();
    github.fields = vec![CustomField {
        name: "Recovery email".into(),
        value: "sam+github@example.org".into(),
        kind: FieldType::Text,
        linked_id: None,
    }];
    let mut items = vec![
        github,
        login(
            "GitLab",
            &code,
            "sam",
            "w1nter-Is-c0ming!",
            "",
            "https://gitlab.com",
        ),
        login(
            "Jira",
            &work,
            "sam@work.example",
            "tickets-tickets",
            "",
            "https://example.atlassian.net",
        ),
        login(
            "Router admin",
            &home,
            "admin",
            "blinking-lights-77",
            "",
            "http://192.168.1.1",
        ),
        login(
            "Bank",
            &money,
            "10293847",
            "save-more-spend-less",
            "GEZDGNBVGY3TQOJQ",
            "https://bank.example.com",
        ),
    ];
    let mut card = Item::new(ItemKind::Card, None, Some(money.clone()));
    card.name = "Everyday Visa".into();
    card.favorite = true;
    card.card.cardholder_name = "Sam Example".into();
    card.card.brand = "Visa".into();
    card.card.number = "4111 1111 1111 1111".into();
    card.card.exp_month = "8".into();
    card.card.exp_year = "2029".into();
    card.card.code = "123".into();
    items.push(card);
    let mut note = Item::new(ItemKind::SecureNote, None, Some(home));
    note.name = "Home Wi-Fi".into();
    note.notes = "Network: Honeycomb\nGuest network: Honeycomb-Guest".into();
    items.push(note);
    let mut id = Item::new(ItemKind::Identity, None, None);
    id.name = "Passport".into();
    for (k, v) in [
        ("firstName", "Sam"),
        ("lastName", "Example"),
        ("email", "sam@example.org"),
        ("passportNumber", "X12345678"),
    ] {
        id.identity.insert(k.into(), v.into());
    }
    items.push(id);
    let mut ssh = Item::new(ItemKind::SshKey, None, Some(code));
    ssh.name = "Deploy key".into();
    // A real, throwaway key when ssh-keygen is available, so the SSH agent
    // can be tried; otherwise a placeholder the agent skips.
    let keydir =
        std::env::temp_dir().join(format!("hushjar-seed-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&keydir).unwrap();
    let keyfile = keydir.join("demo");
    let made = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "hushjar demo", "-f"])
        .arg(&keyfile)
        .status()
        .is_ok_and(|s| s.success());
    if made {
        ssh.ssh_key.private_key = std::fs::read_to_string(&keyfile).unwrap();
        ssh.ssh_key.public_key = std::fs::read_to_string(keyfile.with_extension("pub"))
            .unwrap()
            .trim()
            .to_string();
        let out = std::process::Command::new("ssh-keygen")
            .arg("-lf")
            .arg(keyfile.with_extension("pub"))
            .output()
            .unwrap();
        let line = String::from_utf8_lossy(&out.stdout).to_string();
        ssh.ssh_key.fingerprint = line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string();
    } else {
        ssh.ssh_key.public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealKey demo".into();
        ssh.ssh_key.private_key = "(example private key, not a real one)".into();
    }
    std::fs::remove_dir_all(&keydir).unwrap();
    items.push(ssh);
    for item in &items {
        session.save(&store, item).unwrap();
    }
    session.sync(&store).unwrap();
    println!("DEMO {email} / {password}");
}

mod live_updates {
    use super::*;
    use hushjar_core::notifications::{Listener, Notification};
    use hushjar_core::session::Session;
    use hushjar_core::store::Store;
    use hushjar_core::vault::{Item, ItemKind};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const PASSWORD: &str = "invented interop password";

    fn temp_store() -> (Store, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("hushjar-interop-{}", uuid::Uuid::new_v4().simple()));
        (Store::open(dir.clone()).unwrap(), dir)
    }

    fn note(name: &str) -> Item {
        let mut item = Item::new(ItemKind::SecureNote, None, None);
        item.name = name.into();
        item.notes = "invented".into();
        item
    }

    #[test]
    fn changes_from_another_device_arrive() {
        let Some(base) = server() else { return };
        let email = unique_email("live");
        register(
            &base,
            &email,
            PASSWORD,
            Kdf::Pbkdf2 {
                iterations: 600_000,
            },
        );
        let server = Server::parse(&base).unwrap();
        // Device 1: this installation, listening.
        let (store, dir) = temp_store();
        let mut session =
            Session::sign_in(&store, server.clone(), &email, PASSWORD, None, None).unwrap();
        let token = session.access_token().unwrap();
        let (tx, rx) = mpsc::channel();
        let listener = Listener::start(
            &server,
            &session.profile.device.identifier,
            move || Some(token.clone()),
            move |event| {
                let _ = tx.send(event);
            },
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !listener.is_connected() {
            assert!(
                Instant::now() < deadline,
                "no hub connection: {:?}",
                listener.problem()
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // Our own change carries our device identifier and is ignored.
        session.save(&store, &note("Mine")).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).ok(),
            None,
            "own change ignored"
        );

        // Device 2: a second sign-in of the same account changes an item.
        let (store2, dir2) = temp_store();
        let mut other = Session::sign_in(&store2, server, &email, PASSWORD, None, None).unwrap();
        assert_ne!(
            other.profile.device.identifier,
            session.profile.device.identifier
        );
        let started = Instant::now();
        other.save(&store2, &note("Theirs")).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).ok(),
            Some(Notification::VaultChanged)
        );
        eprintln!("notification after {:?}", started.elapsed());
        // Exactly one message for one change.
        assert_eq!(rx.recv_timeout(Duration::from_millis(500)).ok(), None);

        let started = Instant::now();
        listener.stop();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stop took {:?}",
            started.elapsed()
        );
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(dir2).unwrap();
    }
}

mod organisation_policies {
    use super::*;
    use hushjar_core::policy::{GeneratorType, Policies, kind};
    use hushjar_core::session::Session;
    use hushjar_core::store::Store;

    const PASSWORD: &str = "invented interop password";

    fn account(base: &str, tag: &str) -> (Session, Store, std::path::PathBuf, SymmetricKey) {
        let email = unique_email(tag);
        let user_key = register(
            base,
            &email,
            PASSWORD,
            Kdf::Pbkdf2 {
                iterations: 600_000,
            },
        );
        let dir =
            std::env::temp_dir().join(format!("hushjar-interop-{}", uuid::Uuid::new_v4().simple()));
        let store = Store::open(dir.clone()).unwrap();
        let session = Session::sign_in(
            &store,
            Server::parse(base).unwrap(),
            &email,
            PASSWORD,
            None,
            None,
        )
        .unwrap();
        (session, store, dir, user_key)
    }

    /// Sends an authenticated API request as `session`'s user.
    fn call(base: &str, session: &mut Session, method: &str, path: &str, body: Value) -> Value {
        let token = session.access_token().unwrap();
        let url = format!("{base}/api{path}");
        let bearer = format!("Bearer {}", token.as_str());
        let response = match method {
            "GET" => ureq::get(&url).header("Authorization", &bearer).call(),
            "POST" => ureq::post(&url)
                .header("Authorization", &bearer)
                .send_json(&body),
            "PUT" => ureq::put(&url)
                .header("Authorization", &bearer)
                .send_json(&body),
            _ => unreachable!(),
        };
        let mut response = response.unwrap_or_else(|e| panic!("{method} {path}: {e}"));
        let text = response.body_mut().read_to_string().unwrap();
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    #[test]
    fn policies_reach_members_and_spare_owners() {
        let Some(base) = server() else { return };
        let (mut owner, owner_store, owner_dir, owner_key) = account(&base, "org-owner");
        let (mut member, member_store, member_dir, _) = account(&base, "org-member");

        // The keys are placeholders: Vaultwarden stores them unchecked and
        // policies do not depend on them.
        let body = json!({
            "name": "Invented policy org",
            "billingEmail": owner.profile.email,
            "collectionName": owner_key.encrypt_str("Default"),
            "key": "4.cGxhY2Vob2xkZXI=",
            "planType": 0,
        });
        let org = call(&base, &mut owner, "POST", "/organizations", body);
        let org_id = org["id"].as_str().expect("organisation id").to_string();
        call(
            &base,
            &mut owner,
            "POST",
            &format!("/organizations/{org_id}/users/invite"),
            json!({
                "emails": [member.profile.email],
                "groups": [],
                "type": 2,
                "collections": [],
                "permissions": {},
            }),
        );
        let users = call(
            &base,
            &mut owner,
            "GET",
            &format!("/organizations/{org_id}/users"),
            Value::Null,
        );
        let membership = users["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["email"] == json!(member.profile.email))
            .expect("member listed");
        // Without mail, Vaultwarden accepts invitations of existing users.
        assert_eq!(membership["status"], json!(1));
        let membership_id = membership["id"].as_str().unwrap().to_string();
        call(
            &base,
            &mut owner,
            "POST",
            &format!("/organizations/{org_id}/users/{membership_id}/confirm"),
            json!({ "key": "4.cGxhY2Vob2xkZXI=" }),
        );

        let mut set = |kind: u8, data: Value| {
            call(
                &base,
                &mut owner,
                "PUT",
                &format!("/organizations/{org_id}/policies/{kind}"),
                json!({ "policy": { "enabled": true, "data": data } }),
            );
        };
        set(
            kind::PASSWORD_GENERATOR,
            json!({
                "overridePasswordType": "passphrase", "minLength": 18, "useUpper": true,
                "useLower": true, "useNumbers": true, "useSpecial": false, "minNumbers": 2,
                "minSpecial": 0, "minNumberWords": 5, "capitalize": true, "includeNumber": true,
            }),
        );
        set(kind::ORGANIZATION_DATA_OWNERSHIP, Value::Null);
        set(kind::DISABLE_SEND, Value::Null);
        set(kind::SEND_OPTIONS, json!({ "disableHideEmail": true }));
        // Vaultwarden 1.37.3 rejects the maximum vault timeout (9) and
        // personal export (10) policies as not supported; unit tests cover them.
        set(kind::REMOVE_UNLOCK_WITH_PIN, Value::Null);
        set(kind::RESTRICTED_ITEM_TYPES, json!([3]));

        // The membership fields policies depend on, as the server sends them.
        let raw = call(&base, &mut member, "GET", "/sync", Value::Null);
        let membership = &raw["profile"]["organizations"][0];
        eprintln!(
            "membership {} policy {}",
            serde_json::to_string(&shape(membership)).unwrap(),
            serde_json::to_string(&raw["policies"][0]).unwrap()
        );
        assert_eq!(membership["type"], json!(2));
        assert_eq!(membership["status"], json!(2));
        assert_eq!(membership["enabled"], json!(true));
        assert_eq!(membership["usePolicies"], json!(true));
        member.sync(&member_store).unwrap();
        let policies: Policies = member.policies();
        let generator = policies.generator.clone().expect("generator policy");
        assert_eq!(generator.forced_type, Some(GeneratorType::Passphrase));
        assert_eq!(generator.min_length, 18);
        assert_eq!(generator.min_words, 5);
        assert!(generator.use_upper && generator.capitalize && generator.include_number);
        assert!(policies.personal_ownership_disabled);
        assert!(policies.send_disabled);
        assert!(policies.send_hide_email_disabled);
        assert!(policies.pin_unlock_disabled);
        assert_eq!(policies.restricted_item_types.len(), 1);
        assert_eq!(policies.restricted_item_types[0].item_type, 3);
        assert!(policies.restricted_item_types[0].allowed_in.is_empty());
        assert_eq!(policies.enforced[&kind::DISABLE_SEND], vec![org_id.clone()]);

        // The owner gets the generator policy but is exempt from the rest.
        owner.sync(&owner_store).unwrap();
        let policies = owner.policies();
        assert_eq!(policies.generator.map(|g| g.min_length), Some(18));
        assert!(!policies.personal_ownership_disabled);
        assert!(!policies.send_disabled);
        assert!(!policies.send_hide_email_disabled);
        // These two exempt no one.
        assert!(policies.pin_unlock_disabled);
        assert_eq!(policies.restricted_item_types.len(), 1);

        std::fs::remove_dir_all(owner_dir).unwrap();
        std::fs::remove_dir_all(member_dir).unwrap();
    }
}
