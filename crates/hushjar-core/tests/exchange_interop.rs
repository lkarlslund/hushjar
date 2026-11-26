//! Import and export against a real Vaultwarden server. Runs only when
//! HUSHJAR_INTEROP is set; every account is invented.

use hushjar_core::api::Server;
use hushjar_core::crypto::{self, HashPurpose, Kdf};
use hushjar_core::exchange::ExchangeError;
use hushjar_core::exchange::export::Scope;
use hushjar_core::exchange::import;
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::Store;
use hushjar_core::vault::{CustomField, FieldType, Item, ItemKind, Uri};
use serde_json::{Value, json};

const PASSWORD: &str = "invented exchange password";
const FILE_PASSWORD: &str = "invented file password";

fn server() -> Option<String> {
    let url = std::env::var("HUSHJAR_INTEROP").ok();
    if url.is_none() {
        eprintln!("skipped: set HUSHJAR_INTEROP to a Vaultwarden test server");
    }
    url
}

fn register(base: &str, email: &str, kdf: Kdf) {
    let master = crypto::master_key(PASSWORD, email, kdf).unwrap();
    let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
    let user_key = crypto::SymmetricKey::generate();
    let mut body = json!({
        "email": email, "name": "Hushjar exchange test",
        "masterPasswordHash": hash.as_str(),
        "key": crypto::stretch(&master).wrap_key(&user_key),
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
    assert_eq!(response.status().as_u16(), 200);
}

fn account(base: &str, kdf: Kdf) -> (Store, Session) {
    let email = format!("exchange-{}@example.invalid", uuid::Uuid::new_v4().simple());
    register(base, &email, kdf);
    let dir = std::env::temp_dir().join(format!("hushjar-xchg-{}", uuid::Uuid::new_v4().simple()));
    let store = Store::open(dir).unwrap();
    let session = Session::sign_in(
        &store,
        Server::parse(base).unwrap(),
        &email,
        PASSWORD,
        None,
        None,
    )
    .unwrap();
    (store, session)
}

const ARGON: Kdf = Kdf::Argon2id {
    iterations: 3,
    memory_mib: 64,
    parallelism: 4,
};
const PBKDF2: Kdf = Kdf::Pbkdf2 {
    iterations: 600_000,
};

/// Seeds an account with every item type, custom field type, a passkey,
/// password history, a folder and URI match settings.
fn seed(session: &mut Session, store: &Store) {
    let folder = session.create_folder(store, "Work/Code").unwrap();
    let key = session.keys().user.clone();
    let enc = |s: &str| json!(key.encrypt_str(s));

    let mut login = Item::new(ItemKind::Login, None, Some(folder.clone()));
    login.name = "Passkey login".into();
    login.notes = "notes here".into();
    login.favorite = true;
    login.reprompt = true;
    login.login.username = "sam".into();
    login.login.password = "pw-2".into();
    login.login.totp = "JBSWY3DPEHPK3PXP".into();
    login.login.uris = vec![
        Uri {
            uri: "https://example.org".into(),
            match_type: Some(3),
        },
        Uri {
            uri: "https://example.com".into(),
            match_type: None,
        },
    ];
    for (name, value, kind, linked) in [
        ("Pin", "1234", FieldType::Text, None),
        ("Secret", "s3cret", FieldType::Hidden, None),
        ("Flag", "true", FieldType::Boolean, None),
        ("", "", FieldType::Linked, Some(100)),
    ] {
        login.fields.push(CustomField {
            name: name.into(),
            value: value.into(),
            kind,
            linked_id: linked,
        });
    }
    login.password_history = vec![hushjar_core::vault::PasswordEntry {
        password: "pw-1".into(),
        last_used: "2026-01-01T00:00:00Z".into(),
    }];
    // The passkey rides in the original JSON, which saving keeps.
    login.raw = json!({ "login": { "fido2Credentials": [{
        "credentialId": enc("cred-1"), "keyType": enc("public-key"), "keyAlgorithm": enc("ECDSA"),
        "keyCurve": enc("P-256"), "keyValue": enc("MIGHAgEAMBMG-not-a-real-key"),
        "rpId": enc("example.org"), "userHandle": enc("dXNlcg"), "userName": enc("sam"),
        "counter": enc("7"), "rpName": enc("Example"), "userDisplayName": enc("Sam Example"),
        "discoverable": enc("true"), "creationDate": "2026-02-03T04:05:06.789Z",
    }] } });

    let mut note = Item::new(ItemKind::SecureNote, None, None);
    note.name = "A note".into();
    note.notes = "line one\nline two".into();
    let mut card = Item::new(ItemKind::Card, None, None);
    card.name = "Card".into();
    card.card.cardholder_name = "Sam".into();
    card.card.number = "4111111111111111".into();
    card.card.brand = "Visa".into();
    card.card.exp_month = "8".into();
    card.card.exp_year = "2030".into();
    card.card.code = "123".into();
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
    for item in [&login, &note, &card, &identity, &ssh] {
        session.save(store, item).unwrap();
    }
    session.sync(store).unwrap();
    assert_eq!(session.vault.items.len(), 5);
}

/// An export document without the parts that legitimately differ between
/// accounts: ids, dates and the folder ids (replaced by folder names).
fn comparable(session: &Session) -> Value {
    let text = session.export_json(Scope::Personal).unwrap();
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    let folders: Vec<(String, String)> = doc["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["id"].as_str().unwrap().into(),
                f["name"].as_str().unwrap().into(),
            )
        })
        .collect();
    let mut items = doc["items"].as_array().unwrap().clone();
    for item in &mut items {
        let folder = item["folderId"].as_str().and_then(|id| {
            folders
                .iter()
                .find(|(i, _)| i == id)
                .map(|(_, n)| n.clone())
        });
        let object = item.as_object_mut().unwrap();
        for name in ["id", "creationDate", "revisionDate", "folderId"] {
            object.remove(name);
        }
        object.insert("folder".into(), json!(folder));
    }
    items.sort_by_key(|i| i["name"].as_str().unwrap().to_string());
    doc["folders"] = json!(folders.iter().map(|(_, n)| n).collect::<Vec<_>>());
    doc["items"] = json!(items);
    doc
}

fn import_text(
    session: &mut Session,
    store: &Store,
    text: &str,
    password: Option<&str>,
) -> Result<hushjar_core::exchange::import::ImportSummary, SessionError> {
    let parsed = session.parse_import(text, None, password).unwrap();
    session.import(store, &parsed)
}

#[test]
fn export_and_import_every_format() {
    let Some(base) = server() else { return };
    let (store_a, mut a) = account(&base, ARGON);
    seed(&mut a, &store_a);
    let expected = comparable(&a);
    let passkey = &expected["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "Passkey login")
        .unwrap()["login"]["fido2Credentials"][0];
    assert_eq!(passkey["counter"], "7");
    assert_eq!(passkey["rpId"], "example.org");

    let json_text = a.export_json(Scope::Personal).unwrap();
    let locked = a.export_encrypted_json(Scope::Personal).unwrap();
    let protected = a
        .export_password_protected_json(Scope::Personal, FILE_PASSWORD)
        .unwrap();
    let csv = a.export_csv(Scope::Personal).unwrap();
    let protected_doc: Value = serde_json::from_str(&protected).unwrap();
    assert_eq!(protected_doc["kdfType"], 1, "uses the account's Argon2id");
    assert_eq!(protected_doc["kdfMemory"], 64);

    // Unencrypted JSON into a fresh account, field by field.
    let (store_b, mut b) = account(&base, PBKDF2);
    let summary = import_text(&mut b, &store_b, &json_text, None).unwrap();
    assert_eq!((summary.items, summary.folders_created), (5, 1));
    assert_eq!(comparable(&b), expected);

    // A locked export is refused by another account ...
    let (store_c, mut c) = account(&base, PBKDF2);
    assert!(matches!(
        c.parse_import(&locked, None, None),
        Err(ExchangeError::WrongAccount)
    ));
    // ... and opens in its own account, reusing the existing folder.
    let summary = import_text(&mut a, &store_a, &locked, None).unwrap();
    assert_eq!(
        (
            summary.items,
            summary.folders_reused,
            summary.folders_created
        ),
        (5, 1, 0)
    );
    assert_eq!(a.vault.items.len(), 10);
    assert_eq!(a.vault.folders.len(), 1);
    let again = comparable(&a);
    assert_eq!(again["items"].as_array().unwrap().len(), 10);
    assert_eq!(again["items"][0], again["items"][1], "copies are identical");

    // Password-protected into a third account; the wrong password is refused.
    assert!(matches!(
        c.parse_import(&protected, None, Some("not the password")),
        Err(ExchangeError::WrongPassword)
    ));
    assert!(matches!(
        c.parse_import(&protected, None, None),
        Err(ExchangeError::PasswordRequired)
    ));
    import_text(&mut c, &store_c, &protected, Some(FILE_PASSWORD)).unwrap();
    assert_eq!(comparable(&c), expected);

    // CSV carries logins and notes only.
    let (store_d, mut d) = account(&base, PBKDF2);
    let summary = import_text(&mut d, &store_d, &csv, None).unwrap();
    assert_eq!(summary.items, 2);
    let login = d
        .vault
        .items
        .iter()
        .find(|i| i.kind == ItemKind::Login)
        .unwrap();
    assert_eq!(login.name, "Passkey login");
    assert_eq!(login.login.username, "sam");
    assert_eq!(login.login.uris.len(), 2);
    assert_eq!(
        login.fields.len(),
        4,
        "CSV keeps linked fields as empty text"
    );
    assert!(login.favorite && login.reprompt);
    let folder = d
        .vault
        .folders
        .iter()
        .find(|f| Some(&f.id) == login.folder_id.as_ref());
    assert_eq!(folder.unwrap().name, "Work/Code");
    assert_eq!(import::detect(&csv), Some(import::Format::BitwardenCsv));
}

#[test]
fn import_each_csv_fixture() {
    let Some(base) = server() else { return };
    let (store, mut session) = account(&base, PBKDF2);
    let dir = format!("{}/tests/data/import", env!("CARGO_MANIFEST_DIR"));
    let mut total = 0;
    for (file, count) in [
        ("chrome.csv", 3),
        ("firefox.csv", 2),
        ("safari.csv", 2),
        ("keepassxc.csv", 3),
        ("lastpass.csv", 5),
        ("bitwarden.csv", 3),
        ("onepassword.csv", 3),
    ] {
        let text = std::fs::read_to_string(format!("{dir}/{file}")).unwrap();
        let summary = import_text(&mut session, &store, &text, None).unwrap();
        assert_eq!(summary.items, count, "{file}");
        total += count;
        assert_eq!(session.vault.items.len(), total, "{file}");
    }
    let find = |name: &str| session.vault.items.iter().find(|i| i.name == name).unwrap();
    assert_eq!(find("Intranet").login.totp, "JBSWY3DPEHPK3PXP");
    assert_eq!(find("Travel card").card.number, "4111111111111111");
    assert_eq!(find("com.example.app").login.password, "app-pass-2");
    let work = session
        .vault
        .folders
        .iter()
        .filter(|f| f.name == "Work")
        .count();
    assert_eq!(work, 1, "KeePassXC and Bitwarden CSV share one Work folder");
    let names: Vec<&str> = session
        .vault
        .folders
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    for expected in ["Work", "Work/Code", "Shopping", "Finance", "Root"] {
        assert!(names.contains(&expected), "{expected} in {names:?}");
    }
    assert_eq!(
        names.len(),
        names.iter().collect::<std::collections::HashSet<_>>().len(),
        "no duplicate folders"
    );
}
