//! Folders, archiving, passkeys and organisation moves against a real
//! Vaultwarden server. They run only when HUSHJAR_INTEROP is set to the
//! server's address, like interop.rs. Every account is invented and lives
//! only in the test server's memory.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hushjar_core::api::Server;
use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::Store;
use hushjar_core::vault::{Item, ItemKind};
use rsa::Generate;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde_json::{Value, json};

const PASSWORD: &str = "invented interop password";
const KDF: Kdf = Kdf::Pbkdf2 {
    iterations: 600_000,
};

fn server() -> Option<String> {
    let url = std::env::var("HUSHJAR_INTEROP").ok();
    if url.is_none() {
        eprintln!("skipped: set HUSHJAR_INTEROP to a Vaultwarden test server");
    }
    url
}

fn register(base: &str, email: &str) -> SymmetricKey {
    let master = crypto::master_key(PASSWORD, email, KDF).unwrap();
    let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
    let user_key = SymmetricKey::generate();
    let body = json!({
        "email": email,
        "name": "Hushjar interop test",
        "masterPasswordHash": hash.as_str(),
        "key": crypto::stretch(&master).wrap_key(&user_key),
        "kdf": 0,
        "kdfIterations": 600_000,
    });
    let response = ureq::post(format!("{base}/identity/accounts/register"))
        .send_json(&body)
        .unwrap();
    assert_eq!(response.status().as_u16(), 200, "registration failed");
    user_key
}

struct Account {
    store: Store,
    dir: std::path::PathBuf,
    base: String,
    session: Session,
    user_key: SymmetricKey,
    public: rsa::PublicKey,
}

impl Drop for Account {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sign_in(base: &str, email: &str, dir: &std::path::Path) -> (Store, Session) {
    let store = Store::open(dir.to_path_buf()).unwrap();
    let session = Session::sign_in(
        &store,
        Server::parse(base).unwrap(),
        email,
        PASSWORD,
        None,
        None,
    )
    .unwrap();
    (store, session)
}

/// An invented account with an RSA key pair, as every real account has.
fn account(base: &str, tag: &str) -> Account {
    let email = format!("{tag}-{}@example.invalid", uuid::Uuid::new_v4().simple());
    let user_key = register(base, &email);
    let dir = std::env::temp_dir().join(format!("hushjar-ops-{}", uuid::Uuid::new_v4().simple()));
    let (_, mut first) = sign_in(base, &email, &dir);
    let private = rsa::PrivateKey::generate();
    let der = private.to_pkcs8_der().unwrap();
    let public = private.to_public_key().to_public_key_der().unwrap();
    call(
        base,
        &mut first,
        "POST",
        "/accounts/keys",
        json!({
            "publicKey": B64.encode(public.as_bytes()),
            "encryptedPrivateKey": user_key.encrypt(der.as_bytes()).to_string(),
        }),
    );
    // Signing in again picks the private key up.
    let (store, session) = sign_in(base, &email, &dir);
    Account {
        store,
        dir,
        base: base.to_string(),
        session,
        user_key,
        public: private.to_public_key(),
    }
}

/// Sends an authenticated API request as `session`'s user.
fn call(base: &str, session: &mut Session, method: &str, path: &str, body: Value) -> Value {
    let token = session.access_token().unwrap();
    let url = format!("{base}/api{path}");
    let bearer = format!("Bearer {}", token.as_str());
    let response = match method {
        "POST" => ureq::post(&url)
            .header("Authorization", &bearer)
            .send_json(&body),
        _ => unreachable!(),
    };
    let mut response = response.unwrap_or_else(|e| panic!("{method} {path}: {e}"));
    let text = response.body_mut().read_to_string().unwrap();
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// Creates an organisation owned by `owner` with a real key, and returns
/// its id, its key and two new collections.
fn organisation(owner: &mut Account) -> (String, SymmetricKey, [String; 2]) {
    let org_key = SymmetricKey::generate();
    let wrapped = owner
        .public
        .oaep_encrypt::<sha1::Sha1>(&org_key.to_bytes())
        .unwrap();
    let org = call(
        &owner.base,
        &mut owner.session,
        "POST",
        "/organizations",
        json!({
            "name": "Invented move org",
            "billingEmail": "billing@example.invalid",
            "collectionName": org_key.encrypt_str("Default"),
            "key": format!("4.{}", B64.encode(wrapped)),
            "planType": 0,
        }),
    );
    let org_id = org["id"].as_str().expect("organisation id").to_string();
    let mut collection = |name: &str| {
        let made = call(
            &owner.base,
            &mut owner.session,
            "POST",
            &format!("/organizations/{org_id}/collections"),
            json!({ "name": org_key.encrypt_str(name), "groups": [], "users": [] }),
        );
        made["id"].as_str().expect("collection id").to_string()
    };
    let ids = [collection("Team"), collection("Archive")];
    (org_id, org_key, ids)
}

fn login(name: &str) -> Item {
    let mut item = Item::new(ItemKind::Login, None, None);
    item.name = name.into();
    item.login.username = "sam".into();
    item.login.password = "hunter2 invented".into();
    item
}

/// A login with two passkeys encrypted with `key`.
fn with_passkeys(mut item: Item, key: &SymmetricKey, wrapped_key: Option<String>) -> Item {
    let passkey = |id: &str, site: &str| {
        json!({
            "credentialId": key.encrypt_str(id), "keyType": key.encrypt_str("public-key"),
            "keyAlgorithm": key.encrypt_str("ECDSA"), "keyCurve": key.encrypt_str("P-256"),
            "keyValue": key.encrypt_str("MIGHAgEAMBMG-not-a-real-key"),
            "rpId": key.encrypt_str(site), "userHandle": key.encrypt_str("dXNlcg"),
            "userName": key.encrypt_str("sam"), "counter": key.encrypt_str("7"),
            "rpName": key.encrypt_str("Example"), "userDisplayName": key.encrypt_str("Sam Example"),
            "discoverable": key.encrypt_str("true"), "creationDate": "2026-02-03T04:05:06.789Z",
        })
    };
    item.raw = json!({
        "key": wrapped_key,
        "login": { "fido2Credentials": [passkey("cred-1", "one.example"), passkey("cred-2", "two.example")] },
    });
    item
}

fn fresh(account: &mut Account, id: &str) -> Item {
    account
        .session
        .vault
        .item(id)
        .expect("item in vault")
        .clone()
}

#[test]
fn folders_nest_rename_and_delete() {
    let Some(base) = server() else { return };
    let mut a = account(&base, "ops-folders");
    let s = &mut a.session;
    let store = &a.store;
    let work = s.create_folder(store, "Work").unwrap();
    s.create_folder(store, "Work/Clients").unwrap();
    s.create_folder(store, "Work/Clients/Acme").unwrap();
    s.create_folder(store, "Workshop").unwrap();

    let mut item = login("Filed");
    item.folder_id = Some(work.clone());
    let saved = s.save(store, &item).unwrap();
    assert_eq!(saved.folder_id.as_deref(), Some(work.as_str()));

    assert_eq!(s.rename_folder_tree(store, "Work", "Jobs/Old").unwrap(), 3);
    let mut names: Vec<_> = s.vault.folders.iter().map(|f| f.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "Jobs/Old",
            "Jobs/Old/Clients",
            "Jobs/Old/Clients/Acme",
            "Workshop"
        ]
    );
    s.rename_folder(store, &work, "Jobs/Renamed").unwrap();
    assert!(s.vault.folders.iter().any(|f| f.name == "Jobs/Renamed"));

    // Deleting a folder leaves its items, in "No folder".
    s.delete_folder(store, &work).unwrap();
    assert!(s.vault.folders.iter().all(|f| f.id != work));
    assert_eq!(s.vault.folders.len(), 3);
    let after = fresh(&mut a, &saved.id);
    assert_eq!(after.folder_id, None);
    assert_eq!(after.name, "Filed");
}

#[test]
fn archive_round_trip_and_saving_keeps_it() {
    let Some(base) = server() else { return };
    let mut a = account(&base, "ops-archive");
    let s = &mut a.session;
    let store = &a.store;
    let saved = s.save(store, &login("Old site")).unwrap();
    assert!(!saved.archived);

    s.archive(store, &saved.id).unwrap();
    let mut archived = s.vault.item(&saved.id).unwrap().clone();
    assert!(archived.archived);

    // An edit must not undo the archiving.
    archived.name = "Old site (renamed)".into();
    s.save(store, &archived).unwrap();
    s.sync(store).unwrap();
    let again = s.vault.item(&saved.id).unwrap();
    assert_eq!(again.name, "Old site (renamed)");
    assert!(again.archived, "saving unarchived the item");

    s.unarchive(store, &saved.id).unwrap();
    assert!(!s.vault.item(&saved.id).unwrap().archived);
    assert!(matches!(
        s.archive(store, "00000000-0000-0000-0000-000000000000"),
        Err(SessionError::Api(_))
    ));
}

#[test]
fn passkeys_can_be_removed_one_at_a_time() {
    let Some(base) = server() else { return };
    let mut a = account(&base, "ops-passkeys");
    let user = a.user_key.clone();
    let s = &mut a.session;
    let store = &a.store;
    let saved = s
        .save(store, &with_passkeys(login("Passkey site"), &user, None))
        .unwrap();
    s.sync(store).unwrap();
    let item = s.vault.item(&saved.id).unwrap().clone();
    assert_eq!(item.login.passkey_details.len(), 2);
    assert_eq!(item.login.passkey_details[0].rp_id, "one.example");
    assert_eq!(
        item.login.passkey_details[1].user_display_name,
        "Sam Example"
    );
    let kept = item.raw["login"]["fido2Credentials"][1].clone();

    let item = s.remove_passkey(store, &saved.id, "cred-1").unwrap();
    assert_eq!(item.login.passkeys, 1);
    s.sync(store).unwrap();
    let item = s.vault.item(&saved.id).unwrap();
    assert_eq!(item.login.passkey_details.len(), 1);
    assert_eq!(item.login.passkey_details[0].credential_id, "cred-2");
    assert_eq!(item.raw["login"]["fido2Credentials"][0], kept);
    assert_eq!(item.login.password, "hunter2 invented");
    assert!(matches!(
        s.remove_passkey(store, &saved.id, "cred-1"),
        Err(SessionError::NotFound)
    ));
}

#[test]
fn items_move_into_an_organisation_and_between_collections() {
    let Some(base) = server() else { return };
    let mut a = account(&base, "ops-move");
    let (org, org_key, [team, other]) = organisation(&mut a);
    let user = a.user_key.clone();
    a.session.sync(&a.store).unwrap();
    assert_eq!(a.session.vault.collections.len(), 3);

    let s = &mut a.session;
    let store = &a.store;

    // An old-style item: no item key of its own, with a passkey and a file.
    let plain = s
        .save(store, &with_passkeys(login("Plain item"), &user, None))
        .unwrap();
    s.add_attachment(store, &plain.id, "notes.txt", b"attachment bytes")
        .unwrap();

    // A newer item with its own key.
    let item_key = SymmetricKey::generate();
    let mut keyed = login("Keyed item");
    keyed.raw = json!({ "key": user.wrap_key(&item_key) });
    let keyed = s.save(store, &keyed).unwrap();
    s.add_attachment(store, &keyed.id, "keyed.txt", b"keyed bytes")
        .unwrap();

    assert!(matches!(
        s.move_to_organization(store, &plain.id, &org, &[]),
        Err(SessionError::Invalid(_))
    ));
    assert!(matches!(
        s.move_to_organization(store, &plain.id, &org, &["nope".to_string()]),
        Err(SessionError::Invalid(_))
    ));
    assert!(matches!(
        s.set_collections(store, &plain.id, std::slice::from_ref(&team)),
        Err(SessionError::Invalid(_))
    ));

    for (id, name, file, bytes) in [
        (
            &plain.id,
            "Plain item",
            "notes.txt",
            &b"attachment bytes"[..],
        ),
        (&keyed.id, "Keyed item", "keyed.txt", &b"keyed bytes"[..]),
    ] {
        let moved = s
            .move_to_organization(store, id, &org, std::slice::from_ref(&team))
            .unwrap();
        assert_eq!(moved.organization_id.as_deref(), Some(org.as_str()));
        assert_eq!(moved.collection_ids, std::slice::from_ref(&team));

        // After a fresh sync everything opens with the organisation key.
        s.sync(store).unwrap();
        let item = s.vault.item(id).unwrap().clone();
        assert_eq!(item.name, name);
        assert_eq!(item.login.password, "hunter2 invented");
        assert_eq!(item.unreadable, 0);
        assert_eq!(item.organization_id.as_deref(), Some(org.as_str()));
        let wrapped = item.raw["key"].as_str().expect("item key after move");
        org_key.unwrap_key(wrapped).expect("wrapped by the org key");
        assert_eq!(item.attachments[0].file_name, file);
        let downloaded = s.download_attachment(id, &item.attachments[0].id).unwrap();
        assert_eq!(downloaded.as_slice(), bytes);

        // Another item in the vault: change the collections.
        let changed = s
            .set_collections(store, id, std::slice::from_ref(&other))
            .unwrap();
        assert_eq!(changed.collection_ids, std::slice::from_ref(&other));
        let both = s
            .set_collections(store, id, &[team.clone(), other.clone()])
            .unwrap();
        let mut ids = both.collection_ids.clone();
        ids.sort();
        let mut expected = vec![team.clone(), other.clone()];
        expected.sort();
        assert_eq!(ids, expected);
        assert!(matches!(
            s.move_to_organization(store, id, &org, std::slice::from_ref(&team)),
            Err(SessionError::Invalid(_))
        ));
    }

    // The passkeys survived the re-encryption of the old-style item.
    let plain = s.vault.item(&plain.id).unwrap();
    assert_eq!(plain.login.passkey_details.len(), 2);
    assert_eq!(plain.login.passkey_details[1].rp_id, "two.example");
    // And editing a moved item still works.
    let mut edited = plain.clone();
    edited.login.password = "changed".into();
    s.save(store, &edited).unwrap();
    s.sync(store).unwrap();
    let after = s.vault.item(&edited.id).unwrap();
    assert_eq!(after.login.password, "changed");
    assert_eq!(after.login.passkey_details.len(), 2);
    assert_eq!(after.unreadable, 0);
}
