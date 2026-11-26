//! Attachments and Sends against a real Vaultwarden server. They run only
//! when HUSHJAR_INTEROP is set to the server's address, like interop.rs.
//! Every account is invented and lives only in the test server's memory.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hushjar_core::api::{Client, Device, Server};
use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
use hushjar_core::send::{SendEntry, SendKind};
use hushjar_core::session::Session;
use hushjar_core::store::Store;
use hushjar_core::vault::{Item, ItemKind};
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

fn unique_email(tag: &str) -> String {
    format!("{tag}-{}@example.invalid", uuid::Uuid::new_v4().simple())
}

/// Registers an invented account and returns its user key.
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
    session: Session,
    user_key: SymmetricKey,
}

impl Drop for Account {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sign_in_new(base: &str, tag: &str) -> Account {
    let email = unique_email(tag);
    let user_key = register(base, &email);
    let dir = std::env::temp_dir().join(format!("hushjar-files-{}", uuid::Uuid::new_v4().simple()));
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
    Account {
        store,
        dir,
        session,
        user_key,
    }
}

/// Bytes that are not all alike, so a mix-up would show.
fn sample_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).rotate_right(13) as u8)
        .collect()
}

#[test]
fn attachments_add_download_survive_edits_and_delete() {
    let Some(base) = server() else { return };
    let mut a = sign_in_new(&base, "attach");
    let mut login = Item::new(ItemKind::Login, None, None);
    login.name = "With files".into();
    login.login.password = "first".into();
    let item_id = a.session.save(&a.store, &login).unwrap().id.clone();

    // A small file and one of a few megabytes, uploaded as multipart.
    let small = b"hello attachment\n".to_vec();
    let large = sample_bytes(3 << 20);
    let item = a
        .session
        .add_attachment(&a.store, &item_id, "hello.txt", &small)
        .unwrap();
    assert_eq!(item.attachments.len(), 1);
    assert_eq!(item.attachments[0].file_name, "hello.txt");
    let item = a
        .session
        .add_attachment(&a.store, &item_id, "large.bin", &large)
        .unwrap();
    assert_eq!(item.attachments.len(), 2);
    let id_of = |item: &Item, name: &str| {
        item.attachments
            .iter()
            .find(|x| x.file_name == name)
            .unwrap()
            .id
            .clone()
    };
    let small_id = id_of(&item, "hello.txt");
    let large_id = id_of(&item, "large.bin");
    let large_meta = item.attachments.iter().find(|x| x.id == large_id).unwrap();
    assert!(large_meta.size > large.len() as u64);
    assert!(!large_meta.size_name.is_empty());
    assert_eq!(
        &a.session.download_attachment(&item_id, &small_id).unwrap()[..],
        &small[..]
    );
    assert_eq!(
        &a.session.download_attachment(&item_id, &large_id).unwrap()[..],
        &large[..]
    );

    // Editing the item leaves its attachments alone.
    let mut edited = a.session.vault.item(&item_id).unwrap().clone();
    let before = edited.clone();
    edited.login.password = "second".into();
    edited.note_password_change(&before);
    a.session.save(&a.store, &edited).unwrap();
    a.session.sync(&a.store).unwrap();
    let item = a.session.vault.item(&item_id).unwrap().clone();
    assert_eq!(item.login.password, "second");
    assert_eq!(item.attachments.len(), 2);
    assert_eq!(
        &a.session.download_attachment(&item_id, &small_id).unwrap()[..],
        &small[..]
    );

    // The offline copy holds the attachment list too.
    let profile = a.store.profiles().pop().unwrap();
    let offline = Session::unlock(&a.store, &profile, PASSWORD).unwrap();
    assert_eq!(offline.vault.item(&item_id).unwrap().attachments.len(), 2);

    a.session
        .delete_attachment(&a.store, &item_id, &small_id)
        .unwrap();
    let item = a.session.vault.item(&item_id).unwrap();
    assert_eq!(item.attachments.len(), 1);
    assert_eq!(item.attachments[0].id, large_id);
    assert!(a.session.download_attachment(&item_id, &small_id).is_err());
}

#[test]
fn attachments_on_items_with_their_own_key() {
    let Some(base) = server() else { return };
    let mut a = sign_in_new(&base, "attachkey");
    // Create an item with an item key directly through the API.
    let email = a.session.profile.email.clone();
    let client = Client::new(Server::parse(&base).unwrap());
    let master = crypto::master_key(PASSWORD, &email, KDF).unwrap();
    let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
    let login = client.login(&email, &hash, &Device::new(), None).unwrap();
    let item_key = SymmetricKey::generate();
    let cipher = json!({
        "type": 2,
        "key": a.user_key.wrap_key(&item_key),
        "name": item_key.encrypt_str("Keyed note"),
        "notes": null,
        "favorite": false,
        "secureNote": { "type": 0 },
    });
    let created = client.create_cipher(&login.access_token, &cipher).unwrap();
    let item_id = created["id"].as_str().unwrap().to_string();
    a.session.sync(&a.store).unwrap();
    assert_eq!(a.session.vault.item(&item_id).unwrap().name, "Keyed note");

    let data = sample_bytes(4097);
    let item = a
        .session
        .add_attachment(&a.store, &item_id, "keyed.bin", &data)
        .unwrap();
    let attachment = &item.attachments[0];
    assert_eq!(attachment.file_name, "keyed.bin");
    // The attachment key and file name are encrypted with the item key.
    let raw = item.raw["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == json!(attachment.id))
        .unwrap();
    assert!(item_key.unwrap_key(raw["key"].as_str().unwrap()).is_ok());
    assert!(a.user_key.unwrap_key(raw["key"].as_str().unwrap()).is_err());
    assert_eq!(
        item_key
            .decrypt_str(raw["fileName"].as_str().unwrap())
            .unwrap()
            .as_str(),
        "keyed.bin"
    );
    assert_eq!(
        &a.session
            .download_attachment(&item_id, &attachment.id)
            .unwrap()[..],
        &data[..]
    );
}

/// Opens a share link the way a recipient's browser would: the key comes
/// from the part after `#`, and the access id is all that reaches the
/// server.
fn open_link(link: &str) -> (String, SymmetricKey) {
    let (_, fragment) = link.split_once("#/send/").expect("self-hosted link");
    let (access_id, key) = fragment.split_once('/').unwrap();
    let material: [u8; 16] = URL_SAFE_NO_PAD.decode(key).unwrap().try_into().unwrap();
    (access_id.to_string(), crypto::send_key(&material))
}

/// The anonymous Send access request. Returns the status and reply.
fn access(base: &str, access_id: &str, password_hash: Option<&str>) -> (u16, Value) {
    let mut response = ureq::post(format!("{base}/api/sends/access/{access_id}"))
        .config()
        .http_status_as_error(false)
        .build()
        .send_json(json!({ "password": password_hash }))
        .unwrap();
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string().unwrap_or_default();
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn link_material(link: &str) -> [u8; 16] {
    let key = link.rsplit('/').next().unwrap();
    URL_SAFE_NO_PAD.decode(key).unwrap().try_into().unwrap()
}

#[test]
fn text_send_link_password_and_delete() {
    let Some(base) = server() else { return };
    let mut a = sign_in_new(&base, "sendtext");
    let mut draft = SendEntry::new(SendKind::Text);
    draft.name = "Door code".into();
    draft.notes = "only for the plumber".into();
    draft.text = "4711".into();
    draft.hide_text = true;
    let send = a.session.save_send(&a.store, &draft, None).unwrap();
    assert!(!send.id.is_empty() && !send.access_id.is_empty());
    assert_eq!(send.text, "4711");
    assert_eq!(a.session.vault.sends.len(), 1);
    let link = a.session.send_link(&send).unwrap();
    assert!(link.starts_with(&format!("{base}/#/send/{}/", send.access_id)));

    // A recipient with only the link can read it.
    let (access_id, key) = open_link(&link);
    let (status, reply) = access(&base, &access_id, None);
    assert_eq!(status, 200, "{reply}");
    let read = |reply: &Value, path: &[&str]| {
        let mut v = reply;
        for p in path {
            v = &v[*p];
        }
        key.decrypt_str(v.as_str().unwrap()).unwrap().to_string()
    };
    assert_eq!(read(&reply, &["name"]), "Door code");
    assert_eq!(read(&reply, &["text", "text"]), "4711");
    assert_eq!(reply["text"]["hidden"], json!(true));

    // Edit the text; the link stays the same.
    let mut edited = send.clone();
    edited.text = "0815".into();
    edited.max_access_count = Some(10);
    let edited = a.session.save_send(&a.store, &edited, None).unwrap();
    assert_eq!(edited.access_id, send.access_id);
    assert_eq!(edited.max_access_count, Some(10));
    assert_eq!(a.session.send_link(&edited).unwrap(), link);
    let (_, reply) = access(&base, &access_id, None);
    assert_eq!(read(&reply, &["text", "text"]), "0815");

    // Set a password: access needs its hash, salted with the key material.
    let protected = a
        .session
        .save_send(&a.store, &edited, Some("open sesame"))
        .unwrap();
    assert!(protected.has_password);
    assert_eq!(access(&base, &access_id, None).0, 401);
    let wrong = crypto::send_password_hash("wrong", &link_material(&link));
    assert_eq!(access(&base, &access_id, Some(&wrong)).0, 400);
    let right = crypto::send_password_hash("open sesame", &link_material(&link));
    let (status, reply) = access(&base, &access_id, Some(&right));
    assert_eq!(status, 200, "{reply}");
    assert_eq!(read(&reply, &["text", "text"]), "0815");

    // Editing without a new password keeps the old one.
    let mut renamed = protected.clone();
    renamed.name = "Door code (new)".into();
    let renamed = a.session.save_send(&a.store, &renamed, None).unwrap();
    assert!(renamed.has_password);
    assert_eq!(access(&base, &access_id, None).0, 401);
    assert_eq!(access(&base, &access_id, Some(&right)).0, 200);

    let open = a
        .session
        .remove_send_password(&a.store, &renamed.id)
        .unwrap();
    assert!(!open.has_password);
    assert_eq!(access(&base, &access_id, None).0, 200);

    // A fresh sync and an offline unlock agree with what was saved.
    a.session.sync(&a.store).unwrap();
    let synced = a.session.vault.send(&send.id).unwrap();
    assert_eq!(synced.name, "Door code (new)");
    assert_eq!(synced.notes, "only for the plumber");
    assert!(!synced.has_password);
    let profile = a.store.profiles().pop().unwrap();
    let offline = Session::unlock(&a.store, &profile, PASSWORD).unwrap();
    assert_eq!(offline.vault.send(&send.id).unwrap().text, "0815");

    a.session.delete_send(&a.store, &send.id).unwrap();
    assert!(a.session.vault.sends.is_empty());
    assert_eq!(access(&base, &access_id, None).0, 404);
    a.session.sync(&a.store).unwrap();
    assert!(a.session.vault.sends.is_empty());
}

#[test]
fn file_send_upload_and_anonymous_download() {
    let Some(base) = server() else { return };
    let mut a = sign_in_new(&base, "sendfile");
    let data = sample_bytes(200_003);
    let mut draft = SendEntry::new(SendKind::File);
    draft.name = "Holiday photos".into();
    let send = a
        .session
        .create_file_send(&a.store, &draft, "photos.zip", &data, Some("pw"))
        .unwrap();
    let file = send.file.as_ref().unwrap();
    assert_eq!(file.file_name, "photos.zip");
    assert!(file.size > data.len() as u64);
    assert!(send.has_password);

    // Download as a recipient: access the Send, then ask for the file.
    let link = a.session.send_link(&send).unwrap();
    let (access_id, key) = open_link(&link);
    let hash = crypto::send_password_hash("pw", &link_material(&link));
    let (status, reply) = access(&base, &access_id, Some(&hash));
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        key.decrypt_str(reply["name"].as_str().unwrap())
            .unwrap()
            .as_str(),
        "Holiday photos"
    );
    assert_eq!(
        key.decrypt_str(reply["file"]["fileName"].as_str().unwrap())
            .unwrap()
            .as_str(),
        "photos.zip"
    );
    let send_id = reply["id"].as_str().unwrap();
    let file_id = reply["file"]["id"].as_str().unwrap();
    let mut response = ureq::post(format!("{base}/api/sends/{send_id}/access/file/{file_id}"))
        .send_json(json!({ "password": hash.as_str() }))
        .unwrap();
    let download: Value =
        serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap();
    let url = download["url"].as_str().unwrap();
    let encrypted = ureq::get(url)
        .call()
        .unwrap()
        .body_mut()
        .with_config()
        .limit(16 << 20)
        .read_to_vec()
        .unwrap();
    assert_eq!(&key.decrypt_buffer(&encrypted).unwrap()[..], &data[..]);

    // Settings of a file Send can be edited; the file stays.
    let mut edited = send.clone();
    edited.disabled = true;
    let edited = a.session.save_send(&a.store, &edited, None).unwrap();
    assert!(edited.disabled);
    assert_eq!(edited.file.as_ref().unwrap().file_name, "photos.zip");
    assert_eq!(access(&base, &access_id, Some(&hash)).0, 404);

    a.session.delete_send(&a.store, &send.id).unwrap();
    a.session.sync(&a.store).unwrap();
    assert!(a.session.vault.sends.is_empty());
}
