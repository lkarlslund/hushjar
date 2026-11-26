//! Import and export without a server: the vault is built in memory from
//! encrypted JSON, as a sync reply would deliver it.

use hushjar_core::crypto::{Kdf, SymmetricKey};
use hushjar_core::exchange::ExchangeError;
use hushjar_core::exchange::export::{self, Scope};
use hushjar_core::exchange::import::{self, Context, Format, ParsedImport};
use hushjar_core::vault::{self, ItemKind, Keys};
use serde_json::{Value, json};

fn passkey() -> Value {
    json!({
        "credentialId": "cred-1", "keyType": "public-key", "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256", "keyValue": "MIGHAgEAMBMG-not-a-real-key", "rpId": "example.org",
        "userHandle": "dXNlcg", "userName": "sam", "counter": "7", "rpName": "Example",
        "userDisplayName": "Sam Example", "discoverable": "true",
        "creationDate": "2026-02-03T04:05:06.789Z",
    })
}

/// A vault with every item type, a folder, a passkey and an item key.
fn sample() -> (vault::Vault, Keys) {
    let user = SymmetricKey::generate();
    let keys = Keys {
        user: user.clone(),
        organizations: Default::default(),
    };
    let e = |k: &SymmetricKey, s: &str| json!(k.encrypt_str(s));
    let item_key = SymmetricKey::generate();
    let mut credential = passkey();
    for name in [
        "credentialId",
        "keyType",
        "keyAlgorithm",
        "keyCurve",
        "keyValue",
        "rpId",
        "userHandle",
        "userName",
        "counter",
        "rpName",
        "userDisplayName",
        "discoverable",
    ] {
        credential[name] = e(&item_key, passkey()[name].as_str().unwrap());
    }
    let ciphers = vec![
        json!({
            "id": "i1", "type": 1, "folderId": "f1", "favorite": true, "reprompt": 1,
            "key": user.wrap_key(&item_key), "name": e(&item_key, "Example login"),
            "notes": e(&item_key, "a note"),
            "creationDate": "2026-01-01T00:00:00.123456Z", "revisionDate": "2026-01-02T00:00:00Z",
            "login": {
                "username": e(&item_key, "sam"), "password": e(&item_key, "pw-1"),
                "totp": e(&item_key, "JBSWY3DPEHPK3PXP"),
                "uris": [
                    { "uri": e(&item_key, "https://example.org"), "match": 3, "uriChecksum": e(&item_key, "x") },
                    { "uri": e(&item_key, "https://example.com"), "match": null },
                ],
                "fido2Credentials": [credential],
            },
            "fields": [
                { "type": 0, "name": e(&item_key, "Pin"), "value": e(&item_key, "1234") },
                { "type": 1, "name": e(&item_key, "Secret"), "value": e(&item_key, "s3") },
                { "type": 2, "name": e(&item_key, "Flag"), "value": e(&item_key, "true") },
                { "type": 3, "name": null, "value": null, "linkedId": 100 },
            ],
            "passwordHistory": [{ "password": e(&item_key, "old-pw"), "lastUsedDate": "2025-12-31T00:00:00Z" }],
        }),
        json!({ "id": "i2", "type": 2, "name": e(&user, "Note"), "notes": e(&user, "line1\nline2"),
                "secureNote": { "type": 0 } }),
        json!({ "id": "i3", "type": 3, "folderId": null, "name": e(&user, "Card"),
                "card": { "cardholderName": e(&user, "Sam"), "brand": e(&user, "Visa"),
                          "number": e(&user, "4111111111111111"), "expMonth": e(&user, "8"),
                          "expYear": e(&user, "2030"), "code": e(&user, "123") } }),
        json!({ "id": "i4", "type": 4, "name": e(&user, "Me"),
                "identity": { "firstName": e(&user, "Sam"), "lastName": e(&user, "Example"),
                              "passportNumber": e(&user, "X1"), "email": null } }),
        json!({ "id": "i5", "type": 5, "name": e(&user, "Key"),
                "sshKey": { "privateKey": e(&user, "PRIVATE"), "publicKey": e(&user, "ssh-ed25519 AAAA"),
                            "keyFingerprint": e(&user, "SHA256:x") } }),
        // A type Hushjar does not model; still exported from the raw JSON.
        json!({ "id": "i6", "type": 7, "name": e(&user, "Licence"),
                "driversLicense": { "licenseNumber": e(&user, "L-1") } }),
        json!({ "id": "i7", "type": 2, "deletedDate": "2026-01-01T00:00:00Z", "name": e(&user, "Gone"),
                "secureNote": { "type": 0 } }),
    ];
    let sync = json!({
        "profile": { "id": "u1", "email": "a@example.invalid" },
        "folders": [{ "id": "f1", "name": e(&user, "Work/Code") }],
        "ciphers": ciphers,
    });
    let vault = vault::decrypt_sync(&sync, &keys);
    (vault, keys)
}

const KDF: Kdf = Kdf::Pbkdf2 { iterations: 5_000 };

#[test]
fn json_export_matches_bitwarden_layout() {
    let (vault, keys) = sample();
    let text = export::json(&vault, &keys, Scope::Personal).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["encrypted"], false);
    assert_eq!(doc["folders"], json!([{ "id": "f1", "name": "Work/Code" }]));
    let items = doc["items"].as_array().unwrap();
    assert_eq!(items.len(), 6, "deleted item left out");
    let login = &items[0];
    assert_eq!(login["organizationId"], Value::Null);
    assert_eq!(login["folderId"], "f1");
    assert_eq!(login["reprompt"], 1);
    assert_eq!(login["name"], "Example login");
    assert!(login.get("key").is_none(), "no item key in clear exports");
    assert_eq!(login["collectionIds"], Value::Null);
    assert_eq!(
        login["login"]["uris"][0],
        json!({ "uri": "https://example.org", "match": 3 })
    );
    assert_eq!(login["login"]["fido2Credentials"][0], passkey());
    assert_eq!(
        login["fields"][3],
        json!({ "name": null, "value": null, "type": 3, "linkedId": 100 })
    );
    assert_eq!(login["passwordHistory"][0]["password"], "old-pw");
    assert_eq!(login["creationDate"], "2026-01-01T00:00:00.123Z");
    assert_eq!(login["revisionDate"], "2026-01-02T00:00:00.000Z");
    assert_eq!(items[5]["driversLicense"]["licenseNumber"], "L-1");
    // Key order follows Bitwarden's exporter.
    let keys_in_order: Vec<&str> = login
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        &keys_in_order[..4],
        ["id", "organizationId", "folderId", "type"]
    );
    assert!(
        text.contains("\n  \"items\""),
        "two-space indent like JSON.stringify"
    );
}

#[test]
fn csv_export_has_bitwarden_columns() {
    let (vault, _) = sample();
    let text = export::csv(&vault, Scope::Personal).unwrap();
    let mut lines = text.split("\r\n");
    assert_eq!(
        lines.next().unwrap(),
        "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp"
    );
    assert!(text.contains("Work/Code,1,login,Example login,a note,"));
    assert!(text.contains("\"https://example.org,https://example.com\""));
    assert!(text.contains(",,note,Note,\"line1\nline2\""));
    assert!(!text.contains("Card"), "cards are not in Bitwarden's CSV");
}

/// Compares the parsed items to the sample vault, field by field.
fn assert_matches_sample(parsed: &ParsedImport) {
    assert_eq!(parsed.folders, ["Work/Code"]);
    assert_eq!(parsed.skipped, 1, "the unmodelled licence is counted");
    assert_eq!(parsed.items.len(), 4 + 1);
    let by_name = |n: &str| parsed.items.iter().find(|i| i.item.name == n).unwrap();
    let login = by_name("Example login");
    assert_eq!(login.folder, Some(0));
    assert!(login.item.favorite && login.item.reprompt);
    assert_eq!(login.item.notes, "a note");
    assert_eq!(login.item.login.username, "sam");
    assert_eq!(login.item.login.password, "pw-1");
    assert_eq!(login.item.login.totp, "JBSWY3DPEHPK3PXP");
    assert_eq!(login.item.login.uris[0].match_type, Some(3));
    assert_eq!(login.item.login.uris[1].uri, "https://example.com");
    assert_eq!(login.passkeys, [passkey()]);
    assert_eq!(login.item.fields.len(), 4);
    assert_eq!(login.item.fields[1].value, "s3");
    assert_eq!(login.item.fields[3].linked_id, Some(100));
    assert_eq!(login.item.password_history[0].password, "old-pw");
    assert_eq!(by_name("Note").item.notes, "line1\nline2");
    assert_eq!(by_name("Card").item.card.number, "4111111111111111");
    assert_eq!(by_name("Card").folder, None);
    assert_eq!(by_name("Me").item.identity_value("passportNumber"), "X1");
    assert_eq!(by_name("Key").item.ssh_key.private_key, "PRIVATE");
    assert_eq!(by_name("Key").item.kind, ItemKind::SshKey);
}

#[test]
fn json_variants_round_trip() {
    let (vault, keys) = sample();
    let context = Context {
        keys: Some(&keys),
        password: Some("export password"),
    };
    let plain = export::json(&vault, &keys, Scope::Personal).unwrap();
    assert_matches_sample(&import::parse(&plain, None, &context).unwrap());

    let locked = export::encrypted_json(&vault, &keys, Scope::Personal).unwrap();
    let doc: Value = serde_json::from_str(&locked).unwrap();
    assert_eq!(doc["encrypted"], true);
    assert!(doc["encKeyValidation_DO_NOT_EDIT"].is_string());
    assert!(!locked.contains("pw-1") && !locked.contains("Example login"));
    assert_eq!(doc["items"][0]["login"]["uris"][0]["match"], 3);
    assert!(doc["items"][0]["key"].is_string(), "item key kept, wrapped");
    assert_matches_sample(&import::parse(&locked, None, &context).unwrap());

    for kdf in [
        KDF,
        Kdf::Argon2id {
            iterations: 2,
            memory_mib: 16,
            parallelism: 1,
        },
    ] {
        let protected =
            export::password_protected_json(&vault, &keys, Scope::Personal, kdf, "export password")
                .unwrap();
        let doc: Value = serde_json::from_str(&protected).unwrap();
        assert_eq!(doc["passwordProtected"], true);
        assert!(doc["salt"].is_string() && doc["data"].is_string());
        assert_eq!(
            doc["kdfType"],
            if matches!(kdf, Kdf::Pbkdf2 { .. }) {
                0
            } else {
                1
            }
        );
        assert_eq!(
            doc.get("kdfMemory").is_some(),
            matches!(kdf, Kdf::Argon2id { .. })
        );
        assert_matches_sample(&import::parse(&protected, None, &context).unwrap());
    }
}

#[test]
fn wrong_passwords_and_accounts_are_clear_errors() {
    let (vault, keys) = sample();
    let protected =
        export::password_protected_json(&vault, &keys, Scope::Personal, KDF, "right").unwrap();
    fn with<'a>(password: Option<&'a str>, keys: Option<&'a Keys>) -> Context<'a> {
        Context { keys, password }
    }
    assert!(matches!(
        import::parse(&protected, None, &with(Some("wrong"), None)),
        Err(ExchangeError::WrongPassword)
    ));
    assert!(matches!(
        import::parse(&protected, None, &with(None, None)),
        Err(ExchangeError::PasswordRequired)
    ));
    assert_eq!(
        import::parse(&protected, None, &with(Some("wrong"), None))
            .unwrap_err()
            .to_string(),
        "wrong file password"
    );
    assert!(import::parse(&protected, None, &with(Some("right"), None)).is_ok());

    let locked = export::encrypted_json(&vault, &keys, Scope::Personal).unwrap();
    let stranger = Keys {
        user: SymmetricKey::generate(),
        organizations: Default::default(),
    };
    assert!(matches!(
        import::parse(&locked, None, &with(None, Some(&stranger))),
        Err(ExchangeError::WrongAccount)
    ));
    assert!(matches!(
        export::protect("{}", KDF, ""),
        Err(ExchangeError::EmptyPassword)
    ));
}

#[test]
fn hostile_kdf_settings_are_refused_before_deriving() {
    let doc = json!({
        "encrypted": true, "passwordProtected": true, "salt": "c2FsdA==",
        "kdfType": 1, "kdfIterations": 3, "kdfMemory": 4_000_000, "kdfParallelism": 4,
        "encKeyValidation_DO_NOT_EDIT": "2.AAAA|AAAA|AAAA", "data": "2.AAAA|AAAA|AAAA",
    });
    let context = Context {
        keys: None,
        password: Some("x"),
    };
    assert!(matches!(
        import::parse(&doc.to_string(), None, &context),
        Err(ExchangeError::UnsupportedKdf)
    ));
}

#[test]
fn export_files_are_read_back_by_the_csv_importer() {
    let (vault, _) = sample();
    let text = export::csv(&vault, Scope::Personal).unwrap();
    let parsed = import::parse(&text, None, &Context::default()).unwrap();
    assert_eq!(parsed.format, Format::BitwardenCsv);
    assert_eq!(parsed.items.len(), 2);
    let login = &parsed.items[0].item;
    assert_eq!(login.login.uris.len(), 2);
    assert_eq!(login.fields[0].name, "Pin");
    assert!(login.favorite && login.reprompt);
    assert_eq!(parsed.folders, ["Work/Code", "Work"]);
    assert_eq!(parsed.items[1].item.kind, ItemKind::SecureNote);
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/data/import/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

fn parse_fixture(name: &str, expected: Format) -> ParsedImport {
    let text = fixture(name);
    assert_eq!(import::detect(&text), Some(expected), "{name}");
    let parsed = import::parse(&text, None, &Context::default()).unwrap();
    // An explicit choice gives the same result.
    let explicit = import::parse(&text, Some(expected), &Context::default()).unwrap();
    assert_eq!(parsed.items.len(), explicit.items.len());
    parsed
}

#[test]
fn chrome_csv() {
    let p = parse_fixture("chrome.csv", Format::ChromeCsv);
    assert_eq!(p.items.len(), 3);
    assert_eq!(
        p.items[0].item.login.uris[0].uri,
        "https://mail.example.org/login"
    );
    assert_eq!(p.items[0].item.notes, "Main mailbox");
    assert_eq!(p.items[1].item.name, "com.example.app");
    assert_eq!(
        p.items[1].item.login.uris[0].uri,
        "androidapp://com.example.app"
    );
    assert_eq!(p.items[2].item.login.uris[0].uri, "http://example.net");
    assert_eq!(p.items[2].item.login.password, "pass, with \"quotes\"");
    assert_eq!(p.items[2].item.notes, "line one\nline two");
}

#[test]
fn firefox_csv() {
    let p = parse_fixture("firefox.csv", Format::FirefoxCsv);
    assert_eq!(p.items.len(), 2, "the sync account entry is dropped");
    assert_eq!(p.items[0].item.name, "example.org");
    assert_eq!(p.items[1].item.login.password, "fox-pass-3");
}

#[test]
fn safari_csv() {
    let p = parse_fixture("safari.csv", Format::SafariCsv);
    assert_eq!(p.items.len(), 2);
    assert!(p.items[0].item.login.totp.starts_with("otpauth://totp/"));
    assert_eq!(p.items[0].item.notes, "Remember me");
    assert_eq!(p.items[1].item.name, "shop.example.net");
}

#[test]
fn keepassxc_csv() {
    let p = parse_fixture("keepassxc.csv", Format::KeePassXcCsv);
    assert_eq!(p.items.len(), 3, "an entry without a title is dropped");
    assert_eq!(p.folders, ["Work", "Work/Code", "Root"]);
    assert_eq!(p.items[0].folder, Some(0));
    assert_eq!(p.items[1].folder, Some(1));
    assert_eq!(p.items[0].item.login.totp, "JBSWY3DPEHPK3PXP");
    assert_eq!(p.items[2].item.name, "Top level");
    assert_eq!(p.items[2].folder, Some(2));
    assert_eq!(p.items[2].folder, Some(2));
}

#[test]
fn lastpass_csv() {
    let p = parse_fixture("lastpass.csv", Format::LastPassCsv);
    assert_eq!(p.items.len(), 5);
    assert_eq!(p.folders, ["Shopping", "Finance"]);
    assert!(p.items[0].item.favorite);
    assert_eq!(p.items[0].item.notes, "Some notes");
    assert_eq!(p.items[0].folder, Some(0));
    assert_eq!(p.items[2].item.kind, ItemKind::SecureNote);
    assert_eq!(p.items[2].item.notes, "Just a note\nwith two lines");
    assert_eq!(p.items[2].folder, None);
    let card = &p.items[3].item;
    assert_eq!(card.kind, ItemKind::Card);
    assert_eq!(card.card.number, "4111111111111111");
    assert_eq!(
        (card.card.exp_month.as_str(), card.card.exp_year.as_str()),
        ("6", "2029")
    );
    assert_eq!(card.card.brand, "Visa");
    assert_eq!(card.notes, "Travel card");
    let address = &p.items[4].item;
    assert_eq!(address.kind, ItemKind::Identity);
    assert_eq!(address.identity_value("city"), "Springfield");
}

#[test]
fn bitwarden_csv() {
    let p = parse_fixture("bitwarden.csv", Format::BitwardenCsv);
    assert_eq!(p.items.len(), 3);
    assert_eq!(p.folders, ["Work", "Work/Code"]);
    let login = &p.items[0].item;
    assert!(login.favorite && login.reprompt);
    assert_eq!(login.login.uris.len(), 2);
    assert_eq!(login.fields.len(), 2);
    assert_eq!(login.fields[1].name, "Team");
    assert_eq!(p.items[1].item.kind, ItemKind::SecureNote);
    assert_eq!(p.items[1].folder, None);
    assert_eq!(p.items[2].folder, Some(1));
}

#[test]
fn onepassword_csv() {
    let p = parse_fixture("onepassword.csv", Format::OnePasswordCsv);
    assert_eq!(p.items.len(), 3);
    let first = &p.items[0].item;
    assert!(first.favorite);
    assert_eq!(first.login.uris[0].uri, "https://example.org");
    assert!(first.login.totp.starts_with("otpauth://"));
    assert_eq!(first.notes, "Some notes");
    assert_eq!(p.items[2].item.kind, ItemKind::SecureNote);
}

#[test]
fn unknown_and_empty_files_are_refused() {
    assert!(matches!(
        import::parse("a,b\n1,2\n", None, &Context::default()),
        Err(ExchangeError::UnknownFormat)
    ));
    assert!(matches!(
        import::parse(
            "name,url,username,password\n",
            Some(Format::ChromeCsv),
            &Context::default()
        ),
        Err(ExchangeError::Malformed(_))
    ));
    assert!(matches!(
        import::parse("{\"x\":1}", None, &Context::default()),
        Err(ExchangeError::Malformed(_))
    ));
}
