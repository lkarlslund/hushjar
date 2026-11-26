//! Known-answer tests from Bitwarden's SDK and independent tools. See
//! tests/data/crypto/README.md and the manifests for where each came from.

use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/crypto/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    let s = value.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn u32_of(v: &Value, key: &str) -> u32 {
    v[key].as_u64().unwrap() as u32
}

#[test]
fn pbkdf2_master_keys() {
    for v in load("pbkdf2.json").as_array().unwrap() {
        let kdf = Kdf::Pbkdf2 {
            iterations: u32_of(v, "iterations"),
        };
        let key = crypto::master_key(
            v["password"].as_str().unwrap(),
            v["email"].as_str().unwrap(),
            kdf,
        )
        .unwrap();
        assert_eq!(to_hex(&key[..]), v["key_hex"].as_str().unwrap());
    }
}

#[test]
fn argon2id_master_keys() {
    for v in load("argon2id.json").as_array().unwrap() {
        let kdf = Kdf::Argon2id {
            iterations: u32_of(v, "iterations"),
            memory_mib: u32_of(v, "memory_mib"),
            parallelism: u32_of(v, "parallelism"),
        };
        let key = crypto::master_key(
            v["password"].as_str().unwrap(),
            v["email"].as_str().unwrap(),
            kdf,
        )
        .unwrap();
        assert_eq!(to_hex(&key[..]), v["key_hex"].as_str().unwrap());
    }
}

#[test]
fn password_hashes() {
    for v in load("auth-hash.json").as_array().unwrap() {
        let master: [u8; 32] = hex(&v["master_hex"]).try_into().unwrap();
        let purpose = match v["purpose"].as_u64().unwrap() {
            1 => HashPurpose::Server,
            _ => HashPurpose::Local,
        };
        let hash = crypto::password_hash(&master, v["password"].as_str().unwrap(), purpose);
        assert_eq!(hash.as_str(), v["hash"].as_str().unwrap());
    }
}

#[test]
fn stretched_keys() {
    for v in load("stretch.json").as_array().unwrap() {
        let master: [u8; 32] = hex(&v["master_hex"]).try_into().unwrap();
        let stretched = crypto::stretch(&master);
        assert_eq!(
            to_hex(&stretched.to_bytes()),
            v["stretched_hex"].as_str().unwrap()
        );
    }
}

#[test]
fn type2_strings() {
    for v in load("type2.json").as_array().unwrap() {
        let key = SymmetricKey::from_bytes(&hex(&v["key_hex"])).unwrap();
        let result = v["encoded"]
            .as_str()
            .unwrap()
            .parse()
            .map_err(|_| ())
            .and_then(|e| key.decrypt(&e).map_err(|_| ()));
        if v["valid"].as_bool().unwrap() {
            assert_eq!(
                to_hex(&result.unwrap()),
                v["plaintext_hex"].as_str().unwrap()
            );
        } else {
            assert!(result.is_err(), "{} should be rejected", v["encoded"]);
        }
    }
}

#[test]
fn user_keys() {
    for v in load("user-key.json").as_array().unwrap() {
        let master: [u8; 32] = hex(&v["master_hex"]).try_into().unwrap();
        let result = crypto::stretch(&master).unwrap_key(v["encoded"].as_str().unwrap());
        if v["valid"].as_bool().unwrap() {
            assert_eq!(
                to_hex(&result.unwrap().to_bytes()),
                v["user_key_hex"].as_str().unwrap()
            );
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn item_keys() {
    let v = load("item-key.json");
    let parent = SymmetricKey::from_bytes(&hex(&v["parent_hex"])).unwrap();
    let item = parent.unwrap_key(v["wrapped"].as_str().unwrap()).unwrap();
    assert_eq!(
        item.decrypt_str(v["field"].as_str().unwrap())
            .unwrap()
            .as_str(),
        "item field"
    );
    assert_eq!(
        parent
            .decrypt_str(v["legacy_field"].as_str().unwrap())
            .unwrap()
            .as_str(),
        "legacy field"
    );
    assert!(
        parent.decrypt_str(v["field"].as_str().unwrap()).is_err(),
        "the item key, not the parent, opens item fields"
    );
}

#[test]
fn encstring_sample_parses_and_reformats() {
    let path = format!(
        "{}/tests/data/crypto/encstring.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let text = text.trim();
    let parsed: crypto::EncString = text.parse().unwrap();
    assert_eq!(parsed.to_string(), text);
}
