//! Cross-checks the SSH key module against the real OpenSSH and OpenSSL tools.
//! Each test prints a note and passes when a tool is missing. Unix only: the
//! tests set file permissions the way ssh-keygen insists on.
#![cfg(unix)]

use hushjar_core::sshkey::{self, Algorithm, SshKeyError};
use std::path::{Path, PathBuf};
use std::process::Command;

fn dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sshkey");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn have(tool: &str, arg: &str) -> bool {
    let ok = Command::new(tool).arg(arg).output().is_ok();
    if !ok {
        println!("skipping: {tool} is not installed");
    }
    ok
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("run tool");
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn write_private(name: &str, pem: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir().join(name);
    std::fs::write(&p, pem).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

/// `ssh-keygen -y` and `-l` on our key must agree with what we stored.
fn check_with_ssh_keygen(name: &str, alg: Algorithm) {
    let key = sshkey::generate(alg).unwrap();
    let path = write_private(name, &key.private_key);
    let public = run(Command::new("ssh-keygen").args(["-y", "-f"]).arg(&path));
    assert_eq!(public.trim(), key.public_key);
    let l = run(Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(&path));
    assert_eq!(l.split_whitespace().nth(1).unwrap(), key.fingerprint);
}

#[test]
fn generated_ed25519_matches_ssh_keygen() {
    if have("ssh-keygen", "-?") {
        check_with_ssh_keygen("gen-ed", Algorithm::Ed25519);
    }
}

#[test]
fn generated_rsa_matches_ssh_keygen() {
    if have("ssh-keygen", "-?") {
        check_with_ssh_keygen("gen-rsa2048", Algorithm::Rsa2048);
        check_with_ssh_keygen("gen-rsa3072", Algorithm::Rsa3072);
    }
}

/// Slow in a debug build, so it only runs on request.
#[test]
#[ignore]
fn generated_rsa4096_matches_ssh_keygen() {
    if have("ssh-keygen", "-?") {
        check_with_ssh_keygen("gen-rsa4096", Algorithm::Rsa4096);
    }
}

fn keygen_to_file(path: &Path, args: &[&str]) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}.pub", path.display()));
    run(Command::new("ssh-keygen")
        .args(args)
        .arg("-f")
        .arg(path)
        .arg("-q"));
}

fn pub_without_comment(path: &Path) -> String {
    let text = std::fs::read_to_string(format!("{}.pub", path.display())).unwrap();
    text.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn imports_encrypted_ed25519() {
    if !have("ssh-keygen", "-?") {
        return;
    }
    let path = dir().join("enc-ed");
    keygen_to_file(&path, &["-t", "ed25519", "-N", "test pass", "-C", ""]);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        sshkey::import(&text, None),
        Err(SshKeyError::PassphraseNeeded)
    );
    assert_eq!(
        sshkey::import(&text, Some("nope")),
        Err(SshKeyError::WrongPassphrase)
    );
    let key = sshkey::import(&text, Some("test pass")).unwrap();
    assert_eq!(key.public_key, pub_without_comment(&path));
    // The stored key is decrypted and ssh-keygen agrees.
    let stored = write_private("enc-ed-stored", &key.private_key);
    let public = run(Command::new("ssh-keygen").args(["-y", "-f"]).arg(&stored));
    assert_eq!(public.trim(), key.public_key);
}

#[test]
fn imports_rsa_and_plain_ed25519() {
    if !have("ssh-keygen", "-?") {
        return;
    }
    let rsa = dir().join("imp-rsa");
    keygen_to_file(
        &rsa,
        &["-t", "rsa", "-b", "2048", "-N", "", "-C", "me@host"],
    );
    let key = sshkey::import(&std::fs::read_to_string(&rsa).unwrap(), None).unwrap();
    assert_eq!(key.public_key, pub_without_comment(&rsa));
    let ed = dir().join("imp-ed");
    keygen_to_file(&ed, &["-t", "ed25519", "-N", "", "-C", "x"]);
    let key = sshkey::import(&std::fs::read_to_string(&ed).unwrap(), None).unwrap();
    assert_eq!(key.public_key, pub_without_comment(&ed));
    // ECDSA is not supported.
    let ec = dir().join("imp-ec");
    keygen_to_file(&ec, &["-t", "ecdsa", "-N", "", "-C", ""]);
    assert_eq!(
        sshkey::import(&std::fs::read_to_string(&ec).unwrap(), None),
        Err(SshKeyError::Unsupported)
    );
}

#[test]
fn imports_pkcs8_from_openssl() {
    if !have("openssl", "version") || !have("ssh-keygen", "-?") {
        return;
    }
    for (name, args) in [
        ("p8-ed", vec!["-algorithm", "ed25519"]),
        (
            "p8-rsa",
            vec!["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        ),
    ] {
        let plain = dir().join(name);
        run(Command::new("openssl")
            .arg("genpkey")
            .args(&args)
            .arg("-out")
            .arg(&plain));
        let text = std::fs::read_to_string(&plain).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----")); // privacy:allow (PEM format marker, not a key)
        let key = sshkey::import(&text, None).unwrap();
        // What the key should be, according to ssh-keygen reading the PKCS#8 file.
        std::fs::set_permissions(&plain, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o600)
        })
        .unwrap();
        let out = Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(&plain)
            .output()
            .expect("run ssh-keygen");
        if out.status.success() {
            let expected = String::from_utf8(out.stdout).unwrap();
            assert_eq!(key.public_key, expected.trim());
        } else {
            // Many ssh-keygen builds (macOS's, Ubuntu 24.04's) cannot read
            // Ed25519 keys in PKCS#8 files; newer ones (as on Arch) check it.
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                name == "p8-ed" && stderr.contains("invalid format"),
                "ssh-keygen -y {name}: {stderr}"
            );
            println!(
                "skipping the ssh-keygen check for {name}: {}",
                stderr.trim()
            );
        }

        let enc = dir().join(format!("{name}-enc"));
        run(Command::new("openssl")
            .arg("pkcs8")
            .args([
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-passout",
                "pass:p8 pass",
                "-in",
            ])
            .arg(&plain)
            .arg("-out")
            .arg(&enc));
        let text = std::fs::read_to_string(&enc).unwrap();
        assert!(text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")); // privacy:allow (PEM format marker, not a key)
        assert_eq!(
            sshkey::import(&text, None),
            Err(SshKeyError::PassphraseNeeded)
        );
        assert_eq!(
            sshkey::import(&text, Some("bad")),
            Err(SshKeyError::WrongPassphrase)
        );
        let again = sshkey::import(&text, Some("p8 pass")).unwrap();
        assert_eq!(again.public_key, key.public_key);
        assert_eq!(again.fingerprint, key.fingerprint);
    }
}
