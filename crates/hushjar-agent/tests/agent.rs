//! End-to-end tests: start the agent on a socket in a temporary directory and
//! talk to it with a small protocol client, and with OpenSSH's own tools when
//! they are installed.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use hushjar_agent::{
    Agent, AgentError, AgentKey, Approver, KeySource, SignPurpose, SignRequest, Zeroizing,
};
use signature::{Signer, Verifier};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_RESPONSE: u8 = 14;
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

// ---------------------------------------------------------------------------
// Test fixtures

fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

struct TestKeys {
    ed25519: PrivateKey,
    ecdsa: PrivateKey,
    rsa: PrivateKey,
}

/// Keys are generated once per test binary: RSA generation is slow in debug
/// builds.
fn test_keys() -> &'static TestKeys {
    static KEYS: OnceLock<TestKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let ed25519 = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
        let ecdsa = PrivateKey::random(
            &mut rng(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let rsa = RsaKeypair::random(&mut rng(), 2048).unwrap();
        let rsa = PrivateKey::new(KeypairData::from(rsa), "rsa").unwrap();
        TestKeys {
            ed25519,
            ecdsa,
            rsa,
        }
    })
}

fn agent_key(id: &str, key: &PrivateKey) -> AgentKey {
    AgentKey {
        id: id.into(),
        name: format!("{id} key"),
        private_key_openssh: Zeroizing::new(key.to_openssh(LineEnding::LF).unwrap().to_string()),
    }
}

fn blob(key: &PrivateKey) -> Vec<u8> {
    key.public_key().to_bytes().unwrap()
}

#[derive(Default)]
struct Keys(Mutex<Vec<AgentKey>>);

impl Keys {
    fn with(keys: Vec<AgentKey>) -> Arc<Keys> {
        Arc::new(Keys(Mutex::new(keys)))
    }
}

impl KeySource for Keys {
    fn keys(&self) -> Vec<AgentKey> {
        self.0.lock().unwrap().clone()
    }
}

/// Records requests and answers with `allow`. Optionally empties the key
/// source while "the prompt is up".
struct Recorder {
    allow: AtomicBool,
    requests: Mutex<Vec<SignRequest>>,
    lock_on_prompt: Option<Arc<Keys>>,
}

impl Recorder {
    fn new(allow: bool) -> Arc<Recorder> {
        Arc::new(Recorder {
            allow: AtomicBool::new(allow),
            requests: Mutex::new(Vec::new()),
            lock_on_prompt: None,
        })
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn last(&self) -> SignRequest {
        self.requests.lock().unwrap().last().unwrap().clone()
    }
}

impl Approver for Recorder {
    fn approve(&self, request: &SignRequest) -> bool {
        self.requests.lock().unwrap().push(request.clone());
        if let Some(keys) = &self.lock_on_prompt {
            keys.0.lock().unwrap().clear();
        }
        self.allow.load(Ordering::SeqCst)
    }
}

/// A private temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("hjagent-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        TempDir(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("agent").join("ssh-agent.sock")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// A minimal agent protocol client

fn string(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

struct Client(UnixStream);

impl Client {
    fn connect(path: &Path) -> Client {
        let stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        Client(stream)
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).unwrap();
    }

    /// Sends one message and returns the reply, or `None` if the agent closed
    /// the connection.
    fn request(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        // After the agent has closed the connection, writing fails.
        self.0.write_all(&string(message)).ok()?;
        self.reply()
    }

    fn reply(&mut self) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        self.0.read_exact(&mut len).ok()?;
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        self.0.read_exact(&mut reply).ok()?;
        Some(reply)
    }

    fn list(&mut self) -> Vec<(Vec<u8>, String)> {
        let reply = self.request(&[11]).unwrap();
        assert_eq!(reply[0], IDENTITIES_ANSWER);
        let mut rest = &reply[1..];
        let count = take_u32(&mut rest);
        let mut identities = Vec::new();
        for _ in 0..count {
            let blob = take_string(&mut rest);
            let comment = String::from_utf8(take_string(&mut rest)).unwrap();
            identities.push((blob, comment));
        }
        assert!(rest.is_empty());
        identities
    }

    /// Returns the signature, or `None` on `SSH_AGENT_FAILURE`.
    fn sign(&mut self, key_blob: &[u8], data: &[u8], flags: u32) -> Option<Signature> {
        let mut message = vec![13];
        message.extend(string(key_blob));
        message.extend(string(data));
        message.extend(flags.to_be_bytes());
        let reply = self.request(&message).unwrap();
        if reply == [FAILURE] {
            return None;
        }
        assert_eq!(reply[0], SIGN_RESPONSE);
        let mut rest = &reply[1..];
        let signature = take_string(&mut rest);
        assert!(rest.is_empty());
        Some(Signature::try_from(signature.as_slice()).unwrap())
    }

    /// Sends `session-bind@openssh.com`; returns the reply byte.
    fn bind(&mut self, host: &PrivateKey, session_id: &[u8], forwarding: bool) -> u8 {
        let signature = host.try_sign(session_id).unwrap();
        let signature = ssh_key::encoding::Encode::encode_vec(&signature).unwrap();
        self.bind_raw(&blob(host), session_id, &signature, forwarding)
    }

    fn bind_raw(&mut self, host: &[u8], session_id: &[u8], sig: &[u8], forwarding: bool) -> u8 {
        let mut message = vec![27];
        message.extend(string(b"session-bind@openssh.com"));
        message.extend(string(host));
        message.extend(string(session_id));
        message.extend(string(sig));
        message.push(u8::from(forwarding));
        let reply = self.request(&message).unwrap();
        assert_eq!(reply.len(), 1);
        reply[0]
    }
}

fn take_u32(rest: &mut &[u8]) -> u32 {
    let (head, tail) = rest.split_at(4);
    *rest = tail;
    u32::from_be_bytes(head.try_into().unwrap())
}

fn take_string(rest: &mut &[u8]) -> Vec<u8> {
    let len = take_u32(rest) as usize;
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    head.to_vec()
}

/// SSH_MSG_USERAUTH_REQUEST signed data for a publickey login.
fn userauth_data(session_id: &[u8], user: &str, key: &PrivateKey) -> Vec<u8> {
    let mut data = string(session_id);
    data.push(50);
    data.extend(string(user.as_bytes()));
    data.extend(string(b"ssh-connection"));
    data.extend(string(b"publickey"));
    data.push(1);
    data.extend(string(key.algorithm().as_str().as_bytes()));
    data.extend(string(&blob(key)));
    data
}

fn verify(key: &PrivateKey, data: &[u8], signature: &Signature) {
    key.public_key()
        .key_data()
        .verify(data, signature)
        .expect("signature verifies");
}

fn start(dir: &TempDir, keys: Arc<Keys>, approver: Arc<Recorder>) -> Agent {
    Agent::start(&dir.socket(), keys, approver).unwrap()
}

fn all_keys() -> Arc<Keys> {
    let keys = test_keys();
    Keys::with(vec![
        agent_key("ed25519", &keys.ed25519),
        agent_key("ecdsa", &keys.ecdsa),
        agent_key("rsa", &keys.rsa),
    ])
}

// ---------------------------------------------------------------------------
// Tests

#[test]
fn lists_signs_denies_and_rejects_unknown_keys() {
    let keys = test_keys();
    let dir = TempDir::new();
    let approver = Recorder::new(true);
    let agent = start(&dir, all_keys(), Arc::clone(&approver));
    let mut client = Client::connect(agent.socket_path());

    // List: all three keys, with their names as comments.
    let listed = client.list();
    assert_eq!(
        listed,
        vec![
            (blob(&keys.ed25519), "ed25519 key".to_string()),
            (blob(&keys.ecdsa), "ecdsa key".to_string()),
            (blob(&keys.rsa), "rsa key".to_string()),
        ]
    );

    // Sign and verify with each key.
    let data = b"some data to sign";
    for (id, key, flags) in [
        ("ed25519", &keys.ed25519, 0),
        ("ecdsa", &keys.ecdsa, 0),
        ("rsa", &keys.rsa, RSA_SHA2_256),
        ("rsa", &keys.rsa, RSA_SHA2_512),
    ] {
        let signature = client.sign(&blob(key), data, flags).expect("signed");
        verify(key, data, &signature);
        let request = approver.last();
        assert_eq!(request.key_id, id);
        assert_eq!(request.key_name, format!("{id} key"));
        assert_eq!(
            request.fingerprint,
            key.public_key().fingerprint(HashAlg::Sha256).to_string()
        );
        assert!(request.fingerprint.starts_with("SHA256:"));
        assert!(!request.fingerprint.ends_with('='));
        assert_eq!(request.peer.pid, Some(std::process::id()));
        assert_eq!(request.peer.uid, fs::metadata(&dir.0).unwrap().uid());
        assert_eq!(request.host, None);
        assert!(!request.forwarded);
        assert_eq!(request.purpose, SignPurpose::Other);
        if flags == RSA_SHA2_256 {
            assert_eq!(
                signature.algorithm(),
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256)
                }
            );
        }
        if flags == RSA_SHA2_512 {
            assert_eq!(
                signature.algorithm(),
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512)
                }
            );
        }
    }
    assert_eq!(approver.count(), 4);

    // Flags that do not fit the key are refused without asking.
    assert!(
        client.sign(&blob(&keys.rsa), data, 0).is_none(),
        "ssh-rsa SHA-1"
    );
    assert!(client.sign(&blob(&keys.rsa), data, 6).is_none());
    assert!(client.sign(&blob(&keys.ed25519), data, 2).is_none());
    assert_eq!(approver.count(), 4);

    // An unknown key is refused without asking.
    let other = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    assert!(client.sign(&blob(&other), data, 0).is_none());
    assert_eq!(approver.count(), 4);

    // Denied.
    approver.allow.store(false, Ordering::SeqCst);
    assert!(client.sign(&blob(&keys.ed25519), data, 0).is_none());
    assert_eq!(approver.count(), 5);

    // Empty data is refused.
    assert!(client.sign(&blob(&keys.ed25519), b"", 0).is_none());
    assert_eq!(approver.count(), 5);
}

#[test]
fn refuses_key_management_lock_and_unknown_requests() {
    let dir = TempDir::new();
    let approver = Recorder::new(true);
    let agent = start(&dir, all_keys(), approver);
    let mut client = Client::connect(agent.socket_path());
    let mut query = vec![27];
    query.extend(string(b"query"));
    for message in [
        vec![17, 0, 0, 0, 0],       // add identity
        vec![18, 0, 0, 0, 0],       // remove identity
        vec![19],                   // remove all
        vec![22, 0, 0, 0, 1, b'x'], // lock
        vec![23, 0, 0, 0, 1, b'x'], // unlock
        vec![13, 0, 0],             // truncated sign request
        vec![11, 0],                // list with trailing bytes
        query,                      // other extension
        vec![99],                   // unknown
    ] {
        assert_eq!(client.request(&message), Some(vec![FAILURE]), "{message:?}");
    }
    // The connection still works afterwards.
    assert_eq!(client.list().len(), 3);
}

#[test]
fn closes_connection_on_bad_lengths() {
    let dir = TempDir::new();
    let agent = start(&dir, all_keys(), Recorder::new(true));

    let mut client = Client::connect(agent.socket_path());
    client.send_raw(&0u32.to_be_bytes());
    assert_eq!(client.reply(), None, "zero length");

    let mut client = Client::connect(agent.socket_path());
    client.send_raw(&(64u32 * 1024 + 1).to_be_bytes());
    assert_eq!(client.reply(), None, "over 64 KiB");

    // Exactly 64 KiB is read and answered (with failure: it is not a valid
    // sign request).
    let mut client = Client::connect(agent.socket_path());
    let mut message = vec![0u8; 64 * 1024];
    message[0] = 13;
    assert_eq!(client.request(&message), Some(vec![FAILURE]));
}

#[test]
fn session_bind_reports_the_verified_host() {
    let keys = test_keys();
    let dir = TempDir::new();
    let approver = Recorder::new(true);
    let agent = start(&dir, all_keys(), Arc::clone(&approver));
    let host = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let host_fingerprint = host.public_key().fingerprint(HashAlg::Sha256).to_string();
    let session_id = [7u8; 32];

    // A bad signature is refused.
    let mut client = Client::connect(agent.socket_path());
    let wrong = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let bad_signature = wrong.try_sign(&session_id).unwrap();
    let bad_signature = ssh_key::encoding::Encode::encode_vec(&bad_signature).unwrap();
    assert_eq!(
        client.bind_raw(&blob(&host), &session_id, &bad_signature, false),
        FAILURE
    );

    // A good one binds; signing a login for that session names the host.
    assert_eq!(client.bind(&host, &session_id, false), SUCCESS);
    // Repeating the same binding is fine.
    assert_eq!(client.bind(&host, &session_id, false), SUCCESS);
    let data = userauth_data(&session_id, "git", &keys.ed25519);
    let signature = client.sign(&blob(&keys.ed25519), &data, 0).unwrap();
    verify(&keys.ed25519, &data, &signature);
    let request = approver.last();
    assert_eq!(request.purpose, SignPurpose::Login { user: "git".into() });
    let bound = request.host.expect("host");
    assert_eq!(bound.fingerprint, host_fingerprint);
    assert!(bound.public_key.starts_with("ssh-ed25519 "));
    assert!(!request.forwarded);

    // A login for another session gets no host.
    let data = userauth_data(&[9u8; 32], "git", &keys.ed25519);
    client.sign(&blob(&keys.ed25519), &data, 0).unwrap();
    assert_eq!(approver.last().host, None);

    // A connection bound for a login cannot be bound again.
    assert_eq!(client.bind(&host, &[8u8; 32], false), FAILURE);
}

#[test]
fn session_bind_reports_forwarding() {
    let keys = test_keys();
    let dir = TempDir::new();
    let approver = Recorder::new(true);
    let agent = start(&dir, all_keys(), Arc::clone(&approver));
    let jump = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let target = PrivateKey::random(
        &mut rng(),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    )
    .unwrap();

    let mut client = Client::connect(agent.socket_path());
    // The user's ssh binds the forwarded channel to the jump host...
    assert_eq!(client.bind(&jump, &[1u8; 32], true), SUCCESS);
    // ...and ssh on the jump host binds it to its own login.
    assert_eq!(client.bind(&target, &[2u8; 32], false), SUCCESS);
    let data = userauth_data(&[2u8; 32], "deploy", &keys.rsa);
    let signature = client.sign(&blob(&keys.rsa), &data, RSA_SHA2_512).unwrap();
    verify(&keys.rsa, &data, &signature);
    let request = approver.last();
    assert!(request.forwarded);
    assert_eq!(request.forwarded_via.len(), 1);
    assert_eq!(
        request.forwarded_via[0].fingerprint,
        jump.public_key().fingerprint(HashAlg::Sha256).to_string()
    );
    assert_eq!(
        request.host.unwrap().fingerprint,
        target.public_key().fingerprint(HashAlg::Sha256).to_string()
    );
    assert_eq!(
        request.purpose,
        SignPurpose::Login {
            user: "deploy".into()
        }
    );
}

#[test]
fn key_switched_off_during_prompt_does_not_sign() {
    let keys = test_keys();
    let dir = TempDir::new();
    let source = all_keys();
    let approver = Arc::new(Recorder {
        allow: AtomicBool::new(true),
        requests: Mutex::new(Vec::new()),
        lock_on_prompt: Some(Arc::clone(&source)),
    });
    let agent = start(&dir, source, Arc::clone(&approver));
    let mut client = Client::connect(agent.socket_path());
    assert!(client.sign(&blob(&keys.ed25519), b"data", 0).is_none());
    assert_eq!(approver.count(), 1);
    assert!(client.list().is_empty());
}

#[test]
fn concurrent_connections_wait_independently() {
    // One connection blocked in the approver must not hold up another.
    struct Slow {
        entered: Mutex<usize>,
        release: AtomicBool,
    }
    impl Approver for Slow {
        fn approve(&self, request: &SignRequest) -> bool {
            *self.entered.lock().unwrap() += 1;
            if request.key_id == "ed25519" {
                while !self.release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            true
        }
    }
    let keys = test_keys();
    let dir = TempDir::new();
    let slow = Arc::new(Slow {
        entered: Mutex::new(0),
        release: AtomicBool::new(false),
    });
    let agent = Agent::start(
        &dir.socket(),
        all_keys(),
        Arc::clone(&slow) as Arc<dyn Approver>,
    )
    .unwrap();
    let path = agent.socket_path().to_path_buf();
    let blocked = std::thread::spawn(move || {
        let mut client = Client::connect(&path);
        client
            .sign(&blob(&test_keys().ed25519), b"one", 0)
            .is_some()
    });
    while *slow.entered.lock().unwrap() == 0 {
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut client = Client::connect(agent.socket_path());
    assert!(client.sign(&blob(&keys.ecdsa), b"two", 0).is_some());
    assert_eq!(client.list().len(), 3);
    slow.release.store(true, Ordering::SeqCst);
    assert!(blocked.join().unwrap());
}

#[test]
fn socket_permissions_stale_socket_and_stop() {
    let dir = TempDir::new();
    let socket = dir.socket();

    // A stale socket left by an earlier run is replaced.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(socket.parent().unwrap())
        .unwrap();
    drop(UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());

    let agent = start(&dir, all_keys(), Recorder::new(true));
    assert_eq!(agent.socket_path(), socket);
    let mode = fs::symlink_metadata(&socket).unwrap().mode();
    assert_eq!(mode & 0o777, 0o600);
    let dir_mode = fs::metadata(socket.parent().unwrap()).unwrap().mode();
    assert_eq!(dir_mode & 0o777, 0o700);

    // A second agent on the same path refuses to start.
    assert!(matches!(
        Agent::start(&socket, all_keys(), Recorder::new(true)),
        Err(AgentError::InUse(_))
    ));

    // Stopping closes open connections and removes the socket.
    let mut client = Client::connect(&socket);
    assert_eq!(client.list().len(), 3);
    agent.stop();
    assert!(!socket.exists());
    assert_eq!(client.request(&[11]), None);

    // A regular file at the path is never removed.
    fs::write(&socket, b"not a socket").unwrap();
    assert!(matches!(
        Agent::start(&socket, all_keys(), Recorder::new(true)),
        Err(AgentError::PathOccupied(_))
    ));
    assert!(socket.exists());
}

#[test]
fn skips_unusable_keys() {
    let keys = test_keys();
    let dir = TempDir::new();
    let mut encrypted = keys
        .ed25519
        .encrypt(&mut rng(), "passphrase")
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string();
    let source = Keys::with(vec![
        AgentKey {
            id: "broken".into(),
            name: "broken".into(),
            // A PEM header with no key after it. privacy:allow
            private_key_openssh: Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----".into()), // privacy:allow
        },
        AgentKey {
            id: "encrypted".into(),
            name: "encrypted".into(),
            private_key_openssh: Zeroizing::new(std::mem::take(&mut encrypted)),
        },
        agent_key("ecdsa", &keys.ecdsa),
        // The same key twice is listed once.
        agent_key("ecdsa-again", &keys.ecdsa),
    ]);
    let agent = start(&dir, source, Recorder::new(true));
    let mut client = Client::connect(agent.socket_path());
    let listed = client.list();
    assert_eq!(listed, vec![(blob(&keys.ecdsa), "ecdsa key".to_string())]);
}

// ---------------------------------------------------------------------------
// Interoperability with OpenSSH's tools

fn tool(name: &str) -> Option<PathBuf> {
    let output = Command::new("which").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    Some(PathBuf::from(path.trim()))
}

#[test]
fn openssh_tools_list_and_sign() {
    let (Some(ssh_add), Some(ssh_keygen)) = (tool("ssh-add"), tool("ssh-keygen")) else {
        println!("SKIPPED openssh_tools_list_and_sign: ssh-add or ssh-keygen is not installed");
        return;
    };
    let keys = test_keys();
    let dir = TempDir::new();
    let approver = Recorder::new(true);
    let agent = start(&dir, all_keys(), Arc::clone(&approver));
    let socket = agent.socket_path();

    // ssh-add -L lists every key, with its name as the comment.
    let output = Command::new(&ssh_add)
        .arg("-L")
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .unwrap();
    assert!(output.status.success(), "ssh-add -L: {output:?}");
    let listed = String::from_utf8(output.stdout).unwrap();
    for (id, key) in [
        ("ed25519", &keys.ed25519),
        ("ecdsa", &keys.ecdsa),
        ("rsa", &keys.rsa),
    ] {
        let public = PublicKey::new(key.public_key().key_data().clone(), format!("{id} key"));
        let line = public.to_openssh().unwrap();
        assert!(listed.lines().any(|l| l == line), "{line} not in {listed}");
    }

    // ssh-add refuses to add, remove or lock through this agent.
    let output = Command::new(&ssh_add)
        .arg("-D")
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .unwrap();
    assert!(!output.status.success(), "ssh-add -D should fail");

    // ssh-keygen -Y sign with the public key file signs through the agent;
    // ssh-keygen -Y verify checks the result.
    let message = dir.0.join("message.txt");
    fs::write(&message, b"hello from the hushjar agent test\n").unwrap();
    for (id, key) in [
        ("ed25519", &keys.ed25519),
        ("ecdsa", &keys.ecdsa),
        ("rsa", &keys.rsa),
    ] {
        let public_file = dir.0.join(format!("{id}.pub"));
        fs::write(&public_file, key.public_key().to_openssh().unwrap() + "\n").unwrap();
        let signature_file = dir.0.join("message.txt.sig");
        let _ = fs::remove_file(&signature_file);
        let before = approver.count();
        let output = Command::new(&ssh_keygen)
            .args(["-Y", "sign", "-n", "file", "-f"])
            .arg(&public_file)
            .arg(&message)
            .env("SSH_AUTH_SOCK", socket)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ssh-keygen -Y sign ({id}): {output:?}"
        );
        assert_eq!(approver.count(), before + 1);
        let request = approver.last();
        assert_eq!(request.key_id, id);
        assert_eq!(
            request.purpose,
            SignPurpose::Sshsig {
                namespace: "file".into()
            }
        );

        let allowed = dir.0.join("allowed_signers");
        fs::write(
            &allowed,
            format!("test@example {}\n", key.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        let output = Command::new(&ssh_keygen)
            .args(["-Y", "verify", "-n", "file", "-I", "test@example", "-f"])
            .arg(&allowed)
            .arg("-s")
            .arg(&signature_file)
            .stdin(fs::File::open(&message).unwrap())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ssh-keygen -Y verify ({id}): {output:?}"
        );
    }

    // A denied request makes ssh-keygen fail.
    approver.allow.store(false, Ordering::SeqCst);
    let public_file = dir.0.join("ed25519.pub");
    let _ = fs::remove_file(dir.0.join("message.txt.sig"));
    let output = Command::new(&ssh_keygen)
        .args(["-Y", "sign", "-n", "file", "-f"])
        .arg(&public_file)
        .arg(&message)
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .unwrap();
    assert!(!output.status.success(), "denied signing should fail");
}

/// Kills the child process on drop.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn openssh_login_reports_host_and_forwarding() {
    let (Some(sshd), Some(ssh)) = (tool("sshd"), tool("ssh")) else {
        println!("SKIPPED openssh_login_reports_host_and_forwarding: sshd or ssh is not installed");
        return;
    };
    let keys = test_keys();
    let dir = TempDir::new();
    let approver = Recorder::new(true);
    let agent = start(&dir, all_keys(), Arc::clone(&approver));
    let socket = agent.socket_path().to_path_buf();
    let base = dir.0.display().to_string();

    let host = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let host_file = dir.0.join("host_key");
    host.write_openssh_file(&host_file, LineEnding::LF).unwrap();
    let host_fingerprint = host.public_key().fingerprint(HashAlg::Sha256).to_string();
    let user_pub = dir.0.join("user.pub");
    fs::write(
        &user_pub,
        keys.ed25519.public_key().to_openssh().unwrap() + "\n",
    )
    .unwrap();
    fs::copy(&user_pub, dir.0.join("authorized_keys")).unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    fs::write(
        dir.0.join("known_hosts"),
        format!(
            "[127.0.0.1]:{port} {}\n",
            host.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    fs::write(
        dir.0.join("sshd_config"),
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {base}/host_key\nPidFile none\n\
             UsePAM no\nStrictModes no\nAuthorizedKeysFile {base}/authorized_keys\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\nAllowAgentForwarding yes\nLogLevel ERROR\n"
        ),
    )
    .unwrap();
    let _sshd = ChildGuard(
        Command::new(&sshd)
            .args(["-D", "-e", "-f"])
            .arg(dir.0.join("sshd_config"))
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let ready = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(50));
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
    if !ready {
        println!("SKIPPED openssh_login_reports_host_and_forwarding: sshd did not start");
        return;
    }

    let ssh_options = format!(
        "-F /dev/null -p {port} -o BatchMode=yes -o ConnectTimeout=10 \
         -o UserKnownHostsFile={base}/known_hosts -o GlobalKnownHostsFile=/dev/null \
         -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o IdentityFile={base}/user.pub"
    );
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();

    // Log in through the agent, then (with forwarding) log in again from the
    // "remote" side through the forwarded agent.
    let nested = format!("ssh {ssh_options} 127.0.0.1 echo nested-ok");
    let output = Command::new(&ssh)
        .args(ssh_options.split(' '))
        .arg("-A")
        .arg("127.0.0.1")
        .arg(nested)
        .env("SSH_AUTH_SOCK", &socket)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "ssh: {output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "nested-ok");

    let requests = approver.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2, "{requests:#?}");
    let direct = &requests[0];
    assert_eq!(direct.key_id, "ed25519");
    assert_eq!(direct.purpose, SignPurpose::Login { user: user.clone() });
    assert_eq!(direct.host.as_ref().unwrap().fingerprint, host_fingerprint);
    assert!(!direct.forwarded);
    assert!(direct.peer.exe.is_some() || cfg!(not(target_os = "linux")));

    let forwarded = &requests[1];
    assert_eq!(forwarded.purpose, SignPurpose::Login { user });
    assert!(forwarded.forwarded);
    assert_eq!(forwarded.forwarded_via.len(), 1);
    assert_eq!(forwarded.forwarded_via[0].fingerprint, host_fingerprint);
    assert_eq!(
        forwarded.host.as_ref().unwrap().fingerprint,
        host_fingerprint
    );
}
