//! Serving one agent connection.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use signature::Verifier;
use ssh_key::{HashAlg, PublicKey, Signature};
use zeroize::Zeroizing;

use crate::keys::LoadedKey;
use crate::proto::{self, DataKind, Request};
use crate::{Approver, HostKey, KeySource, PeerInfo, SignPurpose, SignRequest};

/// State shared by the accept loop and the connection threads.
pub(super) struct Shared {
    pub(super) keys: Arc<dyn KeySource>,
    pub(super) approver: Arc<dyn Approver>,
    stopping: AtomicBool,
}

impl Shared {
    pub(super) fn new(keys: Arc<dyn KeySource>, approver: Arc<dyn Approver>) -> Shared {
        Shared {
            keys,
            approver,
            stopping: AtomicBool::new(false),
        }
    }

    pub(super) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    pub(super) fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// Most `session-bind` records kept per connection (one per forwarding hop
/// plus the final login).
const MAX_BINDINGS: usize = 16;
/// Longest user name or namespace passed to the approver, in characters.
const MAX_DISPLAY_CHARS: usize = 256;

/// A verified `session-bind@openssh.com` record.
struct Binding {
    host_key_blob: Vec<u8>,
    host: HostKey,
    session_id: Vec<u8>,
    forwarding: bool,
}

/// Per-connection state.
#[derive(Default)]
struct Session {
    bindings: Vec<Binding>,
}

/// Reads requests and answers them until the client hangs up, a framing
/// error occurs or the agent stops. The caller sets up the stream's idle and
/// write time limits (VaultGoblin `internal/sshagent/server.go:78`: 60
/// seconds; waiting for approval does not count).
pub(super) fn serve<S: Read + Write>(mut stream: S, peer: &PeerInfo, shared: &Shared) {
    let mut session = Session::default();
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let Ok(len) = usize::try_from(u32::from_be_bytes(len)) else {
            return;
        };
        if len == 0 || len > proto::MAX_MESSAGE_LEN {
            return;
        }
        let mut message = Zeroizing::new(vec![0u8; len]);
        if stream.read_exact(&mut message).is_err() {
            return;
        }
        let reply = Zeroizing::new(handle(&message, &mut session, peer, shared));
        drop(message);
        if shared.stopping() {
            return;
        }
        let Ok(reply_len) = u32::try_from(reply.len()) else {
            return;
        };
        let mut framed = Zeroizing::new(Vec::with_capacity(reply.len() + 4));
        framed.extend_from_slice(&reply_len.to_be_bytes());
        framed.extend_from_slice(&reply);
        if stream.write_all(&framed).is_err() || stream.flush().is_err() {
            return;
        }
    }
}

fn handle(message: &[u8], session: &mut Session, peer: &PeerInfo, shared: &Shared) -> Vec<u8> {
    match proto::parse_request(message) {
        Ok(Request::ListIdentities) => list(shared),
        Ok(Request::Sign {
            key_blob,
            data,
            flags,
        }) => sign(key_blob, data, flags, session, peer, shared)
            .and_then(|signature| proto::sign_response(&signature).ok())
            .unwrap_or_else(proto::failure),
        Ok(Request::SessionBind {
            host_key,
            session_id,
            signature,
            forwarding,
        }) => {
            if session.bind(host_key, session_id, signature, forwarding) {
                proto::success()
            } else {
                proto::failure()
            }
        }
        Ok(Request::Refused) | Err(_) => proto::failure(),
    }
}

/// The keys on offer that parse, without duplicates.
fn loaded_keys(shared: &Shared) -> Vec<LoadedKey> {
    let mut loaded: Vec<LoadedKey> = Vec::new();
    for key in shared.keys.keys() {
        if let Some(key) = LoadedKey::load(&key)
            && !loaded.iter().any(|seen| seen.blob == key.blob)
        {
            loaded.push(key);
        }
    }
    loaded
}

fn find_key(shared: &Shared, blob: &[u8]) -> Option<LoadedKey> {
    shared
        .keys
        .keys()
        .iter()
        .filter_map(LoadedKey::load)
        .find(|key| key.blob == blob)
}

fn list(shared: &Shared) -> Vec<u8> {
    let keys = loaded_keys(shared);
    proto::identities_answer(
        keys.iter()
            .map(|key| (key.blob.as_slice(), key.name.as_str())),
    )
}

fn sign(
    key_blob: &[u8],
    data: &[u8],
    flags: u32,
    session: &Session,
    peer: &PeerInfo,
    shared: &Shared,
) -> Option<Vec<u8>> {
    if key_blob.len() > proto::MAX_KEY_BLOB_LEN
        || data.is_empty()
        || data.len() > proto::MAX_SIGN_DATA_LEN
    {
        return None;
    }
    let key = find_key(shared, key_blob)?;
    // Refuse unsupported flag combinations before bothering the user.
    let algorithm = key.algorithm(flags)?;
    let request = session.describe(&key, data, peer);
    drop(key);
    if !shared.approver.approve(&request) || shared.stopping() {
        return None;
    }
    // The key must still be on offer once the user has answered: the account
    // may have locked, or the key been switched off, while the prompt was up.
    let key = find_key(shared, key_blob).filter(|key| key.id == request.key_id)?;
    key.sign(data, algorithm)
}

fn host_key(key: &PublicKey) -> Option<HostKey> {
    Some(HostKey {
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        public_key: key.to_openssh().ok()?,
    })
}

impl Session {
    /// Records a `session-bind@openssh.com` request after checking the
    /// server's signature over the session ID with the host key.
    ///
    /// Like OpenSSH's agent, a connection already bound for a login (not for
    /// forwarding) cannot be bound again, and repeating a binding for the same
    /// session ID is accepted only with the same host key.
    fn bind(
        &mut self,
        host_key_blob: &[u8],
        session_id: &[u8],
        signature: &[u8],
        forwarding: bool,
    ) -> bool {
        if session_id.is_empty()
            || session_id.len() > proto::MAX_SESSION_ID_LEN
            || host_key_blob.len() > proto::MAX_KEY_BLOB_LEN
        {
            return false;
        }
        let Ok(key) = PublicKey::from_bytes(host_key_blob) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(signature) else {
            return false;
        };
        if key.key_data().verify(session_id, &signature).is_err() {
            return false;
        }
        if let Some(existing) = self
            .bindings
            .iter()
            .find(|binding| binding.session_id == session_id)
        {
            return existing.host_key_blob == host_key_blob;
        }
        if self.bindings.len() >= MAX_BINDINGS
            || self.bindings.last().is_some_and(|last| !last.forwarding)
        {
            return false;
        }
        let Some(host) = host_key(&key) else {
            return false;
        };
        self.bindings.push(Binding {
            host_key_blob: host_key_blob.to_vec(),
            host,
            session_id: session_id.to_vec(),
            forwarding,
        });
        true
    }

    /// Builds the request shown to the approver.
    fn describe(&self, key: &LoadedKey, data: &[u8], peer: &PeerInfo) -> SignRequest {
        let (purpose, host) = match proto::classify_sign_data(data) {
            DataKind::UserAuth { session_id, user } => {
                let host = self
                    .bindings
                    .iter()
                    .find(|binding| !binding.forwarding && binding.session_id == session_id)
                    .map(|binding| binding.host.clone());
                let user = proto::display_text(user, MAX_DISPLAY_CHARS);
                (SignPurpose::Login { user }, host)
            }
            DataKind::Sshsig { namespace } => {
                let namespace = proto::display_text(namespace, MAX_DISPLAY_CHARS);
                (SignPurpose::Sshsig { namespace }, None)
            }
            DataKind::Other => (SignPurpose::Other, None),
        };
        let forwarded_via: Vec<HostKey> = self
            .bindings
            .iter()
            .filter(|binding| binding.forwarding)
            .map(|binding| binding.host.clone())
            .collect();
        SignRequest {
            key_id: key.id.clone(),
            key_name: key.name.clone(),
            fingerprint: key.fingerprint.clone(),
            peer: peer.clone(),
            host,
            forwarded: !forwarded_via.is_empty(),
            forwarded_via,
            purpose,
        }
    }
}
