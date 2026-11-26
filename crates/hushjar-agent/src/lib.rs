//! An OpenSSH agent that serves SSH keys supplied by Hushjar, asking the app
//! to approve each signing request.
//!
//! The agent listens on a Unix socket (Linux and macOS) or a named pipe
//! (Windows). Programs such as `ssh`, `git` and `ssh-keygen -Y sign` find the
//! socket through `SSH_AUTH_SOCK`; Windows OpenSSH uses the pipe
//! `\\.\pipe\openssh-ssh-agent` without any setting.
//!
//! - **Keys** come from a [`KeySource`] that the agent asks on every request,
//!   so switching a key off or locking the account takes effect at once.
//! - **Every signing request** goes to the [`Approver`]. Whether the app asks
//!   the user every time or only the first time is the app's policy; this
//!   crate never remembers an approval.
//! - **Refused requests:** adding and removing keys, the agent's own
//!   lock/unlock and every extension except `session-bind@openssh.com` are
//!   answered with failure, because keys are managed in the vault.
//!
//! Only connections from processes running as the same user are served
//! (checked with the socket's peer credentials; on Windows the pipe's access
//! list admits only the user and the system).

#![forbid(unsafe_code)]

// Only the socket and pipe servers use these; on other platforms they are built (and
// unit tested) but unused.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod keys;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
mod proto;
mod server;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use zeroize::Zeroizing;

/// An SSH key the app offers to the agent.
///
/// Supported key types are Ed25519, ECDSA (P-256, P-384, P-521) and RSA
/// (2048 to 8192 bits, SHA-2 signatures only). Keys of other types, keys
/// protected by a passphrase and keys that fail to parse are left out of
/// listings and cannot sign.
#[derive(Clone)]
pub struct AgentKey {
    /// Opaque to the agent: the app's item ID. Passed back in [`SignRequest`].
    pub id: String,
    /// Shown in approval prompts, and sent as the key comment to clients
    /// (what `ssh-add -L` prints).
    pub name: String,
    /// The private key in OpenSSH's own PEM format (the "OPENSSH PRIVATE KEY"
    /// block that `ssh-keygen` writes), unencrypted, as Bitwarden stores it.
    pub private_key_openssh: Zeroizing<String>,
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("private_key_openssh", &"[redacted]")
            .finish()
    }
}

/// Supplies the keys currently on offer.
///
/// Called on a connection's thread for every listing and signing request, and
/// once more after a signing request has been approved (the key must still be
/// on offer then, or the request fails). Return only keys from unlocked
/// accounts whose **Use in SSH agent** switch is on.
pub trait KeySource: Send + Sync {
    /// The keys currently on offer. Called often; keep it cheap.
    fn keys(&self) -> Vec<AgentKey>;
}

/// The process on the other end of an agent connection, from the socket's
/// peer credentials.
///
/// `uid` is always the agent's own user (other users are turned away before
/// any request is read). `pid` comes from the kernel and is the process that
/// connected; `exe` and `cmdline` are read from `/proc` on Linux and are
/// `None` elsewhere or when the process has gone. The process may have exited
/// and its PID been reused by the time the prompt is shown, and the command
/// line is chosen by the process itself, so show them as a hint, not as proof.
/// Control characters in `cmdline` are replaced with `?`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Process ID of the connecting process, when the platform reports it.
    pub pid: Option<u32>,
    /// Effective user ID of the connecting process.
    pub uid: u32,
    /// Path of the connecting program (Linux only).
    pub exe: Option<PathBuf>,
    /// Command line of the connecting program, arguments separated by spaces
    /// (Linux only, at most 4096 bytes are read).
    pub cmdline: Option<String>,
}

/// A server host key, from OpenSSH's `session-bind@openssh.com` extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    /// OpenSSH fingerprint, `SHA256:` followed by unpadded base64.
    pub fingerprint: String,
    /// The public key in OpenSSH one-line form (`ssh-ed25519 AAAA...`), for
    /// looking the host up in `known_hosts`.
    pub public_key: String,
}

/// What the client asks to have signed, worked out from the data to sign.
///
/// The data comes from the client, so this is a description, not a
/// guarantee. Text fields have control characters replaced with `?` and are
/// cut to 256 characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignPurpose {
    /// An SSH login (`SSH_MSG_USERAUTH_REQUEST` with the `publickey` method).
    Login {
        /// The user name being logged in as on the server.
        user: String,
    },
    /// An `ssh-keygen -Y sign` signature (`SSHSIG`), as used by Git commit
    /// signing (`namespace` is `git`) and file signing (`file`).
    Sshsig {
        /// The signature namespace.
        namespace: String,
    },
    /// Anything else.
    Other,
}

/// A signing request, passed to the [`Approver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    /// [`AgentKey::id`] of the key asked for.
    pub key_id: String,
    /// [`AgentKey::name`] of the key asked for.
    pub key_name: String,
    /// The key's OpenSSH fingerprint, `SHA256:` followed by unpadded base64.
    pub fingerprint: String,
    /// The process that connected to the agent. For a forwarded agent this
    /// is the local `ssh` that carries the forwarding, not the remote program.
    pub peer: PeerInfo,
    /// The server being logged in to, when it is known.
    ///
    /// Set only when the client bound the connection to an SSH session with
    /// `session-bind@openssh.com`, the server's signature over the session ID
    /// verified with this host key, and the data to sign is a login request
    /// for that same session. It is `None` for older clients, for signatures
    /// that are not logins (Git, files) and for forwarded requests from
    /// remote clients that do not bind.
    pub host: Option<HostKey>,
    /// The request arrived through agent forwarding: the connection was bound
    /// with the forwarding flag set, so a program on a remote host is asking.
    pub forwarded: bool,
    /// The hosts the forwarded connection passed through, in order (the host
    /// the user's own `ssh` connected to first). Empty unless `forwarded`.
    pub forwarded_via: Vec<HostKey>,
    /// What the data to sign looks like.
    pub purpose: SignPurpose,
}

/// Decides whether a signing request may go ahead.
///
/// `approve` is called on the requesting connection's thread and may block
/// (for example while a prompt is shown); only that connection waits. Several
/// connections can call it at the same time, so an approver that shows one
/// prompt at a time must queue them itself. The agent never times out an
/// approval, so the approver must return `false` after its own timeout, and
/// should return `false` for waiting requests when the app stops the agent.
pub trait Approver: Send + Sync {
    /// Returns `true` to sign, `false` to refuse.
    fn approve(&self, request: &SignRequest) -> bool;
}

/// Why the agent could not start.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The agent supports Unix sockets (Linux, macOS) and Windows named
    /// pipes only.
    #[error("the SSH agent is not supported on this platform")]
    Unsupported,
    /// The socket directory is not private to the current user.
    #[error("the SSH agent socket directory {path} is unsafe: {reason}")]
    InsecureDirectory {
        /// The directory.
        path: PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// Another agent is answering on the socket path.
    #[error("another SSH agent is already listening on {0}")]
    InUse(PathBuf),
    /// Something other than a stale socket owned by this user is at the path.
    #[error("{0} exists and is not a stale SSH agent socket owned by this user")]
    PathOccupied(PathBuf),
    /// The socket path has no parent directory.
    #[error("the SSH agent socket path {0} has no parent directory")]
    BadPath(PathBuf),
    /// A file system or socket call failed.
    #[error("SSH agent socket {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// A running SSH agent. Dropping it stops the agent.
pub struct Agent {
    server: server::Server,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("socket", &self.socket_path())
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Starts listening on `socket`: a Unix socket path, or on Windows a
    /// named pipe path such as `\\.\pipe\openssh-ssh-agent` (the pipe is
    /// restricted to the current user; starting fails with
    /// [`AgentError::InUse`] when the pipe exists, for example while the
    /// Windows OpenSSH Authentication Agent service runs).
    ///
    /// For a Unix socket:
    ///
    /// The socket's directory is created with mode 0700 if it is missing; an
    /// existing directory must be owned by the current user and not be
    /// accessible to anyone else. The socket gets mode 0600. A socket already
    /// at the path is removed only when it is owned by the current user and
    /// nothing answers on it; otherwise starting fails.
    pub fn start(
        socket: &Path,
        keys: Arc<dyn KeySource>,
        approver: Arc<dyn Approver>,
    ) -> Result<Agent, AgentError> {
        server::Server::start(socket, keys, approver).map(|server| Agent { server })
    }

    /// The socket path, the value for `SSH_AUTH_SOCK`.
    pub fn socket_path(&self) -> &Path {
        self.server.socket_path()
    }

    /// Stops accepting connections, closes open ones and removes the socket
    /// file (if it is still the one this agent created). Approvals already
    /// waiting in the [`Approver`] are not interrupted; their requests fail
    /// once they return. Same as dropping the agent.
    pub fn stop(self) {}
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

/// The default socket path: `$XDG_RUNTIME_DIR/hushjar/ssh-agent.sock`.
///
/// On macOS, where `XDG_RUNTIME_DIR` is usually unset, falls back to the
/// per-user `$TMPDIR/hushjar/ssh-agent.sock`. Returns `None` when neither is
/// set to an absolute path, and on platforms the agent does not support.
///
/// On Windows it is the pipe `\\.\pipe\openssh-ssh-agent`, which OpenSSH
/// uses by default. The environment variable `HUSHJAR_SSH_AGENT_PIPE`
/// replaces it, either with a full pipe path or just a pipe name.
#[cfg(windows)]
pub fn default_socket_path() -> Option<PathBuf> {
    const PREFIX: &str = r"\\.\pipe\";
    let name = std::env::var("HUSHJAR_SSH_AGENT_PIPE")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "openssh-ssh-agent".into());
    if name.starts_with(PREFIX) {
        Some(PathBuf::from(name))
    } else {
        Some(PathBuf::from(format!("{PREFIX}{name}")))
    }
}

/// See the Windows variant above.
#[cfg(not(windows))]
pub fn default_socket_path() -> Option<PathBuf> {
    if !server::SUPPORTED {
        return None;
    }
    let absolute = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let base = absolute("XDG_RUNTIME_DIR").or_else(|| {
        if cfg!(target_os = "macos") {
            absolute("TMPDIR")
        } else {
            None
        }
    })?;
    Some(base.join("hushjar").join("ssh-agent.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn default_socket_path_ends_in_hushjar_dir() {
        if let Some(path) = default_socket_path() {
            assert!(path.is_absolute());
            assert!(path.ends_with("hushjar/ssh-agent.sock"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn default_pipe_is_the_openssh_pipe() {
        // Skips the override, which another test may set.
        if std::env::var_os("HUSHJAR_SSH_AGENT_PIPE").is_none() {
            assert_eq!(
                default_socket_path(),
                Some(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
            );
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    #[test]
    fn start_is_unsupported() {
        struct Nothing;
        impl KeySource for Nothing {
            fn keys(&self) -> Vec<AgentKey> {
                Vec::new()
            }
        }
        impl Approver for Nothing {
            fn approve(&self, _: &SignRequest) -> bool {
                false
            }
        }
        assert!(default_socket_path().is_none());
        assert!(matches!(
            Agent::start(
                Path::new("agent.sock"),
                Arc::new(Nothing),
                Arc::new(Nothing)
            ),
            Err(AgentError::Unsupported)
        ));
    }
}
