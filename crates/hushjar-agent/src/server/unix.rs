//! The Unix socket listener and its accept loop.

use std::collections::HashMap;
use std::fs::{self, DirBuilder};
use std::io::{self, ErrorKind};
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

use super::connection;
use super::peer::{current_uid, peer_info};
use crate::{AgentError, Approver, KeySource};

/// Most connections served at once (VaultGoblin
/// `internal/sshagent/server.go:58`). Further connections are closed at once.
const MAX_CONNECTIONS: usize = 16;
/// How often the accept loop checks whether it should stop.
const POLL_INTERVAL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 200_000_000,
};

/// State shared by the accept loop and the connection threads.
pub(super) struct Shared {
    pub(super) keys: Arc<dyn KeySource>,
    pub(super) approver: Arc<dyn Approver>,
    stopping: AtomicBool,
    /// Open connections, so that stopping can shut them down.
    connections: Mutex<HashMap<u64, UnixStream>>,
    next_connection: AtomicU64,
}

impl Shared {
    pub(super) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    fn connections(&self) -> MutexGuard<'_, HashMap<u64, UnixStream>> {
        // A panicking connection thread leaves the map consistent.
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) struct Server {
    path: PathBuf,
    /// Device and inode of the socket this server created, so that shutdown
    /// removes only its own socket file.
    socket_id: (u64, u64),
    shared: Arc<Shared>,
    accept_thread: Option<JoinHandle<()>>,
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> AgentError + '_ {
    move |source| AgentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl Server {
    pub(crate) fn start(
        socket: &Path,
        keys: Arc<dyn KeySource>,
        approver: Arc<dyn Approver>,
    ) -> Result<Server, AgentError> {
        let uid = current_uid();
        let dir = socket
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .ok_or_else(|| AgentError::BadPath(socket.to_path_buf()))?;
        prepare_directory(dir, uid)?;
        remove_stale_socket(socket, uid)?;

        let listener = UnixListener::bind(socket).map_err(io_error(socket))?;
        // The directory is private, so nobody else can reach the socket
        // between bind and chmod.
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(io_error(socket))?;
        let meta = fs::symlink_metadata(socket).map_err(io_error(socket))?;
        let socket_id = (meta.dev(), meta.ino());
        listener.set_nonblocking(true).map_err(io_error(socket))?;

        let shared = Arc::new(Shared {
            keys,
            approver,
            stopping: AtomicBool::new(false),
            connections: Mutex::new(HashMap::new()),
            next_connection: AtomicU64::new(0),
        });
        let loop_shared = Arc::clone(&shared);
        let accept_thread = thread::Builder::new()
            .name("hushjar-agent-accept".into())
            .spawn(move || accept_loop(&listener, &loop_shared, uid));
        let accept_thread = match accept_thread {
            Ok(handle) => handle,
            Err(source) => {
                let _ = fs::remove_file(socket);
                return Err(AgentError::Io {
                    path: socket.to_path_buf(),
                    source,
                });
            }
        };
        Ok(Server {
            path: socket.to_path_buf(),
            socket_id,
            shared,
            accept_thread: Some(accept_thread),
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn shutdown(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        for stream in self.shared.connections().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.socket_id
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Creates the socket directory (mode 0700) or checks that the existing one
/// is a real directory owned by `uid` with no group or other access.
fn prepare_directory(dir: &Path, uid: u32) -> Result<(), AgentError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(io_error(dir))?;
        }
        Err(error) => return Err(io_error(dir)(error)),
    }
    let meta = fs::symlink_metadata(dir).map_err(io_error(dir))?;
    let insecure = |reason| AgentError::InsecureDirectory {
        path: dir.to_path_buf(),
        reason,
    };
    if !meta.file_type().is_dir() {
        return Err(insecure("not a directory (symbolic links are refused)"));
    }
    if meta.uid() != uid {
        return Err(insecure("owned by another user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(insecure("other users have access (needs mode 0700)"));
    }
    Ok(())
}

/// Removes a leftover socket from an earlier run: only a socket owned by
/// `uid` on which nothing answers.
fn remove_stale_socket(path: &Path, uid: u32) -> Result<(), AgentError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(path)(error)),
    };
    if !meta.file_type().is_socket() || meta.uid() != uid {
        return Err(AgentError::PathOccupied(path.to_path_buf()));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(AgentError::InUse(path.to_path_buf())),
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            fs::remove_file(path).map_err(io_error(path))
        }
        Err(_) => Err(AgentError::PathOccupied(path.to_path_buf())),
    }
}

fn accept_loop(listener: &UnixListener, shared: &Arc<Shared>, uid: u32) {
    while !shared.stopping() {
        let mut fds = [PollFd::new(listener, PollFlags::IN)];
        match poll(&mut fds, Some(&POLL_INTERVAL)) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => {
                thread::sleep(Duration::from_millis(200));
                continue;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => admit(stream, shared, uid),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::ConnectionAborted
                ) => {}
            // Out of file descriptors and the like: back off.
            Err(_) => thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Checks a new connection's credentials and starts its thread. Connections
/// from other users, or beyond the limit, are closed unanswered.
fn admit(stream: UnixStream, shared: &Arc<Shared>, uid: u32) {
    let Ok(peer) = peer_info(&stream) else {
        return;
    };
    if peer.uid != uid {
        return;
    }
    // Accepted sockets inherit O_NONBLOCK from the listener on macOS.
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let Ok(registered) = stream.try_clone() else {
        return;
    };
    let id = shared.next_connection.fetch_add(1, Ordering::Relaxed);
    {
        let mut connections = shared.connections();
        if connections.len() >= MAX_CONNECTIONS || shared.stopping() {
            return;
        }
        connections.insert(id, registered);
    }
    let thread_shared = Arc::clone(shared);
    let spawned = thread::Builder::new()
        .name("hushjar-agent-conn".into())
        .spawn(move || {
            connection::serve(stream, &peer, &thread_shared);
            thread_shared.connections().remove(&id);
        });
    if spawned.is_err() {
        shared.connections().remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn scratch_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("hushjar-agent-unit-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    #[test]
    fn creates_private_directory() {
        let base = scratch_dir();
        let dir = base.join("a").join("b");
        prepare_directory(&dir, current_uid()).unwrap();
        let mode = fs::metadata(&dir).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn refuses_shared_directory_and_symlink() {
        let base = scratch_dir();
        let open = base.join("open");
        DirBuilder::new().mode(0o700).create(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            prepare_directory(&open, current_uid()),
            Err(AgentError::InsecureDirectory { .. })
        ));
        let link = base.join("link");
        std::os::unix::fs::symlink(&open, &link).unwrap();
        assert!(matches!(
            prepare_directory(&link, current_uid()),
            Err(AgentError::InsecureDirectory { .. })
        ));
        assert!(matches!(
            prepare_directory(&base, current_uid() + 1),
            Err(AgentError::InsecureDirectory { .. })
        ));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn stale_socket_handling() {
        let base = scratch_dir();
        let uid = current_uid();

        // A regular file is never removed.
        let file = base.join("file.sock");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            remove_stale_socket(&file, uid),
            Err(AgentError::PathOccupied(_))
        ));
        assert!(file.exists());

        // A live socket is left alone.
        let live = base.join("live.sock");
        let listener = UnixListener::bind(&live).unwrap();
        assert!(matches!(
            remove_stale_socket(&live, uid),
            Err(AgentError::InUse(_))
        ));
        // A socket that is not ours is left alone.
        assert!(matches!(
            remove_stale_socket(&live, uid + 1),
            Err(AgentError::PathOccupied(_))
        ));
        // Once nothing listens, it is stale and removed.
        drop(listener);
        remove_stale_socket(&live, uid).unwrap();
        assert!(!live.exists());

        fs::remove_dir_all(base).unwrap();
    }
}
