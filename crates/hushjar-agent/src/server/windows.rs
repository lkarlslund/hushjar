//! The Windows named pipe listener, serving the same protocol as the Unix
//! socket. Windows OpenSSH talks to `\\.\pipe\openssh-ssh-agent`.
//!
//! Unlike a Unix socket, a pipe has no read timeout and its blocking reads
//! cannot be interrupted, so every pipe here is in non-blocking mode and
//! polled in short steps. That is how the idle limit and stopping work.

use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use interprocess::os::windows::named_pipe::{DuplexPipeStream, PipeListenerOptions, pipe_mode};
use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use widestring::U16CString;

use super::connection::{self, Shared};
use crate::{AgentError, Approver, KeySource, PeerInfo};

/// Most connections served at once, as on Unix.
const MAX_CONNECTIONS: usize = 16;
/// How long a connection may sit between messages, or take to send one.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// How often the accept loop and idle connections look again.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Only the user who runs the agent (the pipe's owner) and the system may
/// open the pipe. The default descriptor would let every user read it.
const PIPE_ACL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";
/// Where named pipes live.
const PIPE_PREFIX: &str = r"\\.\pipe\";

type Pipe = DuplexPipeStream<pipe_mode::Bytes>;

pub(crate) struct Server {
    path: PathBuf,
    shared: Arc<Shared>,
    accept_thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Starts listening on the pipe named by `pipe`, a path such as
    /// `\\.\pipe\openssh-ssh-agent`.
    pub(crate) fn start(
        pipe: &Path,
        keys: Arc<dyn KeySource>,
        approver: Arc<dyn Approver>,
    ) -> Result<Server, AgentError> {
        let io_error = |source| AgentError::Io {
            path: pipe.to_path_buf(),
            source,
        };
        let named = pipe
            .to_str()
            .is_some_and(|name| name.len() > PIPE_PREFIX.len() && starts_with_prefix(name));
        if !named {
            return Err(AgentError::BadPath(pipe.to_path_buf()));
        }
        let acl = U16CString::from_str(PIPE_ACL).map_err(|e| io_error(io::Error::other(e)))?;
        let descriptor = SecurityDescriptor::deserialize(&acl).map_err(io_error)?;
        // Creating the first instance fails when a pipe of that name exists:
        // another agent, such as the Windows OpenSSH service, is running.
        let listener = PipeListenerOptions::new()
            .path(pipe)
            .nonblocking(true)
            .security_descriptor(Some(descriptor))
            .create_duplex::<pipe_mode::Bytes>()
            .map_err(|error| match error.kind() {
                ErrorKind::PermissionDenied | ErrorKind::AlreadyExists => {
                    AgentError::InUse(pipe.to_path_buf())
                }
                _ => io_error(error),
            })?;

        let shared = Arc::new(Shared::new(keys, approver));
        let loop_shared = Arc::clone(&shared);
        let active = Arc::new(AtomicUsize::new(0));
        let accept_thread = thread::Builder::new()
            .name("hushjar-agent-accept".into())
            .spawn(move || {
                while !loop_shared.stopping() {
                    match listener.accept() {
                        Ok(pipe) => admit(pipe, &loop_shared, &active),
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(POLL_INTERVAL);
                        }
                        Err(_) => thread::sleep(Duration::from_millis(200)),
                    }
                }
            })
            .map_err(io_error)?;
        Ok(Server {
            path: pipe.to_path_buf(),
            shared,
            accept_thread: Some(accept_thread),
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.path
    }

    /// Stops accepting; open connections notice within one poll step and end.
    pub(crate) fn shutdown(&mut self) {
        self.shared.stop();
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

/// Whether `name` starts with `\\.\pipe\`, ignoring case.
fn starts_with_prefix(name: &str) -> bool {
    name.get(..PIPE_PREFIX.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(PIPE_PREFIX))
}

/// Looks up who connected and starts the connection's thread. Connections
/// beyond the limit are closed unanswered.
fn admit(pipe: Pipe, shared: &Arc<Shared>, active: &Arc<AtomicUsize>) {
    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        active.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let peer = peer_info(&pipe);
    let shared = Arc::clone(shared);
    let counter = Arc::clone(active);
    let spawned = thread::Builder::new()
        .name("hushjar-agent-conn".into())
        .spawn(move || {
            let polled = Polled {
                pipe,
                shared: &shared,
            };
            connection::serve(polled, &peer, &shared);
            counter.fetch_sub(1, Ordering::SeqCst);
        });
    if spawned.is_err() {
        active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The connecting process, from the pipe's client process ID.
///
/// `uid` is 0: Windows has no user ID of this kind, and the pipe's access
/// list already keeps other users out.
fn peer_info(pipe: &Pipe) -> PeerInfo {
    let pid = pipe.client_process_id().ok().filter(|&pid| pid != 0);
    let (exe, cmdline) = pid.map_or((None, None), process_details);
    PeerInfo {
        pid,
        uid: 0,
        exe,
        cmdline,
    }
}

/// The executable path and command line of process `pid`, when readable.
fn process_details(pid: u32) -> (Option<PathBuf>, Option<String>) {
    let pid = Pid::from_u32(pid);
    let Ok(mut system) = System::new() else {
        return (None, None);
    };
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always),
    );
    let Some(process) = system.process(pid) else {
        return (None, None);
    };
    let exe = process.exe().map(Path::to_path_buf);
    let args: Vec<String> = process
        .cmd()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let cmdline = crate::proto::display_text(args.join(" ").as_bytes(), usize::MAX);
    (exe, Some(cmdline).filter(|cmdline| !cmdline.is_empty()))
}

/// A non-blocking pipe that waits by polling, giving up after
/// [`IO_TIMEOUT`] or when the agent stops.
struct Polled<'a> {
    pipe: Pipe,
    shared: &'a Shared,
}

impl Polled<'_> {
    /// Runs `operation` until it does more than report `WouldBlock`.
    fn wait<T>(&mut self, mut operation: impl FnMut(&mut Pipe) -> io::Result<T>) -> io::Result<T> {
        let started = Instant::now();
        loop {
            match operation(&mut self.pipe) {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                other => return other,
            }
            if self.shared.stopping() {
                return Err(ErrorKind::ConnectionAborted.into());
            }
            if started.elapsed() > IO_TIMEOUT {
                return Err(ErrorKind::TimedOut.into());
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Read for Polled<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.wait(|pipe| pipe.read(buf))
    }
}

impl Write for Polled<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.wait(|pipe| pipe.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.wait(|pipe| pipe.flush())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_pipe_names() {
        assert!(starts_with_prefix(r"\\.\pipe\openssh-ssh-agent"));
        assert!(starts_with_prefix(r"\\.\PIPE\x"));
        assert!(!starts_with_prefix(r"C:\temp\agent"));
        assert!(!starts_with_prefix("agent"));
    }

    #[test]
    fn reads_own_process_details() {
        let (exe, _) = process_details(std::process::id());
        assert_eq!(exe, std::env::current_exe().ok());
    }
}
