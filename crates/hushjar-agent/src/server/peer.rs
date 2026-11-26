//! Peer credentials of a connected Unix socket.

use std::io;
use std::os::unix::net::UnixStream;

use crate::PeerInfo;

/// The effective user ID of this process.
pub(crate) fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Reads the connecting process's credentials from the kernel.
#[cfg(target_os = "linux")]
pub(crate) fn peer_info(stream: &UnixStream) -> io::Result<PeerInfo> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    let pid = u32::try_from(cred.pid.as_raw_pid()).ok();
    let (exe, cmdline) = match pid {
        Some(pid) => proc_details(pid),
        None => (None, None),
    };
    Ok(PeerInfo {
        pid,
        uid: cred.uid.as_raw(),
        exe,
        cmdline,
    })
}

/// Reads the connecting process's credentials from the kernel.
#[cfg(target_os = "macos")]
pub(crate) fn peer_info(stream: &UnixStream) -> io::Result<PeerInfo> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerPid};

    let (uid, _gid) = nix::unistd::getpeereid(stream)?;
    let pid = getsockopt(stream, LocalPeerPid)
        .ok()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|&pid| pid != 0);
    Ok(PeerInfo {
        pid,
        uid: uid.as_raw(),
        exe: None,
        cmdline: None,
    })
}

/// Longest command line read from `/proc`.
#[cfg(target_os = "linux")]
const MAX_CMDLINE: u64 = 4096;

#[cfg(target_os = "linux")]
fn proc_details(pid: u32) -> (Option<std::path::PathBuf>, Option<String>) {
    use std::io::Read;

    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let mut raw = Vec::new();
    let cmdline = std::fs::File::open(format!("/proc/{pid}/cmdline"))
        .and_then(|file| file.take(MAX_CMDLINE).read_to_end(&mut raw))
        .ok()
        .map(|_| {
            let args: Vec<&[u8]> = raw
                .split(|&byte| byte == 0)
                .filter(|arg| !arg.is_empty())
                .collect();
            let joined = args.join(&b' ');
            crate::proto::display_text(&joined, usize::MAX)
        })
        .filter(|cmdline| !cmdline.is_empty());
    (exe, cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_credentials() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = peer_info(&a).unwrap();
        assert_eq!(peer.uid, current_uid());
        assert_eq!(peer.pid, Some(std::process::id()));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(peer.exe, std::env::current_exe().ok());
            assert!(peer.cmdline.is_some());
        }
    }
}
