//! End-to-end test of the Windows named pipe: start the agent on a pipe with
//! a unique name and ask it for its identities, as `ssh-add -L` would.

#![cfg(windows)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hushjar_agent::{Agent, AgentError, AgentKey, Approver, KeySource, SignRequest};
use interprocess::os::windows::named_pipe::{DuplexPipeStream, pipe_mode};

const IDENTITIES_REQUEST: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;

struct NoKeys;

impl KeySource for NoKeys {
    fn keys(&self) -> Vec<AgentKey> {
        Vec::new()
    }
}

impl Approver for NoKeys {
    fn approve(&self, _: &SignRequest) -> bool {
        false
    }
}

fn start(pipe: &Path) -> Result<Agent, AgentError> {
    Agent::start(pipe, Arc::new(NoKeys), Arc::new(NoKeys))
}

#[test]
fn lists_identities_over_the_pipe_and_refuses_a_second_agent() {
    let pipe = PathBuf::from(format!(
        r"\\.\pipe\hushjar-agent-test-{}",
        std::process::id()
    ));
    let agent = start(&pipe).unwrap();
    assert_eq!(agent.socket_path(), pipe);
    assert!(matches!(start(&pipe), Err(AgentError::InUse(_))));

    let mut client = DuplexPipeStream::<pipe_mode::Bytes>::connect_by_path(pipe.as_path()).unwrap();
    client.write_all(&[0, 0, 0, 1, IDENTITIES_REQUEST]).unwrap();
    let mut len = [0u8; 4];
    client.read_exact(&mut len).unwrap();
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    client.read_exact(&mut reply).unwrap();
    // Message type, then a key count of zero.
    assert_eq!(reply, [IDENTITIES_ANSWER, 0, 0, 0, 0]);

    drop(client);
    agent.stop();
}

#[test]
fn refuses_names_outside_the_pipe_namespace() {
    let result = start(Path::new(r"C:\temp\agent"));
    assert!(matches!(result, Err(AgentError::BadPath(_))));
}
