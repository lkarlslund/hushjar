//! The socket listener. Real on Linux and macOS, a stub elsewhere.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod connection;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod peer;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use unix::Server;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const SUPPORTED: bool = true;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) const SUPPORTED: bool = false;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use unsupported::Server;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use std::convert::Infallible;
    use std::path::Path;
    use std::sync::Arc;

    use crate::{AgentError, Approver, KeySource};

    /// Never constructed: [`Server::start`] always fails here.
    pub(crate) struct Server(Infallible);

    impl Server {
        pub(crate) fn start(
            _socket: &Path,
            _keys: Arc<dyn KeySource>,
            _approver: Arc<dyn Approver>,
        ) -> Result<Server, AgentError> {
            Err(AgentError::Unsupported)
        }

        pub(crate) fn socket_path(&self) -> &Path {
            match self.0 {}
        }

        pub(crate) fn shutdown(&mut self) {
            match self.0 {}
        }
    }
}
