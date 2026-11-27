//! Live updates from the server's notification hub.
//!
//! Bitwarden and Vaultwarden push vault changes to signed-in clients over an
//! ASP.NET SignalR hub at `<notifications>/hub`, using the MessagePack hub
//! protocol on a websocket. A [`Listener`] keeps one such connection open on
//! its own thread and turns the server's messages into [`Notification`]s;
//! the app reacts to [`Notification::VaultChanged`] with a (debounced) sync.
//!
//! The wire format, as Vaultwarden 1.37.3 (`src/api/notifications.rs`) and
//! Bitwarden's clients (`signalr-connection.service.ts`, which connect with
//! `skipNegotiation: true`, so there is no negotiate request) use it:
//!
//! 1. A websocket to `wss://<notifications>/hub`, authenticated with the
//!    access token as `Authorization: Bearer` (both servers accept it there
//!    as well as in an `access_token` query parameter, which would end up in
//!    server logs).
//! 2. The client sends the JSON handshake `{"protocol":"messagepack",
//!    "version":1}` followed by the record separator 0x1E as a text frame;
//!    the server answers `{}` + 0x1E (or `{"error":…}`).
//! 3. After that, every binary frame holds one or more messages, each a
//!    varint length prefix (7 bits per byte, low bits first) followed by a
//!    MessagePack array whose first element is the message type: 1 is an
//!    invocation `[1, headers, invocationId, target, arguments]`, 6 a ping
//!    `[6]` and 7 a close `[7, error, allowReconnect]`.
//! 4. Vault changes arrive as invocations of `ReceiveMessage` with one
//!    argument `{ContextId, Type, Payload}`. `ContextId` is the device
//!    identifier of the device that made the change; clients ignore their own.
//!
//! Servers drop clients that stay silent (ASP.NET's default client timeout
//! is 30 seconds), so the listener sends a hub ping every 15 seconds, and it
//! treats a connection that has been silent for a minute as lost.

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rmpv::Value as Pack;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{HandshakeError, Message, WebSocket};
use zeroize::Zeroizing;

use crate::api::Server;

/// What the server told us, reduced to what the app acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notification {
    /// Something in the vault or the account changed on another device:
    /// items, folders, Sends, organisations, their keys, policies or account
    /// settings. Also sent after a reconnect, since changes may have been
    /// missed while the connection was down. Sync to catch up.
    VaultChanged,
    /// The server ended this account's sessions, for example after a
    /// password, KDF or key change. The tokens no longer work; sign in again.
    LogOut,
    /// Another device asks to be approved for signing in ("log in with
    /// device"). `id` is the auth request to look up.
    AuthRequest { id: String },
    /// An auth request was answered.
    AuthRequestResponse { id: String },
    /// A message type Hushjar does not act on, with its number.
    Other(i64),
}

/// Bitwarden's push types, from `src/Core/Platform/Push/PushType.cs` in
/// bitwarden/server (Vaultwarden mirrors the subset it sends as
/// `UpdateType` in `src/api/notifications.rs`).
mod push_type {
    pub const SYNC_CIPHER_UPDATE: i64 = 0;
    pub const SYNC_CIPHER_CREATE: i64 = 1;
    pub const SYNC_LOGIN_DELETE: i64 = 2;
    pub const SYNC_FOLDER_DELETE: i64 = 3;
    pub const SYNC_CIPHERS: i64 = 4;
    pub const SYNC_VAULT: i64 = 5;
    pub const SYNC_ORG_KEYS: i64 = 6;
    pub const SYNC_FOLDER_CREATE: i64 = 7;
    pub const SYNC_FOLDER_UPDATE: i64 = 8;
    pub const SYNC_CIPHER_DELETE: i64 = 9;
    pub const SYNC_SETTINGS: i64 = 10;
    pub const LOG_OUT: i64 = 11;
    pub const SYNC_SEND_CREATE: i64 = 12;
    pub const SYNC_SEND_UPDATE: i64 = 13;
    pub const SYNC_SEND_DELETE: i64 = 14;
    pub const AUTH_REQUEST: i64 = 15;
    pub const AUTH_REQUEST_RESPONSE: i64 = 16;
    pub const SYNC_ORGANIZATIONS: i64 = 17;
    pub const SYNC_ORGANIZATION_STATUS_CHANGED: i64 = 18;
    pub const SYNC_ORGANIZATION_COLLECTION_SETTING_CHANGED: i64 = 19;
    pub const POLICY_CHANGED: i64 = 25;
    pub const PREMIUM_STATUS_CHANGED: i64 = 27;
}

const RECORD_SEPARATOR: u8 = 0x1e;
const HANDSHAKE: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";
/// A hub ping message: length 2, then the MessagePack array `[6]`.
const HUB_PING: [u8; 3] = [0x02, 0x91, 0x06];
/// Largest websocket message accepted. Notifications are a few hundred bytes.
const MAX_MESSAGE: usize = 1 << 20;

/// How long a single blocking socket read may take before the listener
/// checks whether it was asked to stop.
const TICK: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(15);
/// Both servers send something (a websocket or hub ping) every 15 seconds.
const SILENCE_LIMIT: Duration = Duration::from_secs(60);
const FIRST_RETRY: Duration = Duration::from_secs(3);
const LAST_RETRY: Duration = Duration::from_secs(300);
/// A connection that stayed up this long resets the retry delay.
const STABLE_AFTER: Duration = Duration::from_secs(60);
/// How long [`Listener::stop`] waits for the thread before leaving it to
/// finish its current, time-limited network call on its own.
const STOP_WAIT: Duration = Duration::from_secs(2);

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

/// State shared between a [`Listener`] and its thread.
struct Shared {
    /// True until the listener is stopped. Events are delivered while this
    /// lock is held, so once `stop` has set it to false no further event
    /// reaches the app.
    running: Mutex<bool>,
    wake: Condvar,
    status: Mutex<Status>,
    /// True while the thread is opening the TCP connection. There is nothing
    /// to close yet, so `stop` need not wait (on Windows a refused connect
    /// takes about two seconds).
    connecting: AtomicBool,
}

#[derive(Clone, Debug, Default)]
struct Status {
    connected: bool,
    problem: Option<String>,
}

impl Shared {
    fn running(&self) -> MutexGuard<'_, bool> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_running(&self) -> bool {
        *self.running()
    }

    /// Waits for `duration` or until stopped. Returns whether still running.
    fn sleep(&self, duration: Duration) -> bool {
        let guard = self.running();
        let (guard, _) = self
            .wake
            .wait_timeout_while(guard, duration, |running| *running)
            .unwrap_or_else(|e| e.into_inner());
        *guard
    }

    fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_status(&self, connected: bool, problem: Option<String>) {
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = Status { connected, problem };
    }
}

/// A background connection to the notification hub for one account.
///
/// Dropping the listener stops it, as does [`Listener::stop`].
pub struct Listener {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    finished: mpsc::Receiver<()>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("connected", &self.is_connected())
            .finish()
    }
}

impl Listener {
    /// Starts listening for `server`'s notifications on a new thread.
    ///
    /// `device_id` is this installation's device identifier (the one sent at
    /// login); changes made from it are ignored. `token` is called before
    /// every connection attempt and returns a current access token, or `None`
    /// when the account cannot get one right now (offline, or it must sign in
    /// again), in which case the listener waits and asks again later.
    /// `on_event` runs on the listener's thread; it should hand the event on
    /// (for example over a channel) and must not stop this listener itself.
    ///
    /// Failed or dropped connections are retried after 3 seconds, doubling up
    /// to 5 minutes, with some jitter.
    pub fn start(
        server: &Server,
        device_id: &str,
        token: impl Fn() -> Option<Zeroizing<String>> + Send + 'static,
        on_event: impl Fn(Notification) + Send + 'static,
    ) -> Listener {
        let shared = Arc::new(Shared {
            running: Mutex::new(true),
            wake: Condvar::new(),
            status: Mutex::new(Status::default()),
            connecting: AtomicBool::new(false),
        });
        let (finished_tx, finished) = mpsc::channel();
        let hub = hub_url(&server.notifications());
        let device_id = device_id.to_string();
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("hushjar-notifications".into())
            .spawn(move || {
                // Dropped when the thread ends, which wakes `stop`.
                let _finished = finished_tx;
                run(&thread_shared, &hub, &device_id, &token, &on_event);
                thread_shared.set_status(false, None);
            })
            .ok();
        Listener {
            shared,
            thread,
            finished,
        }
    }

    /// Whether the hub connection is currently up.
    pub fn is_connected(&self) -> bool {
        self.shared.status().connected
    }

    /// Why the last connection attempt failed or the connection ended, while
    /// it is not connected; for a status line or a tooltip.
    pub fn problem(&self) -> Option<String> {
        self.shared.status().problem
    }

    /// Stops listening. No event is delivered after this returns. Waits up to
    /// two seconds for the thread to close the connection; a thread still
    /// opening one (a time-limited connect) is left to end on its own.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        {
            let mut running = self.shared.running();
            if !*running && self.thread.is_none() {
                return;
            }
            *running = false;
        }
        self.shared.wake.notify_all();
        let Some(thread) = self.thread.take() else {
            return;
        };
        if self.shared.connecting.load(Ordering::SeqCst) {
            drop(thread);
            return;
        }
        match self.finished.recv_timeout(STOP_WAIT) {
            Err(RecvTimeoutError::Timeout) => drop(thread),
            _ => {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The websocket address of the hub below a notification service base.
fn hub_url(notifications: &str) -> String {
    let hub = format!("{}/hub", notifications.trim_end_matches('/'));
    if let Some(rest) = hub.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = hub.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        hub
    }
}

/// Doubling retry delays with jitter.
struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self { next: FIRST_RETRY }
    }

    fn reset(&mut self) {
        self.next = FIRST_RETRY;
    }

    /// The delay before the next attempt: the current step plus up to a
    /// quarter of it at random, so many clients do not retry in step.
    fn delay(&mut self) -> Duration {
        let base = self.next;
        self.next = (self.next * 2).min(LAST_RETRY);
        let random = u16::from_le_bytes(crate::crypto::random_bytes::<2>());
        base + base.mul_f64(f64::from(random) / f64::from(u16::MAX) / 4.0)
    }
}

/// Why a connection ended.
enum Ended {
    Stopped,
    Lost,
}

/// The listener thread: connect, pump messages, retry.
fn run(
    shared: &Shared,
    hub: &str,
    device_id: &str,
    token: &dyn Fn() -> Option<Zeroizing<String>>,
    on_event: &dyn Fn(Notification),
) {
    let deliver = |event: Notification| {
        let running = shared.running();
        if *running {
            on_event(event);
        }
    };
    let mut backoff = Backoff::new();
    // Whether the app's copy of the vault may be missing changes because the
    // connection was down. False at first: the app has just synced.
    let mut behind = false;
    while shared.is_running() {
        let attempt = match token() {
            Some(token) => connect(shared, hub, &token),
            None => Err(ConnectError::Failed("no access token".into())),
        };
        let (mut socket, early) = match attempt {
            Ok(connected) => connected,
            Err(ConnectError::Stopped) => break,
            Err(ConnectError::Failed(reason)) => {
                shared.set_status(false, Some(reason));
                behind = true;
                if !shared.sleep(backoff.delay()) {
                    break;
                }
                continue;
            }
        };
        shared.set_status(true, None);
        if behind {
            deliver(Notification::VaultChanged);
        }
        let started = Instant::now();
        let ended = match handle(&early, device_id, &deliver) {
            Ok(()) => pump(shared, &mut socket, device_id, &deliver),
            Err(ended) => ended,
        };
        shared.set_status(false, Some("connection lost".into()));
        let _ = socket.close(None);
        let _ = socket.flush();
        if matches!(ended, Ended::Stopped) {
            break;
        }
        behind = true;
        if started.elapsed() >= STABLE_AFTER {
            backoff.reset();
        }
        if !shared.sleep(backoff.delay()) {
            break;
        }
    }
}

#[derive(Debug)]
enum ConnectError {
    Stopped,
    Failed(String),
}

impl<E: std::fmt::Display> From<E> for ConnectError {
    fn from(error: E) -> Self {
        ConnectError::Failed(error.to_string())
    }
}

/// Opens the websocket and completes the hub handshake. Every blocking step
/// is time-limited; reads wake every [`TICK`] to check for a stop. Returns
/// the socket and any hub messages that arrived along with the reply.
fn connect(shared: &Shared, hub: &str, token: &str) -> Result<(Socket, Vec<u8>), ConnectError> {
    let mut request = hub.into_client_request()?;
    let bearer = Zeroizing::new(format!("Bearer {token}"));
    let mut auth = HeaderValue::from_str(&bearer)?;
    auth.set_sensitive(true);
    request.headers_mut().insert("Authorization", auth);
    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_str(&format!("Hushjar/{}", env!("CARGO_PKG_VERSION")))?,
    );
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| ConnectError::Failed("no host".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("wss") {
            443
        } else {
            80
        });
    let addresses: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
    shared.connecting.store(true, Ordering::SeqCst);
    let stream = addresses
        .iter()
        .find_map(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok());
    shared.connecting.store(false, Ordering::SeqCst);
    let stream = stream.ok_or_else(|| ConnectError::Failed("could not connect".into()))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(TICK))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut attempt = tungstenite::client_tls_with_config(request, stream, Some(config), None);
    let mut socket = loop {
        match attempt {
            Ok((socket, _)) => break socket,
            Err(HandshakeError::Interrupted(middle)) => {
                if !shared.is_running() {
                    return Err(ConnectError::Stopped);
                }
                if Instant::now() > deadline {
                    return Err(ConnectError::Failed("handshake timed out".into()));
                }
                attempt = middle.handshake();
            }
            Err(HandshakeError::Failure(error)) => return Err(error.into()),
        }
    };
    socket.send(Message::text(HANDSHAKE))?;
    loop {
        if !shared.is_running() {
            return Err(ConnectError::Stopped);
        }
        if Instant::now() > deadline {
            return Err(ConnectError::Failed("hub handshake timed out".into()));
        }
        let data = match socket.read() {
            Ok(Message::Text(text)) => text.as_bytes().to_vec(),
            Ok(Message::Binary(data)) => data.to_vec(),
            Ok(Message::Close(_)) => return Err(ConnectError::Failed("closed".into())),
            Ok(_) => continue,
            Err(tungstenite::Error::Io(e)) if is_timeout(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let rest = handshake_reply(&data).map_err(ConnectError::Failed)?;
        return Ok((socket, rest.to_vec()));
    }
}

/// Checks the server's handshake reply: a JSON object ended by the record
/// separator, empty on success. Returns any bytes that followed it.
fn handshake_reply(data: &[u8]) -> Result<&[u8], String> {
    let end = data
        .iter()
        .position(|b| *b == RECORD_SEPARATOR)
        .ok_or("incomplete hub handshake reply")?;
    let reply: serde_json::Value =
        serde_json::from_slice(&data[..end]).map_err(|_| "unreadable hub handshake reply")?;
    if !reply.is_object() {
        return Err("unreadable hub handshake reply".into());
    }
    if let Some(error) = crate::api::field_str(&reply, "error") {
        return Err(format!("the server refused the hub handshake: {error}"));
    }
    Ok(&data[end + 1..])
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Reads messages until the connection ends or the listener is stopped,
/// pinging the hub so the server keeps the connection.
fn pump(
    shared: &Shared,
    socket: &mut Socket,
    device_id: &str,
    deliver: &dyn Fn(Notification),
) -> Ended {
    let mut last_heard = Instant::now();
    let mut last_ping = Instant::now();
    loop {
        if !shared.is_running() {
            return Ended::Stopped;
        }
        if last_heard.elapsed() > SILENCE_LIMIT {
            return Ended::Lost;
        }
        if last_ping.elapsed() >= PING_EVERY {
            if socket.send(Message::binary(HUB_PING.to_vec())).is_err() {
                return Ended::Lost;
            }
            last_ping = Instant::now();
        }
        match socket.read() {
            Ok(Message::Binary(data)) => {
                last_heard = Instant::now();
                if let Err(ended) = handle(&data, device_id, deliver) {
                    return ended;
                }
            }
            Ok(Message::Close(_)) => return Ended::Lost,
            Ok(_) => last_heard = Instant::now(),
            Err(tungstenite::Error::Io(e)) if is_timeout(&e) => {}
            Err(_) => return Ended::Lost,
        }
    }
}

/// Delivers the events in one binary websocket message. Fails when the
/// message is malformed or the server closes the hub connection.
fn handle(data: &[u8], device_id: &str, deliver: &dyn Fn(Notification)) -> Result<(), Ended> {
    for frame in split_frames(data).ok_or(Ended::Lost)? {
        match decode(frame, device_id) {
            Incoming::Event(event) => deliver(event),
            Incoming::Close => return Err(Ended::Lost),
            Incoming::Nothing => {}
        }
    }
    Ok(())
}

/// Splits a binary websocket message into its length-prefixed hub messages.
/// Returns `None` if the lengths do not add up.
fn split_frames(mut data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut frames = Vec::new();
    while !data.is_empty() {
        let mut length: usize = 0;
        let mut used = 0;
        loop {
            let byte = *data.get(used)?;
            // At most five bytes, as in SignalR's BinaryMessageFormat.
            if used >= 5 {
                return None;
            }
            length |= usize::from(byte & 0x7f) << (7 * used);
            used += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let body = data.get(used..used.checked_add(length)?)?;
        frames.push(body);
        data = &data[used + length..];
    }
    Some(frames)
}

/// What one hub message means for the listener.
#[derive(Debug, PartialEq, Eq)]
enum Incoming {
    Event(Notification),
    Close,
    Nothing,
}

/// Decodes one hub message. Unreadable messages are skipped.
fn decode(frame: &[u8], device_id: &str) -> Incoming {
    let mut reader = frame;
    let Ok(value) = rmpv::decode::read_value_with_max_depth(&mut reader, 32) else {
        return Incoming::Nothing;
    };
    let Some(parts) = value.as_array() else {
        return Incoming::Nothing;
    };
    match parts.first().and_then(Pack::as_i64) {
        Some(1) => {
            let target = parts.get(3).and_then(Pack::as_str);
            let argument = parts
                .get(4)
                .and_then(Pack::as_array)
                .and_then(|arguments| arguments.first());
            match (target, argument) {
                (Some("ReceiveMessage"), Some(message)) => notification(message, device_id)
                    .map(Incoming::Event)
                    .unwrap_or(Incoming::Nothing),
                _ => Incoming::Nothing,
            }
        }
        Some(7) => Incoming::Close,
        _ => Incoming::Nothing,
    }
}

/// Looks a key up in a MessagePack map, ignoring case.
fn entry<'a>(map: &'a Pack, key: &str) -> Option<&'a Pack> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k.as_str().is_some_and(|k| k.eq_ignore_ascii_case(key)))
        .map(|(_, v)| v)
}

/// Turns a `ReceiveMessage` argument into a notification, or `None` when it
/// came from our own device or is malformed.
fn notification(message: &Pack, device_id: &str) -> Option<Notification> {
    let kind = entry(message, "Type")?.as_i64()?;
    if let Some(context) = entry(message, "ContextId").and_then(Pack::as_str)
        && context.eq_ignore_ascii_case(device_id)
    {
        return None;
    }
    use push_type::*;
    Some(match kind {
        SYNC_CIPHER_UPDATE
        | SYNC_CIPHER_CREATE
        | SYNC_LOGIN_DELETE
        | SYNC_FOLDER_DELETE
        | SYNC_CIPHERS
        | SYNC_VAULT
        | SYNC_ORG_KEYS
        | SYNC_FOLDER_CREATE
        | SYNC_FOLDER_UPDATE
        | SYNC_CIPHER_DELETE
        | SYNC_SETTINGS
        | SYNC_SEND_CREATE
        | SYNC_SEND_UPDATE
        | SYNC_SEND_DELETE
        | SYNC_ORGANIZATIONS
        | SYNC_ORGANIZATION_STATUS_CHANGED
        | SYNC_ORGANIZATION_COLLECTION_SETTING_CHANGED
        | POLICY_CHANGED
        | PREMIUM_STATUS_CHANGED => Notification::VaultChanged,
        // Bitwarden's clients keep the session for the KDF-change and
        // key-rotation reasons, because they can re-derive keys; Hushjar
        // cannot follow either change without the master password.
        LOG_OUT => Notification::LogOut,
        AUTH_REQUEST => Notification::AuthRequest {
            id: payload_id(message)?,
        },
        AUTH_REQUEST_RESPONSE => Notification::AuthRequestResponse {
            id: payload_id(message)?,
        },
        other => Notification::Other(other),
    })
}

/// The `Id` in a message's payload. Bitwarden's clients accept the payload
/// either as a map or as a JSON string, so both are read here.
fn payload_id(message: &Pack) -> Option<String> {
    let payload = entry(message, "Payload")?;
    if let Some(text) = payload.as_str() {
        let json: serde_json::Value = serde_json::from_str(text).ok()?;
        return crate::api::field_str(&json, "id").map(str::to_string);
    }
    entry(payload, "Id")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames a value the way Vaultwarden's `serialize` does.
    fn frame(value: &Pack) -> Vec<u8> {
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, value).unwrap();
        let mut size = body.len();
        let mut out = Vec::new();
        loop {
            let mut part = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                part |= 0x80;
            }
            out.push(part);
            if size == 0 {
                break;
            }
        }
        out.extend(body);
        out
    }

    /// A `ReceiveMessage` invocation shaped like Vaultwarden's `create_update`.
    fn update(kind: i64, context: Option<&str>, payload: Pack) -> Vec<u8> {
        frame(&Pack::Array(vec![
            1.into(),
            Pack::Map(vec![]),
            Pack::Nil,
            "ReceiveMessage".into(),
            Pack::Array(vec![Pack::Map(vec![
                ("ContextId".into(), context.map_or(Pack::Nil, Into::into)),
                ("Type".into(), kind.into()),
                ("Payload".into(), payload),
            ])]),
        ]))
    }

    fn cipher_payload() -> Pack {
        Pack::Map(vec![
            ("Id".into(), "c1".into()),
            ("UserId".into(), "u1".into()),
            ("OrganizationId".into(), Pack::Nil),
            ("CollectionIds".into(), Pack::Nil),
            // A MessagePack timestamp, as Vaultwarden sends dates.
            ("RevisionDate".into(), Pack::Ext(-1, vec![0; 8])),
        ])
    }

    fn decode_all(data: &[u8], device: &str) -> Vec<Incoming> {
        split_frames(data)
            .unwrap()
            .into_iter()
            .map(|f| decode(f, device))
            .collect()
    }

    #[test]
    fn vault_changes_from_other_devices() {
        let data = update(0, Some("other-device"), cipher_payload());
        assert_eq!(
            decode_all(&data, "my-device"),
            vec![Incoming::Event(Notification::VaultChanged)]
        );
        // No acting device, as for Sends and user-wide updates.
        let data = update(5, None, Pack::Map(vec![]));
        assert_eq!(
            decode_all(&data, "my-device"),
            vec![Incoming::Event(Notification::VaultChanged)]
        );
        for kind in [1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13, 14, 17, 18, 19, 25, 27] {
            let data = update(kind, Some("x"), Pack::Nil);
            assert_eq!(
                decode_all(&data, "my-device"),
                vec![Incoming::Event(Notification::VaultChanged)],
                "type {kind}"
            );
        }
    }

    #[test]
    fn own_changes_are_ignored() {
        let data = update(0, Some("ABC-device"), cipher_payload());
        assert_eq!(decode_all(&data, "abc-device"), vec![Incoming::Nothing]);
    }

    #[test]
    fn log_out_and_auth_requests() {
        let data = update(11, None, Pack::Map(vec![("UserId".into(), "u".into())]));
        assert_eq!(
            decode_all(&data, "d"),
            vec![Incoming::Event(Notification::LogOut)]
        );
        let payload = Pack::Map(vec![("Id".into(), "req-1".into())]);
        let data = update(15, Some("new-device"), payload.clone());
        assert_eq!(
            decode_all(&data, "d"),
            vec![Incoming::Event(Notification::AuthRequest {
                id: "req-1".into()
            })]
        );
        let data = update(16, Some("new-device"), payload);
        assert_eq!(
            decode_all(&data, "d"),
            vec![Incoming::Event(Notification::AuthRequestResponse {
                id: "req-1".into()
            })]
        );
        // A payload sent as a JSON string.
        let data = update(15, None, r#"{"id":"req-2","userId":"u"}"#.into());
        assert_eq!(
            decode_all(&data, "d"),
            vec![Incoming::Event(Notification::AuthRequest {
                id: "req-2".into()
            })]
        );
        // An auth request without an id is skipped.
        let data = update(15, None, Pack::Map(vec![]));
        assert_eq!(decode_all(&data, "d"), vec![Incoming::Nothing]);
        let data = update(22, None, Pack::Nil);
        assert_eq!(
            decode_all(&data, "d"),
            vec![Incoming::Event(Notification::Other(22))]
        );
    }

    #[test]
    fn pings_closes_and_several_messages_per_frame() {
        let mut data = HUB_PING.to_vec();
        data.extend(update(1, None, Pack::Nil));
        data.extend(frame(&Pack::Array(vec![
            1.into(),
            Pack::Map(vec![]),
            Pack::Nil,
            "Heartbeat".into(),
            Pack::Array(vec![]),
        ])));
        data.extend(frame(&Pack::Array(vec![7.into(), Pack::Nil, true.into()])));
        assert_eq!(
            decode_all(&data, "d"),
            vec![
                Incoming::Nothing,
                Incoming::Event(Notification::VaultChanged),
                Incoming::Nothing,
                Incoming::Close,
            ]
        );
    }

    #[test]
    fn long_and_broken_frames() {
        // A payload over 127 bytes needs a two-byte length prefix.
        let long = "x".repeat(300);
        let data = update(0, Some(&long), Pack::Nil);
        assert!(data[0] & 0x80 != 0);
        assert_eq!(
            decode_all(&data, "d"),
            vec![Incoming::Event(Notification::VaultChanged)]
        );
        // Truncated, an endless length prefix, and garbage.
        assert!(split_frames(&data[..data.len() - 1]).is_none());
        assert!(split_frames(&[0xff; 8]).is_none());
        assert_eq!(decode(&[0xc1], "d"), Incoming::Nothing);
        assert_eq!(decode(&[0x01], "d"), Incoming::Nothing);
        assert_eq!(split_frames(&[]), Some(vec![]));
    }

    #[test]
    fn handshake_replies() {
        assert_eq!(handshake_reply(b"{}\x1e").unwrap(), b"");
        assert_eq!(handshake_reply(b"{}\x1e\x02\x91\x06").unwrap(), &HUB_PING);
        assert!(handshake_reply(b"{\"error\":\"nope\"}\x1e").is_err());
        assert!(handshake_reply(b"{}").is_err());
        assert!(handshake_reply(b"[]\x1e").is_err());
    }

    #[test]
    fn hub_addresses() {
        assert_eq!(
            hub_url("https://notifications.bitwarden.com"),
            "wss://notifications.bitwarden.com/hub"
        );
        assert_eq!(
            hub_url("http://127.0.0.1:18281/notifications"),
            "ws://127.0.0.1:18281/notifications/hub"
        );
    }

    #[test]
    fn backoff_grows_and_resets() {
        let mut backoff = Backoff::new();
        let first = backoff.delay();
        assert!(first >= FIRST_RETRY && first <= FIRST_RETRY * 5 / 4);
        for _ in 0..20 {
            assert!(backoff.delay() <= LAST_RETRY * 5 / 4);
        }
        backoff.reset();
        assert!(backoff.delay() <= FIRST_RETRY * 5 / 4);
    }

    fn server(address: &str) -> Server {
        Server::parse(&format!("http://{address}")).unwrap()
    }

    #[test]
    fn stops_promptly_while_retrying() {
        // Nothing listens on this port, so every attempt fails at once.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed.local_addr().unwrap().to_string();
        drop(closed);
        let (tx, rx) = mpsc::channel();
        let listener = Listener::start(
            &server(&address),
            "d",
            || Some(Zeroizing::new("token".to_string())),
            move |e| tx.send(e).unwrap(),
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(!listener.is_connected());
        let started = Instant::now();
        listener.stop();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn stops_promptly_while_connecting() {
        // A documentation address (RFC 5737) that nothing answers: the
        // connect hangs, as a refused one does on Windows, or fails at once
        // where there is no route.
        let listener = Listener::start(
            &Server::parse("https://192.0.2.1:9").unwrap(),
            "d",
            || Some(Zeroizing::new("token".to_string())),
            |_| {},
        );
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        listener.stop();
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn stops_promptly_during_a_silent_handshake() {
        // A server that accepts the connection and never answers.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = silent.local_addr().unwrap().to_string();
        let accepted = std::thread::spawn(move || silent.accept().map(|(s, _)| s));
        let listener = Listener::start(
            &server(&address),
            "d",
            || Some(Zeroizing::new("token".to_string())),
            |_| {},
        );
        let _connection = accepted.join().unwrap().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn waits_for_a_token() {
        let calls = Arc::new(Mutex::new(0));
        let counted = Arc::clone(&calls);
        let listener = Listener::start(
            &server("127.0.0.1:9"),
            "d",
            move || {
                *counted.lock().unwrap() += 1;
                None
            },
            |_| {},
        );
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        listener.stop();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(*calls.lock().unwrap(), 1, "waits before asking again");
    }
}
