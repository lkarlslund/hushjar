//! The SSH agent wire format (draft-miller-ssh-agent, plus OpenSSH's
//! `session-bind@openssh.com` extension).
//!
//! Every message is a big-endian `uint32` length followed by that many bytes,
//! the first of which is the message number. Strings are a `uint32` length
//! followed by the bytes.
//!
//! Numbers are taken from golang.org/x/crypto v0.58.0 `ssh/agent/client.go`
//! and checked against ssh-agent-lib 0.5.1 `src/proto/message/request.rs` and
//! `response.rs`.

/// `SSH_AGENT_FAILURE` (client.go:164).
pub(crate) const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS` (client.go:168).
pub(crate) const SSH_AGENT_SUCCESS: u8 = 6;
/// `SSH_AGENTC_REQUEST_IDENTITIES` (client.go:173).
pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER` (client.go:178).
pub(crate) const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST` (client.go:186).
pub(crate) const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE` (client.go:197).
pub(crate) const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENTC_EXTENSION` (client.go:222).
pub(crate) const SSH_AGENTC_EXTENSION: u8 = 27;

/// `SSH_AGENT_RSA_SHA2_256` sign flag (client.go:40-42, `1 << 1`;
/// ssh-agent-lib `src/proto/signature.rs:5`).
pub(crate) const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
/// `SSH_AGENT_RSA_SHA2_512` sign flag (client.go:40-42, `1 << 2`;
/// ssh-agent-lib `src/proto/signature.rs:8`).
pub(crate) const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// `SSH_MSG_USERAUTH_REQUEST` (golang.org/x/crypto `ssh/messages.go:153`).
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// Start of the data signed by `ssh-keygen -Y sign` (ssh-key 0.7.0-rc.12
/// `src/sshsig.rs:56`, OpenSSH PROTOCOL.sshsig).
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// The extension that binds a connection to an SSH session.
pub(crate) const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// Largest message accepted or sent, without the length prefix. VaultGoblin
/// `internal/sshagent/server.go:86` closes the connection above this.
pub(crate) const MAX_MESSAGE_LEN: usize = 64 << 10;
/// Largest public key blob in a sign request (server.go:145).
pub(crate) const MAX_KEY_BLOB_LEN: usize = 16384;
/// Largest data to sign (server.go:145).
pub(crate) const MAX_SIGN_DATA_LEN: usize = 60 << 10;
/// Longest key comment sent in a listing (server.go:131). Longer names are
/// cut rather than failing the whole listing as VaultGoblin did.
pub(crate) const MAX_COMMENT_LEN: usize = 1024;
/// Longest session identifier accepted in `session-bind`. Session IDs are
/// key-exchange hashes, at most 64 bytes (SHA-512); this leaves room.
pub(crate) const MAX_SESSION_ID_LEN: usize = 128;

/// A message that could not be parsed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// A parsed request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request<'a> {
    ListIdentities,
    Sign {
        key_blob: &'a [u8],
        data: &'a [u8],
        flags: u32,
    },
    SessionBind {
        host_key: &'a [u8],
        session_id: &'a [u8],
        signature: &'a [u8],
        forwarding: bool,
    },
    /// Requests the agent refuses: adding and removing keys, lock, unlock,
    /// other extensions and unknown message numbers.
    Refused,
}

/// Reads SSH wire types from a byte slice.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Malformed> {
        if len > self.rest.len() {
            return Err(Malformed);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Malformed> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn string(&mut self) -> Result<&'a [u8], Malformed> {
        let len = usize::try_from(self.u32()?).map_err(|_| Malformed)?;
        self.take(len)
    }

    /// The SSH `boolean`: any non-zero byte is true (RFC 4251 section 5).
    pub(crate) fn boolean(&mut self) -> Result<bool, Malformed> {
        Ok(self.byte()? != 0)
    }

    pub(crate) fn finish(&self) -> Result<(), Malformed> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }
}

/// Parses one request (the bytes after the length prefix).
pub(crate) fn parse_request(message: &[u8]) -> Result<Request<'_>, Malformed> {
    let mut reader = Reader::new(message);
    let request = match reader.byte()? {
        SSH_AGENTC_REQUEST_IDENTITIES => Request::ListIdentities,
        SSH_AGENTC_SIGN_REQUEST => {
            let key_blob = reader.string()?;
            let data = reader.string()?;
            let flags = reader.u32()?;
            Request::Sign {
                key_blob,
                data,
                flags,
            }
        }
        SSH_AGENTC_EXTENSION => {
            if reader.string()? != SESSION_BIND {
                return Ok(Request::Refused);
            }
            let host_key = reader.string()?;
            let session_id = reader.string()?;
            let signature = reader.string()?;
            let forwarding = reader.boolean()?;
            Request::SessionBind {
                host_key,
                session_id,
                signature,
                forwarding,
            }
        }
        _ => return Ok(Request::Refused),
    };
    reader.finish()?;
    Ok(request)
}

/// Builds messages, refusing to grow past [`MAX_MESSAGE_LEN`].
pub(crate) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub(crate) fn new(message_number: u8) -> Self {
        Writer {
            bytes: vec![message_number],
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn string(&mut self, value: &[u8]) -> Result<(), Malformed> {
        let len = u32::try_from(value.len()).map_err(|_| Malformed)?;
        if self.bytes.len() + 4 + value.len() > MAX_MESSAGE_LEN {
            return Err(Malformed);
        }
        self.u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

pub(crate) fn success() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

/// `SSH_AGENT_IDENTITIES_ANSWER` for `(key blob, comment)` pairs. Identities
/// that would push the message past [`MAX_MESSAGE_LEN`] are left out.
pub(crate) fn identities_answer<'a>(
    identities: impl IntoIterator<Item = (&'a [u8], &'a str)>,
) -> Vec<u8> {
    let mut body = Writer::new(SSH_AGENT_IDENTITIES_ANSWER);
    let mut count: u32 = 0;
    for (blob, comment) in identities {
        let comment = truncate(comment, MAX_COMMENT_LEN);
        // Count field (4 bytes) is added in front below.
        if body.len() + 4 + 8 + blob.len() + comment.len() > MAX_MESSAGE_LEN {
            break;
        }
        // Cannot fail: the size was checked above.
        let _ = body.string(blob);
        let _ = body.string(comment.as_bytes());
        count += 1;
    }
    let body = body.into_bytes();
    let mut message = Vec::with_capacity(body.len() + 4);
    message.push(SSH_AGENT_IDENTITIES_ANSWER);
    message.extend_from_slice(&count.to_be_bytes());
    message.extend_from_slice(&body[1..]);
    message
}

/// `SSH_AGENT_SIGN_RESPONSE` carrying an encoded signature
/// (`string algorithm, string blob`).
pub(crate) fn sign_response(signature: &[u8]) -> Result<Vec<u8>, Malformed> {
    let mut writer = Writer::new(SSH_AGENT_SIGN_RESPONSE);
    writer.string(signature)?;
    Ok(writer.into_bytes())
}

/// Cuts `text` to at most `max` bytes at a character boundary.
pub(crate) fn truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// What the data in a sign request looks like.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DataKind<'a> {
    /// RFC 4252 section 7 `publickey` request, or OpenSSH's
    /// `publickey-hostbound-v00@openssh.com` variant.
    UserAuth {
        session_id: &'a [u8],
        user: &'a [u8],
    },
    /// OpenSSH PROTOCOL.sshsig signed data.
    Sshsig {
        namespace: &'a [u8],
    },
    Other,
}

pub(crate) fn classify_sign_data(data: &[u8]) -> DataKind<'_> {
    parse_userauth(data)
        .or_else(|_| parse_sshsig(data))
        .unwrap_or(DataKind::Other)
}

/// `string session_id, byte 50, string user, string service, string method,
/// boolean TRUE, string algorithm, string public key [, string host key]`.
fn parse_userauth(data: &[u8]) -> Result<DataKind<'_>, Malformed> {
    let mut reader = Reader::new(data);
    let session_id = reader.string()?;
    if reader.byte()? != SSH_MSG_USERAUTH_REQUEST {
        return Err(Malformed);
    }
    let user = reader.string()?;
    let _service = reader.string()?;
    let method = reader.string()?;
    if !reader.boolean()? {
        return Err(Malformed);
    }
    let _algorithm = reader.string()?;
    let _public_key = reader.string()?;
    match method {
        b"publickey" => {}
        b"publickey-hostbound-v00@openssh.com" => {
            let _host_key = reader.string()?;
        }
        _ => return Err(Malformed),
    }
    reader.finish()?;
    Ok(DataKind::UserAuth { session_id, user })
}

/// `byte[6] "SSHSIG", string namespace, string reserved, string hash
/// algorithm, string hash`.
fn parse_sshsig(data: &[u8]) -> Result<DataKind<'_>, Malformed> {
    let rest = data.strip_prefix(SSHSIG_MAGIC).ok_or(Malformed)?;
    let mut reader = Reader::new(rest);
    let namespace = reader.string()?;
    let _reserved = reader.string()?;
    let _hash_algorithm = reader.string()?;
    let _hash = reader.string()?;
    reader.finish()?;
    Ok(DataKind::Sshsig { namespace })
}

/// Text from a client made safe to show: invalid UTF-8 and control
/// characters become `?`/U+FFFD, and at most `max_chars` characters are kept.
pub(crate) fn display_text(bytes: &[u8], max_chars: usize) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(max_chars)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut message = vec![SSH_AGENTC_SIGN_REQUEST];
        message.extend(string(blob));
        message.extend(string(data));
        message.extend(flags.to_be_bytes());
        message
    }

    fn session_bind(host: &[u8], sid: &[u8], sig: &[u8], forwarding: u8) -> Vec<u8> {
        let mut message = vec![SSH_AGENTC_EXTENSION];
        message.extend(string(SESSION_BIND));
        message.extend(string(host));
        message.extend(string(sid));
        message.extend(string(sig));
        message.push(forwarding);
        message
    }

    #[test]
    fn parses_request_identities() {
        assert_eq!(parse_request(&[11]), Ok(Request::ListIdentities));
        assert_eq!(parse_request(&[11, 0]), Err(Malformed));
    }

    #[test]
    fn parses_sign_request() {
        let message = sign_request(b"blob", b"data", 4);
        assert_eq!(
            parse_request(&message),
            Ok(Request::Sign {
                key_blob: b"blob",
                data: b"data",
                flags: 4
            })
        );
    }

    #[test]
    fn rejects_truncated_sign_requests() {
        let message = sign_request(b"blob", b"data", 4);
        for len in 1..message.len() {
            assert_eq!(parse_request(&message[..len]), Err(Malformed), "len {len}");
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut message = sign_request(b"blob", b"data", 0);
        message.push(0);
        assert_eq!(parse_request(&message), Err(Malformed));
        let mut message = session_bind(b"h", b"s", b"g", 1);
        message.push(0);
        assert_eq!(parse_request(&message), Err(Malformed));
    }

    #[test]
    fn rejects_lengths_past_the_end() {
        let mut message = vec![SSH_AGENTC_SIGN_REQUEST];
        message.extend(u32::MAX.to_be_bytes());
        message.extend(b"x");
        assert_eq!(parse_request(&message), Err(Malformed));
        assert_eq!(parse_request(&[]), Err(Malformed));
    }

    #[test]
    fn parses_session_bind() {
        let message = session_bind(b"host", b"sid", b"sig", 1);
        assert_eq!(
            parse_request(&message),
            Ok(Request::SessionBind {
                host_key: b"host",
                session_id: b"sid",
                signature: b"sig",
                forwarding: true
            })
        );
        let message = session_bind(b"host", b"sid", b"sig", 0);
        assert!(matches!(
            parse_request(&message),
            Ok(Request::SessionBind {
                forwarding: false,
                ..
            })
        ));
        // Missing the forwarding flag.
        assert_eq!(parse_request(&message[..message.len() - 1]), Err(Malformed));
    }

    #[test]
    fn refuses_mutation_lock_and_other_extensions() {
        // add 17, remove 18, remove all 19, smartcard 20/21, lock 22,
        // unlock 23, add constrained 25/26 (client.go:132-142), and an
        // unknown number.
        for number in [17u8, 18, 19, 20, 21, 22, 23, 25, 26, 200] {
            assert_eq!(parse_request(&[number, 1, 2, 3]), Ok(Request::Refused));
        }
        let mut query = vec![SSH_AGENTC_EXTENSION];
        query.extend(string(b"query"));
        assert_eq!(parse_request(&query), Ok(Request::Refused));
        // An extension without a name is malformed.
        assert_eq!(parse_request(&[SSH_AGENTC_EXTENSION, 0, 0]), Err(Malformed));
    }

    #[test]
    fn identities_answer_layout() {
        let message = identities_answer([(&b"k1"[..], "one"), (&b"k2"[..], "two")]);
        let mut expected = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 2];
        expected.extend(string(b"k1"));
        expected.extend(string(b"one"));
        expected.extend(string(b"k2"));
        expected.extend(string(b"two"));
        assert_eq!(message, expected);
    }

    #[test]
    fn identities_answer_stays_within_the_limit() {
        let blob = vec![7u8; 4000];
        let comment = "é".repeat(2000);
        let many = (0..100).map(|_| (&blob[..], comment.as_str()));
        let message = identities_answer(many);
        assert!(message.len() <= MAX_MESSAGE_LEN);
        let mut reader = Reader::new(&message[1..]);
        let count = reader.u32().unwrap();
        assert!(count > 0 && count < 100);
        for _ in 0..count {
            assert_eq!(reader.string().unwrap(), &blob[..]);
            let comment = reader.string().unwrap();
            assert!(comment.len() <= MAX_COMMENT_LEN);
            assert!(std::str::from_utf8(comment).is_ok());
        }
        reader.finish().unwrap();
    }

    #[test]
    fn sign_response_respects_the_limit() {
        assert!(sign_response(&[1; 100]).is_ok());
        assert_eq!(sign_response(&vec![1; MAX_MESSAGE_LEN]), Err(Malformed));
    }

    #[test]
    fn classifies_userauth_data() {
        let mut data = string(b"session");
        data.push(SSH_MSG_USERAUTH_REQUEST);
        data.extend(string(b"git"));
        data.extend(string(b"ssh-connection"));
        data.extend(string(b"publickey"));
        data.push(1);
        data.extend(string(b"ssh-ed25519"));
        data.extend(string(b"key"));
        assert_eq!(
            classify_sign_data(&data),
            DataKind::UserAuth {
                session_id: b"session",
                user: b"git"
            }
        );
        // Truncated data is not a login.
        assert_eq!(classify_sign_data(&data[..data.len() - 1]), DataKind::Other);
    }

    #[test]
    fn classifies_hostbound_userauth_data() {
        let mut data = string(b"session");
        data.push(SSH_MSG_USERAUTH_REQUEST);
        data.extend(string(b"me"));
        data.extend(string(b"ssh-connection"));
        data.extend(string(b"publickey-hostbound-v00@openssh.com"));
        data.push(1);
        data.extend(string(b"ssh-ed25519"));
        data.extend(string(b"key"));
        data.extend(string(b"hostkey"));
        assert!(matches!(
            classify_sign_data(&data),
            DataKind::UserAuth { user: b"me", .. }
        ));
    }

    #[test]
    fn classifies_sshsig_data() {
        let mut data = b"SSHSIG".to_vec();
        data.extend(string(b"git"));
        data.extend(string(b""));
        data.extend(string(b"sha512"));
        data.extend(string(&[0; 64]));
        assert_eq!(
            classify_sign_data(&data),
            DataKind::Sshsig { namespace: b"git" }
        );
        assert_eq!(classify_sign_data(b"SSHSIG"), DataKind::Other);
        assert_eq!(classify_sign_data(b"anything"), DataKind::Other);
    }

    #[test]
    fn display_text_removes_control_characters() {
        assert_eq!(display_text(b"git\n\x1b[31mok", 256), "git??[31mok");
        assert_eq!(display_text(&[0xff, b'a'], 256), "\u{fffd}a");
        assert_eq!(display_text(b"abcdef", 3), "abc");
    }

    #[test]
    fn truncate_keeps_characters_whole() {
        assert_eq!(truncate("aé", 2), "a");
        assert_eq!(truncate("abc", 5), "abc");
    }
}
