//! USB security keys through Mozilla's `authenticator` crate (the one
//! Firefox uses), built with its pure-Rust cryptography. It speaks CTAP2 and
//! falls back to CTAP1/U2F for older keys; on Linux it needs read and write
//! access to the key's `/dev/hidraw*` node, which udev grants to the logged-in
//! user for known security keys.

use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use authenticator::authenticatorservice::{AuthenticatorService, SignArgs};
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor, Transport,
    UserVerificationRequirement,
};
use authenticator::errors::AuthenticatorError;
use authenticator::statecallback::StateCallback;
use authenticator::{StatusPinUv, StatusUpdate};

use super::{Assertion, AssertionRequest, Cancel, SecurityKey, UserVerification, WebAuthnError};

/// How often the wait checks for cancellation.
const TICK: Duration = Duration::from_millis(100);

/// Any FIDO security key plugged into this computer.
#[derive(Clone, Copy, Debug, Default)]
pub struct UsbSecurityKey;

fn device_error(error: AuthenticatorError) -> WebAuthnError {
    match error {
        AuthenticatorError::CancelledByUser => WebAuthnError::Cancelled,
        other => WebAuthnError::Device(other.to_string()),
    }
}

fn sign_args(request: &AssertionRequest) -> SignArgs {
    SignArgs {
        client_data_hash: request.client_data_hash,
        origin: request.origin.clone(),
        relying_party_id: request.rp_id.clone(),
        allow_list: request
            .allow_credentials
            .iter()
            .map(|id| PublicKeyCredentialDescriptor {
                id: id.clone(),
                transports: vec![Transport::USB],
            })
            .collect(),
        user_verification_req: match request.user_verification {
            UserVerification::Discouraged => UserVerificationRequirement::Discouraged,
            UserVerification::Preferred => UserVerificationRequirement::Preferred,
            UserVerification::Required => UserVerificationRequirement::Required,
        },
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs {
            app_id: request.app_id.clone(),
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    }
}

impl SecurityKey for UsbSecurityKey {
    fn get_assertion(
        &self,
        request: &AssertionRequest,
        cancel: &Cancel,
    ) -> Result<Assertion, WebAuthnError> {
        let mut service = AuthenticatorService::new().map_err(device_error)?;
        service.add_u2f_usb_hid_platform_transports();
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (result_tx, result_rx) = channel();
        let callback = StateCallback::new(Box::new(move |result| {
            let _ = result_tx.send(result);
        }));
        let timeout_ms = request.timeout.as_millis() as u64;
        service
            .sign(timeout_ms, sign_args(request), status_tx, callback)
            .map_err(device_error)?;
        // The service gives up by itself at the timeout; the deadline here
        // only guards against it never answering.
        let started = Instant::now();
        let deadline = started + request.timeout + Duration::from_secs(5);
        let result = loop {
            while let Ok(status) = status_rx.try_recv() {
                match status {
                    // No PIN is collected here: two-step login does not ask
                    // for user verification. Dropping the sender fails the
                    // request instead of hanging.
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))
                    | StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, _)) => drop(sender),
                    StatusUpdate::SelectResultNotice(sender, _) => {
                        let _ = sender.send(Some(0));
                    }
                    _ => {}
                }
            }
            if cancel.is_cancelled() {
                let _ = service.cancel();
                return Err(WebAuthnError::Cancelled);
            }
            match result_rx.recv_timeout(TICK) {
                Ok(result) => break result,
                Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                Err(_) => {
                    let _ = service.cancel();
                    return Err(WebAuthnError::TimedOut);
                }
            }
        };
        // When the service gives up at its timeout it reports a generic
        // error; tell the user it timed out instead.
        let signed = result.map_err(|e| match e {
            AuthenticatorError::CancelledByUser => WebAuthnError::Cancelled,
            _ if started.elapsed() >= request.timeout => WebAuthnError::TimedOut,
            other => device_error(other),
        })?;
        let assertion = signed.assertion;
        // CTAP 2.0 keys may leave out the credential when only one was
        // allowed.
        let credential_id = match assertion.credentials {
            Some(c) => c.id,
            None if request.allow_credentials.len() == 1 => request.allow_credentials[0].clone(),
            None => return Err(WebAuthnError::Device("the key named no credential".into())),
        };
        Ok(Assertion {
            credential_id,
            authenticator_data: assertion.auth_data.to_vec(),
            signature: assertion.signature,
            user_handle: assertion.user.map(|u| u.id),
            used_app_id: signed.extensions.app_id.unwrap_or(false),
        })
    }
}
