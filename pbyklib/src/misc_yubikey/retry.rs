//! Reconnect-and-retry support for YubiKey operations interrupted by a transient PC/SC failure
//!
//! On Windows a YubiKey can disappear from underneath a live handle in the middle of a long on-card
//! operation. It is most visible during RSA 3072/4096 key generation, which can run for minutes:
//! the operation comes back with a bare PC/SC error (`SCARD_W_RESET_CARD`,
//! `SCARD_E_READER_UNAVAILABLE`) and the enrollment phase fails. Restarting the phase is not an
//! option, because the one-time password that started it has been consumed and the portal-side
//! device state has already advanced, so recovery has to happen inside the phase.
//!
//! Recovery has two mechanisms, because the drop comes in two shapes. When the card is reset but
//! its reader stays present, [`YubiKey::reconnect`] restores the connection, the PIV applet
//! selection and the PIN. When the *reader* disappears — which is what a 2026-08-11 capture of a
//! spontaneous drop actually showed, `ReaderUnavailable` — that handle is dead permanently and no
//! amount of waiting revives it, so the device is reopened by its cached serial instead.
//!
//! Neither mechanism restores management key authentication: the management key is never cached in
//! the `YubiKey` struct. That is why this lives in pbyklib rather than in the yubikey crate —
//! pbyklib is where the management key is in hand — and it is also why no change to the yubikey
//! fork was required, since `open_by_serial`, `serial` and `disconnect` are all public already.
//!
//! This makes pbyk survive a drop; it does not prevent one. If the device never comes back, the
//! retries run out and the original error is returned to the caller.

use std::{thread::sleep, time::Duration};

use log::{debug, error, info, warn};

use yubikey::{MgmKey, YubiKey};

use crate::{Error, Result};

/// Number of times an interrupted operation is retried before its error is returned to the caller
///
/// Four rather than two. Two was not the safety margin it looked like: in the 2026-08-11
/// verification run, one `enroll` took two drops inside a single key generation and used both
/// retries to complete, so a third drop would have failed the phase — and that was one of only two
/// drop events observed, making it far from a corner case. A retry costs a key generation only when
/// a drop actually happens, so a higher ceiling is free in the normal case and the difference
/// between a recovered enrollment and a failed one in the bad case.
const MAX_RETRIES: u32 = 4;

/// Number of reconnect attempts made before a retry of an interrupted operation is abandoned
///
/// Eight rather than five: at five the window was thirty seconds, and a 2026-08-11 unplug test
/// exhausted it with `ReaderUnavailable` on every attempt. Thirty seconds is not much room for a
/// device to re-enumerate, and the operation being retried is a key generation that costs minutes
/// anyway, so waiting longer before giving up is close to free.
const MAX_RECONNECT_ATTEMPTS: u32 = 8;

/// Delay before the first reconnect attempt. Attempt `n` waits `n` times this value, so the eight
/// attempts span seventy-two seconds.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Returns true for the yubikey crate errors that indicate the card or the reader went away
/// underneath a live handle, i.e., the conditions that a reconnect may be able to recover from.
///
/// Errors that describe the card refusing a request (wrong PIN, security status not satisfied, and
/// so on) are deliberately absent: retrying those changes nothing, and where a PIN is involved
/// retrying burns retry counter.
///
/// `UnknownError` is included on evidence rather than theory. Pulling the YubiKey mid-keygen on
/// 2026-08-11 produced `PcscError { inner: Some(UnknownError) }` from `piv::generate`, not one of
/// the tidy variants — so the set of codes a real drop can surface as is not something to predict
/// from the names. See [card_went_away] for how the remaining unknowns are covered.
pub(crate) fn is_transient_yubikey_error(e: &yubikey::Error) -> bool {
    matches!(
        e,
        yubikey::Error::PcscError {
            inner: Some(
                pcsc::Error::ResetCard
                    | pcsc::Error::RemovedCard
                    | pcsc::Error::ReaderUnavailable
                    | pcsc::Error::NoService
                    | pcsc::Error::ServiceStopped
                    | pcsc::Error::NoSmartcard
                    | pcsc::Error::CommError
                    | pcsc::Error::UnknownError
            )
        }
    )
}

/// Returns true if the presented error wraps one of the PC/SC conditions recognized by
/// [is_transient_yubikey_error].
pub(crate) fn is_transient_pcsc_error(e: &Error) -> bool {
    match e {
        Error::YubiKey(e) => is_transient_yubikey_error(e),
        _ => false,
    }
}

/// Asks the card whether it is still there.
///
/// Not every failure carries the PC/SC error with it. The signing paths run through the cms and
/// signature crates, which discard the source error, so an interrupted signature is indistinguishable
/// from a rejected one by error value alone. Verifying the PIN is a single APDU and, when the PIN is
/// correct, resets the retry counter rather than decrementing it, which makes it a cheap and
/// harmless way to ask the question.
///
/// The test here is deliberately broader than [is_transient_yubikey_error]: **any** PC/SC-level
/// error answers "gone". Verifying a correct PIN is about as simple as a card command gets, so a
/// transport error on it means the transport is broken, whatever code came back. The first version
/// of this reused the narrow predicate and that was a mistake — a single unlisted variant then
/// disabled both the fast path and the probe meant to back it up, which is exactly what happened
/// with `UnknownError`. Errors that are not PC/SC errors (wrong PIN, blocked PIN) still answer
/// false, so a genuine refusal is still reported to the caller untouched.
fn card_went_away(yubikey: &mut YubiKey, pin: &[u8]) -> bool {
    match yubikey.verify_pin(pin) {
        Ok(()) => false,
        Err(yubikey::Error::PcscError { .. }) => true,
        Err(_) => false,
    }
}

/// Restores the connection to the YubiKey and re-establishes both PIN verification and management
/// key authentication.
///
/// Two mechanisms, tried in order:
///
/// 1. [`YubiKey::reconnect`], which re-selects the PIV applet on the existing handle and replays
///    the cached PIN. Cheap, and enough when the card was reset but its reader stayed put.
/// 2. Reopening the device by serial. Once the reader itself is gone from the resource manager the
///    handle is dead for good — `SCardReconnect` operates on that handle, so it keeps returning
///    `ReaderUnavailable` however long it is given. A 2026-08-11 capture settled this: a
///    spontaneous drop reported `ReaderUnavailable`, eight reconnects spanning 72 s all failed with
///    the same error, and the device was demonstrably usable again straight afterwards.
///
/// The PIN is verified explicitly rather than relying on `reconnect`'s cache replay, and the
/// management key is authenticated because neither path restores it.
fn reconnect_and_authenticate(yubikey: &mut YubiKey, pin: &[u8], mgmt_key: &MgmKey) -> Result<()> {
    if let Err(e) = yubikey.reconnect() {
        debug!("reconnect() failed with {e:?}. Reopening the device by serial instead.");
        reopen_by_serial(yubikey)?;
    }
    yubikey.verify_pin(pin).map_err(Error::YubiKey)?;
    yubikey.authenticate(mgmt_key).map_err(Error::YubiKey)?;
    Ok(())
}

/// Replaces `yubikey` with a fresh handle to the same physical device.
///
/// The serial comes from the handle's own cached copy, read when the device was first opened and
/// still valid after the card has gone away, so this reopens the same device rather than whichever
/// YubiKey happens to be enumerated first. `open_by_serial` leaves any non-matching YubiKey alone
/// (it disconnects those with `LeaveCard`), so other attached devices are undisturbed.
///
/// Order matters. The new handle is opened first and swapped in, then the stale one is disconnected
/// explicitly with `LeaveCard`. Letting it drop instead would disconnect with
/// `Disposition::ResetCard` — `pcsc::Card` does that in its own `Drop` — which would reset the card
/// underneath the handle just opened. Opening first also means a failed open leaves the original
/// handle in place for the caller to report against.
fn reopen_by_serial(yubikey: &mut YubiKey) -> Result<()> {
    let serial = yubikey.serial();
    let fresh = YubiKey::open_by_serial(serial).map_err(Error::YubiKey)?;
    let stale = core::mem::replace(yubikey, fresh);

    if let Err((_returned, e)) = stale.disconnect(pcsc::Disposition::LeaveCard) {
        // Expected: the reason for reopening is usually that this handle's reader is gone. The
        // handle is returned to us on failure and dropped here, which is the correct place for it
        // to die.
        debug!(
            "Disconnecting the stale YubiKey handle failed, which is expected after the reader went away: {e:?}"
        );
    }

    info!("Reopened YubiKey with serial {serial}");
    Ok(())
}

/// Makes up to [MAX_RECONNECT_ATTEMPTS] attempts to restore a usable connection to the YubiKey,
/// returning true if one of them succeeded.
fn reconnect(yubikey: &mut YubiKey, pin: &[u8], mgmt_key: &MgmKey) -> bool {
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        // Wait before each attempt, including the first. After SCARD_E_READER_UNAVAILABLE the
        // device is gone from the resource manager until the operating system re-enumerates it, so
        // for a moment there is nothing to reconnect to. This blocks the calling thread; the
        // on-card operations it sits between block that thread for minutes at a time already.
        sleep(RECONNECT_DELAY * attempt);

        match reconnect_and_authenticate(yubikey, pin, mgmt_key) {
            Ok(()) => {
                info!(
                    "Reconnected to the YubiKey on attempt {attempt} of {MAX_RECONNECT_ATTEMPTS}"
                );
                return true;
            }
            Err(e) => {
                warn!("Reconnect attempt {attempt} of {MAX_RECONNECT_ATTEMPTS} failed: {e:?}");
            }
        }
    }
    false
}

/// Runs `op`, and where it fails because the YubiKey went away, reconnects and runs it again.
///
/// `op` is retried at most [MAX_RETRIES] times and only when either the error it returned names one
/// of the PC/SC conditions in [is_transient_yubikey_error] or the card fails to answer a probe (see
/// [card_went_away]). Any other failure is returned to the caller untouched on the first attempt.
/// If the error survives the retries, or the YubiKey cannot be reconnected, the error from the most
/// recent attempt is returned.
///
/// `op` must be safe to run more than once against the same slot. Regenerating a key or re-importing
/// one overwrites whatever a partial attempt left behind, so the operations covered here qualify.
///
/// `what` names the operation for the log; it appears in both the warning that a retry is starting
/// and the error that the retries were exhausted.
pub(crate) fn retry_after_pcsc_drop<T, F>(
    yubikey: &mut YubiKey,
    pin: &[u8],
    mgmt_key: &MgmKey,
    what: &str,
    mut op: F,
) -> Result<T>
where
    F: FnMut(&mut YubiKey) -> Result<T>,
{
    let mut retries = 0;
    loop {
        let err = match op(yubikey) {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };

        if !is_transient_pcsc_error(&err) && !card_went_away(yubikey, pin) {
            return Err(err);
        }

        if retries == MAX_RETRIES {
            error!(
                "{what} did not complete after {MAX_RETRIES} reconnect-and-retry attempts. Returning the most recent error: {err:?}"
            );
            return Err(err);
        }
        retries += 1;

        warn!(
            "{what} was interrupted by a PC/SC failure ({err:?}). Reconnecting to the YubiKey to retry ({retries} of {MAX_RETRIES})."
        );

        if !reconnect(yubikey, pin, mgmt_key) {
            error!(
                "Failed to reconnect to the YubiKey after {what} was interrupted. Returning the original error: {err:?}"
            );
            return Err(err);
        }
    }
}
