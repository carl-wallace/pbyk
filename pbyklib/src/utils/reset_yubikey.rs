//! Reset YubiKey devices for enrollment with Purebred

use log::{error, info};
use rand_core::{OsRng, RngCore, TryRngCore};
use yubikey::{CccId, ChuId, MgmKey, MgmKeyOps, YubiKey};

#[cfg(target_os = "windows")]
use crate::misc_win::yubikey::cleanup_capi_yubikey;

/// Resets a given YubiKey for enrollment with Purebred
///
/// From the release of Yubikey support, users were required to take some preliminary steps to prepare their Yubikey for use
/// with the Purebred app. The point of this exercise was to put in place the management key hardcoded into the Purebred app.
/// A script was provided in the user's guide the provided a list of actions that could be taken with the yubico-piv-tool to
/// effect the necessary changes. Those actions were as follows:
///
/// ```bash
/// yubico-piv-tool -a verify-pin -P 32165498
/// yubico-piv-tool -a verify-pin -P 32165498
/// yubico-piv-tool -a verify-pin -P 32165498
/// yubico-piv-tool -a change-puk -P 12345679 -N 32165498
/// yubico-piv-tool -a change-puk -P 12345679 -N 32165498
/// yubico-piv-tool -a change-puk -P 12345679 -N 32165498
/// yubico-piv-tool -a reset
/// yubico-piv-tool -a set-chuid
/// yubico-piv-tool -a set-ccc
/// yubico-piv-tool -a set-mgm-key -n 020203040506070801020304050607080102030405060708
/// yubico-piv-tool -a change-puk -P 12345678 -N 08182025
/// yubico-piv-tool -a change-pin -P 123456 -N 08182025
/// ```
///
/// The reset_yubikey function is intended to perform the equivalent steps. In the steps above, where
/// AES management keys are desired or required, add `-m AES192` to the end of the `set-mgm-key`
/// command above. The `reset_yubikey` function will automatically use `AES192` where supported.
///
/// The caller is assumed to have enforced PIN and PUK requirements. If either the PIN or PUK fails
/// to satisfy requirements (as describe here, for example: <https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html>)
/// then the attempt to set the PIN or PUK will fail.
pub fn reset_yubikey(
    yubikey: &mut YubiKey,
    pin: &str,
    puk: &str,
    management_key: &MgmKey,
) -> yubikey::Result<()> {
    info!("Resetting YubiKey with serial {}", yubikey.serial());

    #[cfg(target_os = "windows")]
    cleanup_capi_yubikey(yubikey);

    let mut failed = 0;
    let mut value = "00000000";
    while failed < 3 {
        if yubikey.verify_pin(value.as_bytes()).is_err() {
            failed += 1;
        } else {
            value = "00000001";
        }
    }
    value = "00000000";
    failed = 0;
    while failed < 3 {
        if yubikey
            .change_puk(value.as_bytes(), value.as_bytes())
            .is_err()
        {
            failed += 1;
        } else {
            value = "00000001";
        }
    }
    let _ = yubikey.reset_device();

    if let Err(e) = yubikey.verify_pin(b"123456") {
        error!("Failed to verify using default PIN post-reset: {e:?}");
        return Err(e);
    }
    let mgmt_key = MgmKey::get_default(yubikey)?;
    if let Err(e) = yubikey.authenticate(&mgmt_key) {
        error!("Failed to authenticate using default management key post-reset: {e:?}");
        return Err(e);
    }

    /// Template value for CCC
    /// f0: Card Identifier
    ///  - 0xa000000116 == GSC-IS RID
    ///  - 0xff == Manufacturer ID (dummy)
    ///  - 0x02 == Card type (javaCard)
    ///  - next 14 bytes: card ID
    const CCC_TMPL: &[u8] = &[
        0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3,
        0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00,
        0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00,
    ];

    let mut cardid_cccid = [0u8; 14];
    OsRng.unwrap_err().fill_bytes(&mut cardid_cccid);

    let mut cccid_bytes = CCC_TMPL.to_vec();
    cccid_bytes[9..23].copy_from_slice(&cardid_cccid);
    let cccid = CccId(
        cccid_bytes
            .try_into()
            .map_err(|_| yubikey::Error::GenericError)?,
    );
    if let Err(e) = cccid.set(yubikey) {
        error!("Failed to set CccId: {e:?}");
        return Err(e);
    }

    /// Template value for CHUID
    const CHUID_TMPL: &[u8] = &[
        0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68,
        0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
    ];
    let mut cardid_chuid = [0u8; 16];
    OsRng.unwrap_err().fill_bytes(&mut cardid_chuid);

    let mut chuid_bytes = CHUID_TMPL.to_vec();
    chuid_bytes[29..45].copy_from_slice(&cardid_chuid);
    let chuid = ChuId(
        chuid_bytes
            .try_into()
            .map_err(|_| yubikey::Error::GenericError)?,
    );
    if let Err(e) = chuid.set(yubikey) {
        error!("Failed to set ChuId: {e:?}");
        return Err(e);
    }
    let _ = ChuId::get(yubikey);

    if let Err(e) = management_key.set_manual(yubikey, false) {
        error!("Failed to set management key: {e:?}");
        return Err(e);
    }
    if let Err(e) = yubikey.authenticate(management_key) {
        error!("Failed to authenticate using management key in generate_self_signed_cert: {e:?}");
        return Err(e);
    }
    if let Err(e) = yubikey.change_pin(b"123456", pin.as_bytes()) {
        error!("Failed to set new PIN: {e:?}");
        return Err(e);
    }
    if let Err(e) = yubikey.change_puk(b"12345678", puk.as_bytes()) {
        error!("Failed to set new PUK: {e:?}");
        return Err(e);
    }

    Ok(())
}
