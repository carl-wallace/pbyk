#![cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]

use std::ffi::CString;

use log::{error, info};
use windows::Security::Cryptography::Certificates::{Certificate, UserCertificateStore};
use windows::{Devices::SmartCards::SmartCard, Security::Cryptography::CryptographicBuffer};

use crate::{
    Result,
    misc_win::{
        cert_store::delete_cert_hashes_from_named_store, vsc_state::read_saved_state_or_default,
    },
    utils::get_vsc_id_from_serial,
};

pub async fn reset_vsc(smart_card: &SmartCard) -> Result<()> {
    info!("Resetting VSC with serial {}", smart_card.Reader()?.Name()?);

    let win_state = read_saved_state_or_default();
    if let Ok(r) = smart_card.Reader() {
        if let Ok(n) = r.Name() {
            let reader = n.to_string();
            let vsc_id = get_vsc_id_from_serial(&reader).unwrap_or_default();
            let hashes = win_state.get_hashes_for_reader(&vsc_id);

            // This code and the create_vsc function are commented out but could be revisited at some point.

            // There is no API call to delete a key from a VSC. deleting from the stores (as above) is only temporary as
            // the VSC will add them back. This will delete the card then recreate it. However, this will also not work
            // in STIG'ed environments (apparently due to treating VSCs and USB devices similarly).
            //
            // Unfortunately, these calls do not appear to work from Rust. Internet chatter relative to Xamarin suggests
            // these need to be called via a main thread API call that is not available in windows-rs. Leaving for now
            // for further research.
            //
            // info!("Deleting VSC named {n} with VSC ID {vsc_id}");
            // match SmartCardProvisioning::RequestVirtualSmartCardDeletionAsync(smart_card)?.await {
            //     Ok(b) => {
            //         info!("RequestVirtualSmartCardDeletionAsync returned {b}");
            //         let pin_policy = SmartCardPinPolicy::new().unwrap();
            //         let _ = pin_policy.SetDigits(SmartCardPinCharacterPolicyOption::Allow);
            //         let _ =
            //             pin_policy.SetLowercaseLetters(SmartCardPinCharacterPolicyOption::Allow);
            //         let _ =
            //             pin_policy.SetUppercaseLetters(SmartCardPinCharacterPolicyOption::Allow);
            //         let _ =
            //             pin_policy.SetSpecialCharacters(SmartCardPinCharacterPolicyOption::Allow);
            //         let _ = pin_policy.SetMinLength(8);
            //         info!("Creating new VSC");
            //         if let Err(e) =
            //             SmartCardProvisioning::RequestAttestedVirtualSmartCardCreationAsync(
            //                 &n,
            //                 &CryptographicBuffer::GenerateRandom(24)?,
            //                 &pin_policy,
            //             )?
            //             .await
            //         {
            //             error!("Failed to create virtual smart card: {e:?}");
            //         }
            //     }
            //     Err(e) => {
            //         error!("Failed to delete virtual smart card: {e:?}");
            //     }
            // }

            if let Ok(my) = CString::new("MY") {
                delete_cert_hashes_from_named_store(&hashes, &my).await;
            }
            // if the hashes are cleared, then reset can only work once (because subsequent enrollments will restore
            // certificates that are not present in the VSC state record).
            // win_state.clear_cert_hashes_for_reader(&vsc_id);
            // let _ = save_state(&win_state);
        }
    }
    Ok(())
}

/// Structure to enable creation of IBuffer objects necessary to create a Certificate to pass to a UserCertificateStore
pub(crate) struct CertDelete;
impl CertDelete {
    /// Attempts to delete the given certificate from the given certificate store
    pub(crate) async fn delete(cert: &[u8], cs: &UserCertificateStore) {
        match CryptographicBuffer::CreateFromByteArray(cert) {
            Ok(buffer) => match Certificate::CreateCertificate(&buffer) {
                Ok(cert_to_delete) => {
                    cs.RequestDeleteAsync(&cert_to_delete)
                        .unwrap()
                        .get()
                        .unwrap();
                }
                Err(e) => {
                    error!("Failed to create certificate from IBuffer: {e:?}");
                }
            },
            Err(e) => {
                error!("Failed to create IBuffer: {e:?}");
            }
        }
    }
}
unsafe impl Send for CertDelete {}
unsafe impl Sync for CertDelete {}
