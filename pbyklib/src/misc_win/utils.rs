//! Utility functions for working with virtual smart cards (VSCs) on Windows systems

#![cfg(all(target_os = "windows", feature = "vsc"))]

use std::{io::Cursor, sync::Mutex};

use log::{debug, error, info};
use windows::{
    Devices::SmartCards::SmartCard,
    Security::Cryptography::{
        Certificates::{
            CertificateEnrollmentManager, CertificateRequestProperties, EnrollKeyUsages,
            ExportOption, InstallOptions, KeyAlgorithmNames, KeyProtectionLevel,
            PfxImportParameters,
        },
        CryptographicBuffer,
    },
    Win32::Security::Cryptography::{
        BCRYPT_PAD_PKCS1, CERT_KEY_SPEC, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
        NCryptDecrypt, NCryptOpenKey, NCryptOpenStorageProvider,
    },
    core::{HSTRING, PCWSTR},
};

use base64ct::{Base64, Encoding};
use cipher::{BlockModeDecrypt, KeyIvInit};
use cms::{
    content_info::ContentInfo,
    enveloped_data::{EnvelopedData, RecipientInfo},
};
use der::{Decode, Encode, asn1::OctetString};

#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use crate::misc_win::scep::get_vsc_id_from_smartcard;
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use crate::misc_win::vsc_state::{read_saved_state_or_default, save_state};
use certval::PDVCertificate;
use der::zeroize::Zeroizing;
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use pbykcorelib::misc::utils::buffer_to_hex;
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::misc_win::cert_store::delete_cert_from_store;
use crate::misc_win::csr::consume_attested_csr;
use crate::{
    Error, Result,
    misc::p12::process_p12,
    misc_win::{
        csr::{
            consume_csr, get_credential_list, get_key_provider_info, prepare_base64_certs_only_p7,
            resign_as_self,
        },
        scep::process_scep_payload_vsc,
        vsc_signer::CertContext,
    },
};
use pbykcorelib::misc::utils::{get_as_string, purebred_authorize_request};

//------------------------------------------------------------------------------------
// Global variable
//------------------------------------------------------------------------------------
/// Attestation support works inconsistently. It appears to require elevation. Thus, if we try and fail we can
/// make note of that in a run-time variable.
pub static GAMBLE_ON_ATTESTATION: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(true));

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Returns true if both the global GAMBLE_ON_ATTESTATION and provided with_attestation are true, else false.
/// If mutex on GAMBLE_ON_ATTESTATION cannot be obtained, a log message is generated and with_attestation is returned.
fn gamble_on_attestation(with_attestation: bool) -> bool {
    match GAMBLE_ON_ATTESTATION.lock() {
        Ok(v) => {
            if *v && with_attestation {
                debug!("Attestation generation support enabled");
                true
            } else {
                debug!("Attestation generation support disabled");
                false
            }
        }
        Err(e) => {
            error!("Failed to read value in gamble_on_attestation: {e:?}");
            with_attestation
        }
    }
}

/// Sets GAMBLE_ON_ATTESTATION to false
fn attestation_does_not_work() {
    match GAMBLE_ON_ATTESTATION.lock() {
        Ok(mut v) => {
            if *v {
                *v = false;
                info!("Disabled attestation generation support");
            }
        }
        Err(e) => {
            error!("Failed to read value in attestation_does_not_work: {e:?}");
        }
    }
}

/// Takes a [CertContext] notionally containing public key used to encrypt the provided `ciphertext` and returns the
/// plaintext if the corresponding private key can be found and decryption is successful. Currently only supports RSA keys.
fn asym_decrypt(cred: &CertContext, ciphertext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let kpi_wrapper = match get_key_provider_info(cred) {
            Ok(kpi_wrapper) => kpi_wrapper,
            Err(e) => {
                error!("Failed to get CRYPT_KEY_PROV_INFO for CERT_CONTEXT in asym_decrypt: {e:?}");
                return Err(e);
            }
        };
        let container_name = kpi_wrapper.get_container_name()?;
        let provider_name = kpi_wrapper.get_provider_name()?;

        // open the storage provider associated with the provided credential
        let prov_handle = &mut NCRYPT_PROV_HANDLE(0) as *mut NCRYPT_PROV_HANDLE;
        if let Err(e) =
            NCryptOpenStorageProvider(prov_handle, PCWSTR::from_raw(provider_name.as_ptr()), 0)
        {
            error!("NCryptOpenStorageProvider failed in asym_decrypt: {e:?}");
            return Err(e.into());
        }

        // open the key associated with the provided credential
        let key_handle = &mut NCRYPT_KEY_HANDLE(0) as *mut NCRYPT_KEY_HANDLE;
        if let Err(e) = NCryptOpenKey(
            *prov_handle,
            key_handle,
            PCWSTR::from_raw(container_name.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ) {
            error!("NCryptOpenKey failed in asym_decrypt: {e:?}");
            return Err(e.into());
        }

        let mut plaintext_len = 0;
        if let Err(e) = NCryptDecrypt(
            *key_handle,
            Some(ciphertext),
            None,
            None,
            &mut plaintext_len,
            NCRYPT_FLAGS(BCRYPT_PAD_PKCS1.0),
        ) {
            error!("NCryptDecrypt failed to determine length in asym_decrypt: {e:?}");
            return Err(e.into());
        }
        let mut plaintext = vec![0u8; plaintext_len as usize];
        if let Err(e) = NCryptDecrypt(
            *key_handle,
            Some(ciphertext),
            None,
            Some(&mut plaintext),
            &mut plaintext_len,
            NCRYPT_FLAGS(BCRYPT_PAD_PKCS1.0),
        ) {
            error!("NCryptDecrypt failed in asym_decrypt: {e:?}");
            return Err(e.into());
        }
        Ok(plaintext)
    }
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Generates a fresh CSR using [CertificateEnrollmentManager::UserCertificateEnrollmentManager::CreateRequestAsync](https://microsoft.github.io/windows-docs-rs/doc/windows/Security/Cryptography/Certificates/struct.UserCertificateEnrollmentManager.html#method.CreateRequestAsync).
///
/// The CSR will be generating using the indicate SmartCard object and will feature the provided subject name. If with_attestation is true,
/// the request will be generated using the embedded privacy CA certificate as the attestation credential certificate. If
/// container_name is present, the request will be generated using the existing key pair identified by container_name.
pub(crate) async fn generate_csr(
    subject_name: &str,
    sc: &SmartCard,
    with_attestation: bool,
    container_name: Option<HSTRING>,
    friendly_name: &str,
) -> Result<String> {
    let h_subject_name = HSTRING::from(subject_name);

    // Generate a new key pair using the selected virtual smart card. This will result in a CSR that we do not need.
    let request = CertificateRequestProperties::new()?;
    request.SetFriendlyName(&HSTRING::from(friendly_name))?;
    request.SetKeyAlgorithmName(&KeyAlgorithmNames::Rsa()?)?;
    request
        .SetKeyStorageProviderName(&HSTRING::from("Microsoft Smart Card Key Storage Provider"))?;
    request.SetExportable(ExportOption::NotExportable)?;
    request.SetSubject(&h_subject_name)?;
    request.SetKeyUsages(EnrollKeyUsages::All)?;
    request.SetSmartcardReaderName(&sc.Reader()?.Name()?)?;

    if let Some(container_name) = container_name {
        info!("Generating certificate request for existing key pair");
        request.SetUseExistingKey(true)?;
        request.SetContainerName(&container_name)?;
    } else {
        request.SetUseExistingKey(false)?;
        if with_attestation {
            info!("Requesting attestation for generated key pair");
            let privacy_ca_bytes = include_bytes!("../../assets/privacy_ca.der");
            let buffer = CryptographicBuffer::CreateFromByteArray(privacy_ca_bytes)?;
            let privacy_ca_cert =
                windows::Security::Cryptography::Certificates::Certificate::CreateCertificate(
                    &buffer,
                )?;
            request.SetAttestationCredentialCertificate(&privacy_ca_cert)?;
        } else {
            info!("Not requesting attestation for generated key pair");
        }
    }

    match CertificateEnrollmentManager::UserCertificateEnrollmentManager()?
        .CreateRequestAsync(&request)?
        .get()
    {
        Ok(csr) => Ok(csr.to_string()),
        Err(e) => {
            error!("Failed to generate request in generate_csr: {e:?}");
            Err(Error::Vsc)
        }
    }
}

/// Performs a series of bizarre steps to arrive at a self-signed certificate with corresponding attestation.
///
/// The Windows APIs for generating attested key pairs yield a CSR that is not useful in the Purebred context. The keys
/// resulting from CSR generation cannot be used (for example, to sign another request or a self-signed certificate)
/// until after the CSR generation process is completed by installing a certificate. To get around this, `pbyk` follows
/// the process used in the Purebred app for UWP and generates a fake certificate using an embedded CA key. After installing
/// the resulting fake certificate, a self-signed certificate is generated.
///
/// Upon success, a tuple containing the self-signed certificate (in binary DER-encoded form) and, optionally, a base-64
/// encoded CSR that represents an attestation is returned.
pub(crate) async fn generate_self_signed_cert_vsc(
    subject_name: &str,
    sc: &SmartCard,
) -> Result<(Vec<u8>, Option<String>)> {
    debug!(
        "Attempting to generate a fresh key pair with attestation in generate_self_signed_cert_vsc for {subject_name}"
    );

    let with_attestation = gamble_on_attestation(true);

    // generate a fresh key pair (which will yield a CSR we don't want but must use and an attestation)
    let (csr_to_consume, attestation) = match generate_csr(
        subject_name,
        sc,
        with_attestation,
        None,
        "Purebred Self-Signed Device Certificate",
    )
    .await
    {
        Ok(csr_to_consume) => {
            if with_attestation {
                (csr_to_consume.clone(), Some(csr_to_consume))
            } else {
                (csr_to_consume.clone(), None)
            }
        }
        Err(e) => {
            if gamble_on_attestation(true) {
                attestation_does_not_work();
                debug!(
                    "Attempting to generate a fresh key pair without attestation in generate_self_signed_cert_vsc after an attempt with attestation failed with: {e:?}"
                );
                (
                    generate_csr(
                        subject_name,
                        sc,
                        false,
                        None,
                        "Purebred Self-Signed Device Certificate",
                    )
                    .await?,
                    None,
                )
            } else {
                return Err(e);
            }
        }
    };

    debug!("Generating fake certificate in generate_self_signed_cert_vsc");
    // The generated key (apparently) cannot be used until the request is completed, so generate a fake cert and install it.
    let (b64_fake_cert_as_p7, fake_cert) = if attestation.is_some() {
        consume_attested_csr(&csr_to_consume.to_string()).await?
    } else {
        consume_csr(&csr_to_consume.to_string()).await?
    };
    if let Err(e) = CertificateEnrollmentManager::UserCertificateEnrollmentManager()?
        .InstallCertificateAsync(
            &HSTRING::from(b64_fake_cert_as_p7),
            InstallOptions::DeleteExpired,
        )?
        .get()
    {
        error!("Failed to install fake certificate in generate_self_signed_cert_vsc: {e:?}");
        return Err(Error::Unrecognized);
    }

    debug!("Searching for fresh credential in generate_self_signed_cert_vsc");
    // Using the fake certificate, read the certificate from the MY store and use the corresponding key to sign a self-signed certificate
    let creds = get_credential_list(Some(PDVCertificate::try_from(fake_cert.clone())?))?;
    debug!(
        "Found {} matching credentials in generate_self_signed_cert_vsc",
        creds.len()
    );

    // there ought not be > 1 credential, but even if there is the private key ought to be the same so just use the first one
    match creds.first() {
        Some(cred) => {
            debug!("Generating self-signed certificate in generate_self_signed_cert_vsc");
            let self_signed = resign_as_self(&fake_cert, cred)?;

            #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
            let mut win_state = read_saved_state_or_default();
            #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
            let reader = get_vsc_id_from_smartcard(sc);

            #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
            if !reader.is_empty() {
                if let Ok(der_cert) = self_signed.to_der() {
                    let hash = Sha256::digest(der_cert);
                    let hex_hash = buffer_to_hex(&hash);
                    win_state.add_cert_hash_for_reader(&reader, &hex_hash);
                    let _ = save_state(&win_state);
                }
            }

            let container_name = get_key_provider_info(cred)?.get_container_name()?;

            // generate a new CSR for the existing key, so we can try to install the self-signed certificate
            let _csr_to_discard = generate_csr(
                subject_name,
                sc,
                false,
                Some(container_name.clone()),
                "Purebred Self-Signed Device Certificate",
            )
            .await?;

            let ss_p7 = prepare_base64_certs_only_p7(&self_signed)?;
            if let Err(e) = CertificateEnrollmentManager::UserCertificateEnrollmentManager()?
                .InstallCertificateAsync(&HSTRING::from(ss_p7), InstallOptions::DeleteExpired)?
                .get()
            {
                error!(
                    "Failed to install self-signed certificate in generate_self_signed_cert_vsc: {e:?}"
                );
                return Err(Error::Unrecognized);
            }

            // delete the fake cert from the certificate store
            let fake_cert_der = fake_cert.to_der()?;
            delete_cert_from_store(&fake_cert_der);

            // The below stuff works when not built with gui feature but will not compile when gui feature is elected (hence using the loop above).
            // See https://github.com/microsoft/windows-rs/issues/2800.
            // let user_store = CertificateStores::GetUserStoreByName(&HSTRING::from("MY")).unwrap();
            // let ca_store = CertificateStores::GetUserStoreByName(&HSTRING::from("CA")).unwrap();
            //
            // let buffer = CryptographicBuffer::CreateFromByteArray(&fake_cert_der).unwrap();
            // let cert_to_delete =
            //     windows::Security::Cryptography::Certificates::Certificate::CreateCertificate(
            //         &buffer,
            //     )
            //     .unwrap();
            // if let Err(e) = user_store
            //     .RequestDeleteAsync(&cert_to_delete)
            //     .unwrap()
            //     .await
            // {
            //     error!("Failed to delete fake certificate from MY store: {e:?}");
            // }
            // if let Err(e) = ca_store.RequestDeleteAsync(&cert_to_delete).unwrap().await {
            //     error!("Failed to delete fake certificate from CA store: {e:?}");
            // }

            Ok((self_signed.to_der()?, attestation))
        }
        None => {
            error!(
                "Failed to retrieve credential for freshly generated key pair in generate_self_signed_cert_vsc"
            );
            Err(Error::Unrecognized)
        }
    }
}

/// Installs a private key and certificate extracted from a password-protected PKCS #12 object into the provided SmartCard and
/// returns the certificate from the PKCS #12.
///
/// # Arguments
/// * `smart_card` - `SmartCard` object to receive the private key
/// * `enc_p12` - Binary DER-encoded PKCS #12 object
/// * `password` - Password used to decrypt the PKCS #12 object
/// * `friendly_name` - Friendly name of the PKCS #12 object
pub(crate) async fn import_p12_vsc(
    smart_card: &SmartCard,
    enc_p12: &[u8],
    password: &str,
    friendly_name: &str,
) -> Result<Vec<u8>> {
    let provider_name = HSTRING::from("Microsoft Smart Card Key Storage Provider");
    let friendly_name_h = HSTRING::from(friendly_name);
    let pfx_import_parameters = PfxImportParameters::new()?;
    let _ = pfx_import_parameters.SetFriendlyName(&friendly_name_h);
    let _ = pfx_import_parameters.SetKeyStorageProviderName(&provider_name);
    let _ = pfx_import_parameters.SetReaderName(&smart_card.Reader()?.Name()?);

    let base64_pkcs12 = Base64::encode_string(enc_p12);
    let base64_pkcs12_h = HSTRING::from(base64_pkcs12);
    if let Err(e) = CertificateEnrollmentManager::UserCertificateEnrollmentManager()?
        .ImportPfxDataToKspWithParametersAsync(
            &base64_pkcs12_h,
            &HSTRING::from(password),
            &pfx_import_parameters,
        )?
        .get()
    {
        error!(
            "Failed to install PKCS #12 object into SmartCard: {e:?}. Trying to install into software module."
        );
        CertificateEnrollmentManager::UserCertificateEnrollmentManager()?
            .ImportPfxDataToKspAsync(
                &base64_pkcs12_h,
                &HSTRING::from(password),
                ExportOption::NotExportable,
                KeyProtectionLevel::NoConsent,
                InstallOptions::None,
                &friendly_name_h,
                &provider_name,
            )?
            .get()?;
    }

    let (der_cert, _) = process_p12(enc_p12, password, false)?;

    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    let mut win_state = read_saved_state_or_default();
    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    let reader = crate::misc_win::scep::get_vsc_id_from_smartcard(smart_card);
    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    if !reader.is_empty() {
        let hash = Sha256::digest(&der_cert);
        let hex_hash = buffer_to_hex(&hash);
        win_state.add_cert_hash_for_reader(&reader, &hex_hash);
        let _ = save_state(&win_state);
    }

    info!("Installed PKCS #12 object into VSC");
    Ok(der_cert)
}

/// Verifies a signature on an outer SignedData object, then decrypts and returns content from the wrapped EnvelopedData.
pub(crate) async fn verify_and_decrypt_vsc(
    cred: &CertContext,
    content: &[u8],
    is_ota: bool,
    env: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let xml = purebred_authorize_request(content, env).await?;

    let enc_ci = match is_ota {
        true => pbykcorelib::misc::utils::get_encrypted_payload_content(&xml)?,
        false => xml.to_vec(),
    };

    let ci_ed = ContentInfo::from_der(&enc_ci)?;
    if ci_ed.content_type != const_oid::db::rfc5911::ID_ENVELOPED_DATA {
        error!(
            "Unexpected content type (expected ID_ENVELOPED_DATA): {:?}",
            ci_ed.content_type
        );
        return Err(Error::ParseError);
    }
    let bytes2ed = ci_ed.content.to_der()?;
    let ed = EnvelopedData::from_der(&bytes2ed)?;

    let params = match ed.encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => return Err(Error::Unrecognized),
    };
    let enc_params = params.to_der()?;

    let os_iv = OctetString::from_der(&enc_params)?;
    let iv = os_iv.as_bytes();

    let mut ct = match ed.encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => return Err(Error::Unrecognized),
    };

    for ri in ed.recip_infos.0.iter() {
        let key = match ri {
            RecipientInfo::Ktri(ktri) => match asym_decrypt(cred, ktri.enc_key.as_bytes()) {
                Ok(dk) => dk,
                Err(_) => continue,
            },
            _ => continue,
        };

        /// decryption type
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let cipher = match Aes256CbcDec::new_from_slices(&key, iv.into()) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create new Aes256CbcDec instance: {e}. Continuing...");
                continue;
            }
        };
        if let Ok(pt) = cipher.decrypt_padded::<cipher::block_padding::Pkcs7>(&mut ct) {
            return Ok(Zeroizing::new(pt.to_vec()));
        }
    }
    Err(Error::Unrecognized)
}

/// Processes payloads from the presented `xml` generating and import keys using the provided YubiKey
pub(crate) async fn process_payloads_vsc(
    smartcard: &mut SmartCard,
    xml: &[u8],
    env: &str,
    is_recover: bool,
) -> Result<()> {
    let xml_cursor = Cursor::new(xml);
    let profile = match plist::Value::from_reader(xml_cursor) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse XML in process_payloads: {e:?}");
            return Err(Error::Plist);
        }
    };
    let payloads = match profile.as_array() {
        Some(d) => d,
        None => {
            error!("Failed to parse profile as an array");
            return Err(Error::Plist);
        }
    };

    let mut p12_index = 0;
    let mut recovered_index = 0;
    for payload in payloads {
        if let Some(dict) = payload.as_dictionary() {
            if let Some(payload_type) = dict.get("PayloadType") {
                match payload_type.as_string() {
                    Some(t) => {
                        if "com.apple.security.scep" == t {
                            let payload_content = match dict.get("PayloadContent") {
                                Some(pc) => match pc.as_dictionary() {
                                    Some(d) => d,
                                    None => {
                                        error!(
                                            "Failed to parse PayloadContent as a dictionary for SCEP payload."
                                        );
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    error!("SCEP payload missing PayloadContent.");
                                    return Err(Error::Plist);
                                }
                            };

                            if let Err(e) = process_scep_payload_vsc(
                                smartcard,
                                payload_content,
                                get_as_string(dict, "PayloadDisplayName"),
                                env,
                            )
                            .await
                            {
                                error!("Failed to process SCEP payload: {e:?}.");
                                return Err(e);
                            }
                        } else if "com.apple.security.pkcs12" == t {
                            let payload_content = match dict.get("PayloadContent") {
                                Some(pc) => match pc.as_data() {
                                    Some(d) => d,
                                    None => {
                                        error!(
                                            "Failed to parse PayloadContent as a data for PKCS #12 payload."
                                        );
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    error!("PKCS #12 payload missing PayloadContent.");
                                    return Err(Error::Plist);
                                }
                            };

                            let password = match dict.get("Password") {
                                Some(pc) => match pc.as_string() {
                                    Some(d) => d,
                                    None => {
                                        error!(
                                            "Failed to parse Password as a data for PKCS #12 payload."
                                        );
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    error!("PKCS #12 payload missing Password.");
                                    return Err(Error::Plist);
                                }
                            };
                            let friendly_name = match dict.get("DisplayName") {
                                Some(pc) => match pc.as_string() {
                                    Some(d) => d.to_string(),
                                    None => {
                                        error!(
                                            "Failed to parse Password as a data for PKCS #12 payload."
                                        );
                                        return Err(Error::Plist);
                                    }
                                },
                                None => format!("PKCS #12 #{recovered_index}"),
                            };

                            info!("Processing PKCS #12 payload with index {p12_index}");
                            if let Err(e) =
                                import_p12_vsc(smartcard, payload_content, password, &friendly_name)
                                    .await
                            {
                                error!(
                                    "Failed to process PKCS #12 payload at index {p12_index}: {e:?}."
                                );
                                return Err(e);
                            }
                            p12_index += 1;
                            if is_recover {
                                recovered_index += 1;
                            }
                        }
                    }
                    None => {
                        continue;
                    }
                }
            }
        }
    }
    Ok(())
}

//------------------------------------------------------------------------------------
// Unit tests
//------------------------------------------------------------------------------------
// #[tokio::test]
// async fn import_p12_vsc_test() {
//     let enc_p12 = hex!("30820B0D02010330820AD706092A864886F70D010701A0820AC804820AC430820AC03082057706092A864886F70D010706A0820568308205640201003082055D06092A864886F70D010701301C060A2A864886F70D010C0106300E0408DCCB781100D582680202080080820530E7710EBBD091123E40A60824A702440CC27E176489687C4F97EE104576B58E983998C6105C29E97465CF5FC4E05A909DAA193F138334042A8C22B896BEFB58DFEEB010EA9A601B243F542F2C3D8003329E66158805E50131B8220BBA4BE6F37B78FF11469F41747B254B7904F64A940F47D15468B0F1B3907840B4C5447682DFF80ADBF74BEA4D16C224E1FBF4D21187B588A3BD3DD3DFA472FB9E2E0F189A7BE3CB4C2B2CCCA528BBE1A3988D62E95C2A92817E4EEA7A9FA840B01467BD16A017DCFF8F167EEF2A27EC0C6CB6614D34075D571F321A9F98A809B689421049A9F93F534035256D96E5180058320BD3B137F9EDE8E6AD086577D96C3045B966C8F795FA671E6A69D99626260D209CB2D2877FD2F1C6E9001354B78009A21028C251A4E237029B8683F30D4EFB0F706D14F06B04B8B27FD862060DEF0CE0C960780C2B12CF5D6208D4F69BC5898103A5B95B17BF622996ED99296DF922B739223C8D3DD8C577798A3FF44C6E1DCD82A4F08DD80C4E72A53CFD96341A4BBB2A63355CC2EE5CD269EBDE08387AEB1A28EC4105B39107B203F9057F9259026B77D8B804CFE786F5AAF93370BDF20060A0D372A270794F6579A1C05972CA0361DD8848EE98B477F702BD65421BACD2F97E7B0E9D37A45D2E4B921FA53D9961DDB1B2E05A2B69946401D806DC0FA5B9214E8D9B9F0303A3E9C75AAFDF8CD9CB4505693FC25953F1CB12341438B5D5309E456F7ED7774D6589B8A60555819710EBCBDF0772CC71CC69339B411E44FA3C881AE51DC037A7C1F98882DBD2F9595EF09A43A445D5A8A9E09A66CAC2729C3744FFA90679B0AAFD14F50B53E433945F918F0724126C965DD93842A15EAEC5DEEF4AC74BBB3B98A224DAFD1805B8AAE0C3D477819547C6FD5B3F40E9B40AB78EC599190ABB7A8251E38F075552F8FE9BB3956D49F5B75CA2737A55428BBD85CD943712AE7186D80F1D69931D4603827A033711F6F0818D08558DFD949193C2E4C5562FC246AE6F30BE01A179401439EA219B3933EE8CA3EEF4FECB2B7376379658D704AF0C46AAE73B94EE194924733B6F78165127ECF8DD19AD051452277593C75DD0BAD5889ADFCE72AB2A8D9CAF55E815EE30099CFB38632F3F6D6C560E2762B22013E330272DB358E2DAAB42E91CB89C9E3EFE6BEC1347BCF387EA0FCC3D5E5D7588230B9EEBF07B33E478A2FCFD8840A33A5B003F2C54780CAA3373F01150C275100E13BBA34A9B87D3876A6CA9FB59BE8872BA3915FE102C4E6D64B0808D2E12F961287A56E3582D8F7506819551EF9A766902BF328CF7BE90780781E679FFB42F95DB12D697281A48A8BD66BE7EF0F4F6946F5057E69A1C806B1834B928CB4B5090FB1A19F4248E163AFA7C092E618CCD80DA91BDBB4DA0B3BF14B5DE474F0D1DE07F53014298011553B4654A6A0AB0A4B3304DB5C01ECF8F209006B755A53CA7AEAAB0A326EF539773CF0B5111924063206859E2F3E317F9F5409C0525EEA7F557839A7B2235EF46EED4ED0BA085876CD16B9A8C68943519A776DFDE06522B19C8D404CEF197808AD5CA0E596437FE5752CB05FF0DC3B11657763E274C72D06C93900686D0C5CE775FD6249F3FD15CF90D32BDB23110BD42968AD178FA08AFC9685749459AC69AF586D064C2D0EFDF0993C5D13B9A06199BD8ED217D43B83A7B6CC22F1705E81349132638005C615FC9214D0F2C5D9AB7A173A6A4B929DAB4B62FA6D99349D080C0F7EC7F0B1E1D3D4987BE8B2DCBB7ABCBAEC16A3845A86F2A7E1F677933C62440370929B09FD1FE332C1146383234DDE6A5D292BEA91C5FBAE952C90FA16CAB2FF956CC32B30F06D96885FF9E09A20536CC849A097416C4753082054106092A864886F70D010701A08205320482052E3082052A30820526060B2A864886F70D010C0A0102A08204EE308204EA301C060A2A864886F70D010C0103300E04084EEEA52A202EF27E02020800048204C800838F9D69144E7EAE0A018217D690B9F8D8999C383757E75191639B57D94A91CCA03D743789B8B67C50C43288D54E59D98D2D6E29F665E27214EB222C2ED7A8C574CBD8B4141F45C4DACC5CA680C87FDCE89A2A63AC71FDD5FBD841B0D8623892068B1D520E1C75D2F5B68BBAEBD63712E32597675829CB9D9F4201755C53509F5B0987540E07B869E6C6D029F83AFB38F9F8AA95E1C43EBC3E8C73ABF9E166691976E7BADAD12CB29CF06C17D3723F8C7837F2CC7F7E055E78FACAB53886B7E5ABDE26B2FC65A42EE30483114DB3FC766A1C2559B30DAB76505988FBB5400A2FE8EF6CF20849E2B8673041A2B0BF4BE840879F592DBC746885318E31B01670578B047A07633C32E72CC0290FEBB94BB7BFA063057C0504ED0D9182AC7DADC2607F6DA9851C2A24FAF13A592F0B9498F3216D418D77C3D60510BA143467AFDF40C7D1E968A3A9294BE30A247B4BC341750778F5F98456CF9A93F7DC416EDB2FBAB80B2D9C6C8A2BB2D96E796AED427455F1578DB818BFDDEA8772C38B071C1CAE1EEEC85AA8E7E39E4E7BA253D429C2931287EC44B99FC49D57DBCF8DDFB7D976B56948943813D7F6E1C1AA650F53E63DB762E51BCFF831EDF17B1398BC52CEC681E897376B90C0BE201AE36D3E56FA1CB952D2334D748EEF717442E73B8379F1DC7A817C770BD3CCE4B0ECBE31DDC072BE5071264D6C05802383097084B4C75DABD47BD8D790A0C7A1A258AC4A25F53846DA874AE5A32774C16AE4E24559026661C60F8DA8E66C00FF3BCD2400FB6C4F7967BC80C78552AC5170F1D7D409091C2685448367F0CECD36086CB0E12E3FADC03A594DEFB55F6828493DC60FED24EA9D2B874F1E25C55CE88ABE9C9D761E5B6243288D74A6ECE7B02470D1A373F36ADE00597CDD2F27CE2A6707E7A3D81729E91C8690E228F1ACCD8F8DC7D2D3006BF5B1C7BA12CC6D14B97FFD825769A5E6CFEE2BD11854343F1FF7E172BD8AEE918D198825238A5E0B6334EFEA0FC0E618D415B27AAEE6D8D99A0556308751216D1B51774CE54D1351A70AD741F10546C2889DE26F85B028ACD0B638D3196EE8EAE83AAE2045FD6279EBD96796D885B781C7AB7D42C806BEECFEF728BD80C8EE967BE5C216CDC26BFA06633F61B9FF352EDEC88F7641E3595A44B6E528D2049DDB27987036BE5A7F9B54D367B1C10D4A4B1F449E33878AF7EDF81A174B05A3BE6E4DA70BFDF4D7E3219B7BCAF83F9C450E080078E9833ADA3D73E71143F8CB58FFF988A8FD11F550B7490290EC49ABD96DA308A7769FA3313A2F5A6EEEDE6970BFD2AD1140EB1C1CCB720A0CD91ECDC57BE6E6A055A08452F7AFE7B35F54BE66596D96C192CC83FED011AA3538E67857658A70F3CA3223BC85B46F0038802C2482ED8B4DE239CC944907C7B01E5F22D6E54894DA89BC04E9DDDEA8ABFECC806320F1CB8C9EEA9A8C9BCD8AB0A311F4084F91AD00077ED5D5083EB4794C7B1B5CCC04337876E2546383AB97D4B48DCE068BF444511DBEA1A2FBA8C355E5B6138056EEA0630ECC2E83533A758BB860DC68329636FA2283E6CEAB25B5399088984CAEDA519F2B65BEEE955C7917366AEF27215146673CBCE53A164E4B301F231EF10CCF35FAE04E9E8A8AC2A394DD6FD86F537E7E018BF0D3EBD600F4FFE894D7BD2FA0D99499B0A07B6B0AD68BFADFEFDAA73CABD1D57EB9366C8090493C8D13B682B73FC832A37E6B3125302306092A864886F70D010915311604140E5600CB20BD87E7C36A728E50B4A39294D8FDD6302D3021300906052B0E03021A05000414B90EB924126DA95FAEB20C7621C7CA32EC75FE1404084F4B70EFE30156FA");
//     let password = "@aK)R7L>8S~fLyVBZ500[k2u3-vgEO|BhM~(?)jv]UeG!qN_0_C{P3XYDL4:9XO~4(y3W!b.Oq2AY4v/JrXO?D\\oyg?jOCUaM@RhrbPcGabb7#DK6:x^.eg3WP.+\\]iR";
//     let friendly_name = "PKCS #12";
//     import_p12_vsc(&enc_p12, password, friendly_name).await;
// }
