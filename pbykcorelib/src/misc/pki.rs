//! Provide certification path building and validation support

use std::sync::Arc;

use log::{Level::Trace, debug, error, info, log_enabled, trace};

use base64ct::{Base64, Encoding};
use der::Encode;
use x509_cert::Certificate;

use certval::*;
use certval_cms::CmsEnvironment;
use certval_stores_core::prepare_certval_environment;

use crate::Error;
use crate::misc::stores::{providers, store_id};

/// Writes base64 encodings of certificates in the path to the logging system at the trace level
fn log_certs_in_path(path: &CertificationPath) {
    if !log_enabled!(Trace) {
        return;
    }

    trace!(
        "Trust anchor: {}",
        Base64::encode_string(path.trust_anchor.as_bytes())
    );
    for (i, cert) in path.intermediates.iter().enumerate() {
        trace!(
            "Certificate #{i}: {}",
            Base64::encode_string(cert.as_bytes())
        );
    }
    trace!("Target: {}", Base64::encode_string(path.target.as_bytes()));
}

/// Returns a `PkiEnvironment` populated with certval's RFC 5280 implementations, preceded by the
/// platform's crypto provider: Security.framework on macOS, CNG on Windows and AWS-LC on Linux.
///
/// The platform provider is consulted first. It declines what it does not support, and certval's
/// software implementations answer those cases.
pub fn new_pki_environment() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();

    #[cfg(target_os = "macos")]
    {
        use certval_security_framework::SecurityFrameworkCrypto;
        pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
        pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
    }
    #[cfg(target_os = "windows")]
    {
        use certval_cng::CngCrypto;
        pe.add_calculate_hash_callback(CngCrypto::new());
        pe.add_verify_signature_message_callback(CngCrypto::new());
        pe.add_verify_signature_digest_callback(CngCrypto::new());
    }
    #[cfg(target_os = "linux")]
    {
        use certval_awslc::AwsLcCrypto;
        pe.add_calculate_hash_callback(AwsLcCrypto::new());
        pe.add_verify_signature_message_callback(AwsLcCrypto::new());
        pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
    }

    pe.populate_5280_pki_environment();
    pe
}

/// Returns a [`PkiEnvironment`] from [`new_pki_environment`] holding the trust anchors and CA
/// certificates compiled in for the `env` environment.
pub fn pki_environment_for(env: &str) -> crate::Result<PkiEnvironment> {
    let mut pe = new_pki_environment();
    let Some(store_id) = store_id(env) else {
        error!("No trust store provider is compiled in for the {env} environment");
        return Err(Error::BadInput);
    };
    if let Err(e) = prepare_certval_environment(&providers(), &mut pe, store_id) {
        error!("Error preparing PkiEnvironment: {e}");
        return Err(Error::BadInput);
    }
    Ok(pe)
}

/// Returns a [`CmsEnvironment`] whose content encryption and key management go to the platform's
/// crypto provider first, with certval-cms's software implementations answering what the provider
/// declines, and which hashes, verifies signatures and vets certificates with `pe`.
pub fn new_cms_environment(pe: PkiEnvironment) -> CmsEnvironment {
    let mut env = CmsEnvironment::new();

    #[cfg(target_os = "macos")]
    {
        use certval_security_framework::SecurityFrameworkCrypto;
        env.add_encrypt_content_callback(SecurityFrameworkCrypto::new());
        env.add_decrypt_content_callback(SecurityFrameworkCrypto::new());
        env.add_encrypt_key_transport_callback(SecurityFrameworkCrypto::new());
        env.add_encrypt_key_agreement_callback(SecurityFrameworkCrypto::new());
    }
    #[cfg(target_os = "windows")]
    {
        use certval_cng::CngCrypto;
        env.add_encrypt_content_callback(CngCrypto::new());
        env.add_decrypt_content_callback(CngCrypto::new());
        env.add_encrypt_key_transport_callback(CngCrypto::new());
        env.add_encrypt_key_agreement_callback(CngCrypto::new());
        env.add_encrypt_kem_callback(CngCrypto::new());
    }
    #[cfg(target_os = "linux")]
    {
        use certval_awslc::AwsLcCrypto;
        env.add_encrypt_content_callback(AwsLcCrypto::new());
        env.add_decrypt_content_callback(AwsLcCrypto::new());
        env.add_encrypt_key_transport_callback(AwsLcCrypto::new());
        env.add_encrypt_key_agreement_callback(AwsLcCrypto::new());
        env.add_encrypt_kem_callback(AwsLcCrypto::new());
    }

    env.populate_software();
    env.set_pki_environment(Arc::new(pe));
    env
}

/// Takes a leaf certificate and a set of intermediate certificates and builds and validates a certification path to a
/// trust anchor set populated based on the elected features using resources available at compile time.
///
/// `validate_cert` mostly serves to prepare TaSource and CertSource instances for inclusion in a `PkiEnvironment` that
/// is passed to `validate_cert_buf`, which executes the validation operation and returns the result.
pub async fn validate_cert(
    leaf_cert: &Vec<u8>,
    intermediate: Vec<Certificate>,
    env: &str,
) -> crate::Result<()> {
    debug!("validate_cert for {env}");
    let cps = CertificationPathSettings::new();
    let mut pe = pki_environment_for(env)?;

    let mut cert_source = CertSource::new();
    for (i, ca_cert) in intermediate.iter().enumerate() {
        if let Ok(b) = ca_cert.to_der() {
            let cf = CertFile {
                filename: format!("intermediate_{i}").to_string(),
                bytes: b,
            };
            cert_source.push(cf);
        }
    }

    cert_source.initialize(&Default::default())?;
    pe.add_certificate_source(Box::new(cert_source.clone()));

    // Actually validate the certificate
    let mut fresh_uris = vec![];
    let res = validate_cert_buf(&pe, &cps, leaf_cert, &mut fresh_uris, 0).await;
    match res {
        Ok(_) => Ok(()),
        Err(_e) => Err(Error::BadInput),
    }
}

/// Validates the target certificate using the provided PkiEnvironment and CertificationPathSettings
///
/// The fresh_uris and threshold parameters are not presently used. Threshold should be set to zero.
async fn validate_cert_buf(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    target: &Vec<u8>,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) -> crate::Result<()> {
    let time_of_interest = cps.get_time_of_interest();

    if let Ok(target_cert) = parse_cert(target.as_slice(), "") {
        let mut paths: Vec<CertificationPath> = vec![];
        let r = pe.get_paths_for_target(&target_cert, &mut paths, threshold, time_of_interest);
        if let Err(e) = r {
            error!(
                "Failed to find certification paths for target with error {:?}",
                e
            );
            return Err(Error::BadInput);
        }

        if paths.is_empty() {
            collect_uris_from_aia_and_sia(&target_cert, fresh_uris);
            error!("Failed to find any certification paths for target",);
            return Err(Error::BadInput);
        }

        for path in paths.iter_mut() {
            let mut cpr = CertificationPathResults::new();
            log_certs_in_path(path);
            match pe.validate_path(pe, cps, path, &mut cpr) {
                Ok(()) => {
                    info!(
                        "Validated {} certificate path for {}",
                        path.intermediates.len() + 2,
                        name_to_string(path.target.as_ref().tbs_certificate().subject())
                    );
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to validate {} certificate path for {}: {e:?}",
                        path.intermediates.len() + 2,
                        name_to_string(path.target.as_ref().tbs_certificate().subject())
                    );
                    //return Err(Error::Attestation);
                }
            }
        }
        error!(
            "Failed to find a valid certificate path for {}",
            name_to_string(target_cert.as_ref().tbs_certificate().subject())
        );
        Err(Error::BadInput)
    } else {
        error!("Failed to parse target certificate");
        Err(Error::BadInput)
    }
}
