//! Provide certification path building and validation support

use log::{debug, error, info, log_enabled, trace, Level::Trace};

use base64ct::{Base64, Encoding};
use der::Encode;
use x509_cert::Certificate;

use certval::*;

use crate::Error;

/// Writes base64 encodings of certificates in the path to the logging system at the trace level
fn log_certs_in_path(path: &CertificationPath) {
    if !log_enabled!(Trace) {
        return;
    }

    trace!(
        "Trust anchor: {}",
        Base64::encode_string(&path.trust_anchor.encoded_ta)
    );
    for (i, cert) in path.intermediates.iter().enumerate() {
        trace!(
            "Certificate #{i}: {}",
            Base64::encode_string(&cert.encoded_cert)
        );
    }
    trace!(
        "Target: {}",
        Base64::encode_string(&path.target.encoded_cert)
    );
}

/// Takes a leaf certificate and a set of intermediate certificates and builds and validates a
/// certification path to a trust anchor from the location identified in the
/// [apple_attest_ta_folder](crate::configuration::Settings) setting
///
/// `validate_cert` mostly serves to prepare TaSource and CertSource instances for inclusion in a
/// `PkiEnvironment` that is passed to `validate_cert_buf`, which executes the validation operation
/// and returns the result.
pub(crate) async fn validate_cert(
    leaf_cert: &Vec<u8>,
    intermediate: Vec<Certificate>,
    env: &str,
) -> crate::Result<()> {
    debug!("validate_cert for {env}");
    // let configuration = get_configuration().expect("Failed to read configuration.");

    // create a default path settings object and default PKIEnvironment object
    let cps = CertificationPathSettings::new();
    let mut pe = PkiEnvironment::default();
    populate_5280_pki_environment(&mut pe);

    // read trust anchors from apple_attest_ta_folder and populate a TaSource instance
    let mut ta_store = TaSource::new();

    #[cfg(feature = "dev")]
    if env == "DEV" {
        let ta_bytes = include_bytes!("../../../roots/NIPR/dev/DoDENGRootCA3.der");
        let cf = CertFile {
            filename: "dev root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../../../cas/NIPR/dev/dev.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "om_nipr")]
    if env == "OM_NIPR" {
        let ta_bytes = include_bytes!("../../../roots/NIPR/om/DoDJITCRootCA3.der");
        let cf = CertFile {
            filename: "om nipr root 3".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let ta_bytes = include_bytes!("../../../roots/NIPR/om/DoDJITCRootCA6.der");
        let cf = CertFile {
            filename: "om nipr root 6".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../../../cas/NIPR/om/om.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "om_sipr")]
    if env == "OM_SIPR" {
        let ta_bytes = include_bytes!("../../../roots/SIPR/om/NSSJITCRootCA-2.der");
        let cf = CertFile {
            filename: "om sipr root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../../../cas/SIPR/om/om.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "nipr")]
    if env == "NIPR" {
        let ta_bytes = include_bytes!("../../../roots/NIPR/prod/DoDRootCA3.der");
        let cf = CertFile {
            filename: "nipr root 3".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let ta_bytes = include_bytes!("../../../roots/NIPR/prod/DoDRootCA6.der");
        let cf = CertFile {
            filename: "nipr root 6".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../../../cas/NIPR/prod/prod.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "sipr")]
    if env == "SIPR" {
        let ta_bytes = include_bytes!("../../../roots/SIPR/prod/NSSRootCA-2.der");
        let cf = CertFile {
            filename: "sipr root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../../../cas/SIPR/prod/prod.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }

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

    ta_store.initialize()?;
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));

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
    let time_of_interest = get_time_of_interest(cps);

    if let Ok(target_cert) = parse_cert(target.as_slice(), "") {
        let mut paths: Vec<CertificationPath> = vec![];
        let r = pe.get_paths_for_target(pe, &target_cert, &mut paths, threshold, time_of_interest);
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
            debug!(
                "Validating {} certificate path for {}",
                (path.intermediates.len() + 2),
                name_to_string(&path.target.decoded_cert.tbs_certificate.subject)
            );
            let mut cpr = CertificationPathResults::new();
            log_certs_in_path(path);
            match pe.validate_path(pe, cps, path, &mut cpr) {
                Ok(()) => {
                    info!(
                        "Validating {} certificate path for {}",
                        (path.intermediates.len() + 2),
                        name_to_string(&path.target.decoded_cert.tbs_certificate.subject)
                    );
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to validate {} certificate path for {}: {e:?}",
                        (path.intermediates.len() + 2),
                        name_to_string(&path.target.decoded_cert.tbs_certificate.subject)
                    );
                    //return Err(Error::Attestation);
                }
            }
        }
        error!(
            "Failed to find a valid certificate path for {}",
            name_to_string(&target_cert.decoded_cert.tbs_certificate.subject)
        );
        Err(Error::BadInput)
    } else {
        error!("Failed to parse target certificate");
        Err(Error::BadInput)
    }
}
