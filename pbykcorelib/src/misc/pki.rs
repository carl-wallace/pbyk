//! Provide certification path building and validation support

use log::{debug, error, info, log_enabled, trace, Level::Trace};

use base64ct::{Base64, Encoding};
use der::Encode;
use x509_cert::Certificate;

use certval::*;
use pb_pki::prepare_certval_environment;

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
    // let configuration = get_configuration().expect("Failed to read configuration.");

    // create a default path settings object and default PKIEnvironment object
    let cps = CertificationPathSettings::new();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    // read trust anchors from apple_attest_ta_folder and populate a TaSource instance
    let mut ta_store = TaSource::new();

    prepare_certval_environment(&mut pe, &mut ta_store, env)?;

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
                        name_to_string(path.target.decoded_cert.tbs_certificate().subject())
                    );
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to validate {} certificate path for {}: {e:?}",
                        path.intermediates.len() + 2,
                        name_to_string(path.target.decoded_cert.tbs_certificate().subject())
                    );
                    //return Err(Error::Attestation);
                }
            }
        }
        error!(
            "Failed to find a valid certificate path for {}",
            name_to_string(target_cert.decoded_cert.tbs_certificate().subject())
        );
        Err(Error::BadInput)
    } else {
        error!("Failed to parse target certificate");
        Err(Error::BadInput)
    }
}
