//! Networking-related utility functions

use log::error;
use reqwest::{Response, header::CONTENT_TYPE};

use certval_stores_core::get_reqwest_client_rustls;
use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};

use crate::misc::pki::validate_cert;
use crate::misc::stores::providers;
use crate::{Error, Result};

/// Default value in seconds to use as timeout for network requests
pub static TIMEOUT: u64 = 60;

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Checks the HTTP status of a response, generates an appropriate log message and returns an error if necessary.
fn check_response(response: &Response, uri: &str) -> Result<()> {
    let status = response.status();
    if status == 403 {
        error!(
            "Received failure response ({status}) from {uri}. Make sure the OTP value is valid.",
        );
        return Err(Error::Forbidden);
    } else if status == 409 {
        error!(
            "Received failure response ({status}) from {uri}. Have a Purebred Agent reset the device on the portal then re-enroll.",
        );
        return Err(Error::UnexpectedDeviceState);
    } else if status != 200 {
        error!("Request to {uri} failed with {:?}", status);
        return Err(Error::Http(status));
    }
    Ok(())
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Takes an encoded ContentInfo and returns every Certificate carried in the SignedData payload, in
/// the order they appear.
///
/// A SCEP `GetCACert` response is a degenerate SignedData that carries the RA certificate(s)
/// alongside the CA certificate(s) (RFC 8894 Section 2.1.3), and the CA certificates are what a path
/// to a trust anchor is built through — so callers that intend to validate the RA certificate need
/// the whole set, not just the one they picked.
pub fn get_certs_from_signed_data(enc_ci: &[u8]) -> Result<Vec<x509_cert::Certificate>> {
    match ContentInfo::from_der(enc_ci) {
        Ok(ci) => match ci.content.to_der() {
            Ok(content) => match SignedData::from_der(content.as_slice()) {
                Ok(sd) => {
                    let mut certs = vec![];
                    for c in sd.certificates.iter() {
                        for a in c.0.iter() {
                            if let CertificateChoices::Certificate(c) = a {
                                certs.push(c.clone());
                            }
                        }
                    }
                    Ok(certs)
                }
                Err(e) => {
                    error!(
                        "Failed to parse SignedData in get_certs_from_signed_data: {:?}",
                        e
                    );
                    Err(Error::Asn1(e))
                }
            },
            Err(e) => {
                error!(
                    "Failed to encode content in get_certs_from_signed_data: {:?}",
                    e
                );
                Err(Error::Asn1(e))
            }
        },
        Err(e) => Err(Error::Asn1(e)),
    }
}

/// Returns Content-Type header value from Response or an empty string
pub fn get_content_type(response: &Response) -> String {
    match response.headers().get("Content-Type") {
        Some(content_type_val) => match content_type_val.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                error!("Failed to process content type: {e:?}");
                String::new()
            }
        },
        None => String::new(),
    }
}

/// Retrieves a configuration profile from the indicated URL
pub async fn get_profile(url: &str) -> Result<Vec<u8>> {
    let client = get_reqwest_client_rustls(&providers(), TIMEOUT, None)?;
    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status();
            if status == 403 {
                error!(
                    "Received failure response ({status}) from {url}. Make sure the OTP value is valid.",
                );
                Err(Error::Forbidden)
            } else if status == 409 {
                error!(
                    "Received failure response ({status}) from {url}. Have a Purebred Agent reset the device on the portal then re-enroll.",
                );
                Err(Error::UnexpectedDeviceState)
            } else if status != 200 {
                error!(
                    "Received failure response from {url}: {}",
                    response.status()
                );
                Err(Error::Http(status))
            } else {
                match response.bytes().await {
                    Ok(bytes) => Ok(bytes.to_vec()),
                    Err(e) => {
                        error!("Failed to read response from {url}: {e:?}");
                        Err(Error::Network)
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to get a response from {url}: {e:?}");
            Err(Error::Network)
        }
    }
}

/// Fetches a SCEP `GetCACert` response from the given URL and returns the RA certificate to encrypt
/// the enrollment request to, after validating it to a trust anchor.
///
/// The RA certificate is selected as the first certificate in the response that is not self-issued.
/// That is a positional heuristic rather than the `keyUsage` discrimination RFC 8894 Section 2.1.3
/// calls for; it holds while the response carries a single usable RA certificate, and stops holding
/// when the RA has separate signing and encryption certificates — which post-quantum algorithms
/// force, since ML-DSA signs and ML-KEM encapsulates and neither does both.
///
/// The selected certificate is then validated to a trust anchor, building through the other
/// certificates in the response. Without this the client encrypts the enrollment request — which
/// carries the CSR, the attestation, and the one-time challenge password — to whatever public key
/// the response happened to contain. Transport is TLS-authenticated against the same trust material,
/// so this is defense in depth rather than the only control, but the challenge is bound to the
/// subject DN and SAN rather than to the CSR's public key, so anyone able to decrypt the request
/// could pair the challenge with a key of their own choosing.
pub async fn get_ca_cert(url: &str, env: &str) -> Result<x509_cert::Certificate> {
    let client = get_reqwest_client_rustls(&providers(), TIMEOUT, None)?;
    match client.get(url).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                error!("Request to {url} failed with {:?}", response.status());
                return Err(Error::Network);
            }

            // some things "succeed" when handing us an HTML page with an error. skip those.
            if "text/html" == get_content_type(&response) {
                error!(
                    "Received HTML success from {:?}. Expected ContentInfo.",
                    url
                );
                return Err(Error::Unrecognized);
            }

            match &response.bytes().await {
                Ok(bytes) => {
                    let certs = get_certs_from_signed_data(bytes)?;
                    let Some(ra_cert) = certs
                        .iter()
                        .find(|c| c.tbs_certificate().subject() != c.tbs_certificate().issuer())
                    else {
                        error!("No RA certificate found in the GetCACert response from {url}");
                        return Err(Error::ParseError);
                    };

                    // Build through the rest of the response. The CA certificate that issued the RA
                    // certificate travels in the same degenerate SignedData, and the trust anchor
                    // comes from the compiled-in stores.
                    let intermediates = certs
                        .iter()
                        .filter(|c| *c != ra_cert)
                        .cloned()
                        .collect::<Vec<_>>();
                    let ra_cert_der = ra_cert.to_der()?;
                    if validate_cert(&ra_cert_der, intermediates, env)
                        .await
                        .is_err()
                    {
                        error!(
                            "Failed to validate the RA certificate returned by {url}. Refusing to \
                             encrypt an enrollment request to it."
                        );
                        return Err(Error::BadInput);
                    }
                    Ok(ra_cert.clone())
                }
                Err(e) => {
                    error!("Failed to read response from {:?} with {e:?}.", url);
                    Err(Error::Network)
                }
            }
        }
        Err(e) => {
            error!("Failed to get response from {:?} with {e:?}.", url);
            Err(Error::Network)
        }
    }
}

/// Makes a POST request to the given URL with the provided body and content type and returns the result
/// as a buffer. Logs any error details before returning.
pub async fn post_body(uri: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>> {
    let client = get_reqwest_client_rustls(&providers(), TIMEOUT, None)?;
    let response = match client
        .post(uri)
        .body(body.to_vec())
        .header(CONTENT_TYPE, content_type)
        .send()
        .await
    {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to send request to {uri} with: {e:?}");
            return Err(Error::Network);
        }
    };

    check_response(&response, uri)?;

    match response.bytes().await {
        Ok(bb) => Ok(bb.to_vec()),
        Err(e) => {
            error!("Failed to read response from {uri} with: {e:?}");
            Err(Error::Network)
        }
    }
}

/// Makes a POST request to the given URL and returns the result as a buffer. Logs error details
/// before returning.
pub async fn post_no_body(uri: &str) -> Result<Vec<u8>> {
    let client = get_reqwest_client_rustls(&providers(), TIMEOUT, None)?;
    let response = match client.post(uri).send().await {
        Ok(b) => b,
        Err(e) => {
            error!("HTTP request send for {uri} failed with: {e:?}");
            return Err(Error::Network);
        }
    };

    check_response(&response, uri)?;

    match response.bytes().await {
        Ok(bb) => Ok(bb.to_vec()),
        Err(e) => {
            error!("Failed to read CMP response for {uri} with: {e:?}");
            Err(Error::Network)
        }
    }
}

/// Attempts to retrieve data from the given URL within the specified timeout.
pub async fn get_url(url: &str, timeout: u64) -> Result<()> {
    let client = get_reqwest_client_rustls(&providers(), timeout, None)?;
    match client.get(url).send().await {
        Ok(response) => match response.bytes().await {
            Ok(_bytes) => Ok(()),
            Err(e) => {
                error!("Failed to read response from {url}: {e:?}");
                Err(Error::Network)
            }
        },
        Err(e) => {
            error!("Status check failed for {url}: {e:?}");
            Err(Error::Network)
        }
    }
}
