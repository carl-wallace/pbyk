//! Networking-related utility functions

use std::time::Duration;

use log::error;
use reqwest::{header::CONTENT_TYPE, Client, Response};

use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};

use crate::{Error, Result};

/// Default value in seconds to use as timeout for network requests
pub(crate) static TIMEOUT: u64 = 60;

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Returns Content-Type header value from Response or an empty string
fn get_content_type(response: &Response) -> String {
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

/// Takes an encoded ContentInfo and returns the first Certificate read from SignedData payload
fn get_first_cert_from_signed_data(enc_ci: &[u8]) -> Result<x509_cert::Certificate> {
    match ContentInfo::from_der(enc_ci) {
        Ok(ci) => match ci.content.to_der() {
            Ok(content) => match SignedData::from_der(content.as_slice()) {
                Ok(sd) => {
                    for c in sd.certificates.iter() {
                        for a in c.0.iter() {
                            if let CertificateChoices::Certificate(c) = a {
                                if c.tbs_certificate.subject != c.tbs_certificate.issuer {
                                    return Ok(c.clone());
                                }
                            }
                        }
                    }
                    error!("No certificate found in SignedData in get_first_cert_from_signed_data");
                    Err(Error::ParseError)
                }
                Err(e) => {
                    error!(
                        "Failed to parse SignedData in get_first_cert_from_signed_data: {:?}",
                        e
                    );
                    Err(Error::Asn1(e))
                }
            },
            Err(e) => {
                error!(
                    "Failed to encode content in get_first_cert_from_signed_data: {:?}",
                    e
                );
                Err(Error::Asn1(e))
            }
        },
        Err(e) => Err(Error::Asn1(e)),
    }
}

/// Checks the HTTP status of a response, generates an appropriate log message and returns an error if necessary.
fn check_response(response: &Response, uri: &str) -> Result<()> {
    let status = response.status();
    if status == 403 {
        error!(
            "Received failure response ({status}) from {uri}. Make sure the OTP value is valid.",
        );
        return Err(Error::Forbidden);
    } else if status == 409 {
        error!("Received failure response ({status}) from {uri}. Have a Purebred Agent reset the device on the portal then re-enroll.",);
        return Err(Error::UnexpectedDeviceState);
    } else if status != 200 {
        error!("Request to {uri} failed with {:?}", status);
        return Err(Error::Network);
    }
    Ok(())
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Creates a Reqwest Client using indicated timeout value
pub(crate) fn get_client(timeout_secs: u64) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .use_rustls_tls()
        .connection_verbose(true);

    #[cfg(feature = "dev")]
    {
        let ta_bytes = include_bytes!("../../../roots/NIPR/dev/DoDENGRootCA3.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse dev/DoDENGRootCA3DoDENGRootCA3: {e:?}"),
        };
    }
    #[cfg(feature = "om_nipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/NIPR/om/DoDJITCRootCA3.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/om/DoDJITCRootCA3: {e:?}"),
        };

        let ta_bytes = include_bytes!("../../../roots/NIPR/om/DoDJITCRootCA6.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/om/DoDJITCRootCA6: {e:?}"),
        };
    }
    #[cfg(feature = "om_sipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/SIPR/om/NSSJITCRootCA-2.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse SIPR/om/NSSJITCRootCA-2: {e:?}"),
        };
    }
    #[cfg(feature = "nipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/NIPR/prod/DoDRootCA3.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/prod/DoDRootCA3: {e:?}"),
        };

        let ta_bytes = include_bytes!("../../../roots/NIPR/prod/DoDRootCA6.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/prod/DoDRootCA6: {e:?}"),
        };
    }
    #[cfg(feature = "sipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/SIPR/prod/NSSRootCA-2.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse SIPR/prod/NSSRootCA-2: {e:?}"),
        };
    }

    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) => {
            error!("Failed to create HTTP Client: {e:?}");
            Err(Error::Network)
        }
    }
}

/// Retrieves a configuration profile from the indicated URL
pub(crate) async fn get_profile(url: &str) -> Result<Vec<u8>> {
    let client = get_client(TIMEOUT)?;
    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status();
            if status == 403 {
                error!("Received failure response ({status}) from {url}. Make sure the OTP value is valid.",);
                Err(Error::Forbidden)
            } else if status == 409 {
                error!("Received failure response ({status}) from {url}. Have a Purebred Agent reset the device on the portal then re-enroll.",);
                Err(Error::UnexpectedDeviceState)
            } else if status != 200 {
                error!(
                    "Received failure response from {url}: {}",
                    response.status()
                );
                Err(Error::Network)
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
            error!("Failed to get response from {url}: {e:?}");
            Err(Error::Network)
        }
    }
}

/// Fetches a P7 blob from the given URL and returns the first certificate that is not self-issued
pub(crate) async fn get_ca_cert(url: &str) -> Result<x509_cert::Certificate> {
    let client = get_client(TIMEOUT)?;
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
                Ok(bytes) => get_first_cert_from_signed_data(bytes),
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
pub(crate) async fn post_body(uri: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>> {
    let client = get_client(TIMEOUT)?;
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
pub(crate) async fn post_no_body(uri: &str) -> Result<Vec<u8>> {
    let client = get_client(TIMEOUT)?;
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

#[test]
fn parse_embedded_roots() {
    #[cfg(feature = "dev")]
    {
        let ta_bytes = include_bytes!("../../../roots/NIPR/dev/DoDENGRootCA3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "om_nipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/NIPR/om/DoDJITCRootCA3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../../../roots/NIPR/om/DoDJITCRootCA6.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "om_sipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/SIPR/om/NSSJITCRootCA-2.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "nipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/NIPR/prod/DoDRootCA3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../../../roots/NIPR/prod/DoDRootCA6.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "sipr")]
    {
        let ta_bytes = include_bytes!("../../../roots/SIPR/prod/NSSRootCA-2.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
}

/// Attempts to retrieve data from the given URL within the specified timeout.
pub(crate) async fn get_url(url: &str, timeout: u64) -> Result<()> {
    let client = get_client(timeout)?;
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
