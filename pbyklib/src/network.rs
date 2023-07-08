//! Networking-related utility functions

use std::time::Duration;

use reqwest::header::CONTENT_TYPE;

use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};
use reqwest::{Client, Response};
use x509_cert::Certificate;

use crate::{log_error, Error, Result};

static TIMEOUT: u64 = 10;

/// Creates a Reqwest Client using indicated timeout value
fn get_client(timeout_secs: u64) -> Result<Client> {
    match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(client) => Ok(client),
        Err(e) => {
            log_error(&format!("Failed to create HTTP Client: {:?}", e));
            Err(Error::Network)
        }
    }
}

/// Retrieves a configuration profile from the indicated URL
pub(crate) async fn get_profile(url: &str) -> Result<Vec<u8>> {
    let client = get_client(TIMEOUT)?;
    match client.get(url).send().await {
        Ok(response) => match response.bytes().await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(e) => {
                log_error(&format!("Failed to read response from {url}: {:?}", e));
                Err(Error::Network)
            }
        },
        Err(e) => {
            log_error(&format!("Failed to get response from {url}: {:?}", e));
            Err(Error::Network)
        }
    }
}

/// Returns Content-Type header value from Response or an empty string
fn get_content_type(response: &Response) -> String {
    match response.headers().get("Content-Type") {
        Some(content_type_val) => match content_type_val.to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                log_error(&format!("Failed to process content type: {:?}", e));
                "".to_string()
            }
        },
        None => "".to_string(),
    }
}

/// Takes an encoded ContentInfo and returns the first Certificate read from SignedData payload
fn get_first_cert_from_signed_data(enc_ci: &[u8]) -> Result<Certificate> {
    match ContentInfo::from_der(enc_ci) {
        Ok(ci) => {
            match ci.content.to_der() {
                Ok(content) => {
                    match SignedData::from_der(content.as_slice()) {
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
                            log_error("No certificate found in SignedData in get_first_cert_from_signed_data");
                            Err(Error::ParseError)
                        }
                        Err(e) => {
                            log_error(&format!("Failed to parse SignedData in get_first_cert_from_signed_data: {:?}", e));
                            Err(Error::Asn1(e))
                        }
                    }
                }
                Err(e) => {
                    log_error(&format!(
                        "Failed to encode content in get_first_cert_from_signed_data: {:?}",
                        e
                    ));
                    Err(Error::Asn1(e))
                }
            }
        }
        Err(e) => {
            log_error(&format!(
                "Failed to decode ContentInfo in get_first_cert_from_signed_data: {:?}",
                e
            ));
            Err(Error::Asn1(e))
        }
    }
}

/// Fetches a P7 blob from the given URL and returns the first certificate that is not self-issued
pub(crate) async fn get_ca_cert(url: &str) -> crate::Result<Certificate> {
    let client = get_client(TIMEOUT)?;
    match client.get(url).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                log_error(&format!(
                    "Request to {url} failed with {:?}",
                    response.status()
                ));
                return Err(Error::Network);
            }

            // some things "succeed" when handing us an HTML page with an error. skip those.
            if "text/html" == get_content_type(&response) {
                log_error(&format!(
                    "Received HTML success from {:?}. Expected ContentInfo.",
                    url
                ));
                return Err(Error::Unrecognized);
            }

            match &response.bytes().await {
                Ok(bytes) => get_first_cert_from_signed_data(bytes),
                Err(e) => {
                    log_error(&format!(
                        "Failed to read response from {:?} with {:?}.",
                        url, e
                    ));
                    Err(Error::Network)
                }
            }
        }
        Err(e) => {
            log_error(&format!(
                "Failed to get response from {:?} with {:?}.",
                url, e
            ));
            Err(Error::Network)
        }
    }
}

/// Makes a POST request to the given URL with the provided body and content type and returns the result
/// as a buffer
pub(crate) async fn post_body(
    uri: &str,
    body: &[u8],
    content_type: &str,
) -> crate::Result<Vec<u8>> {
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
            log_error(&format!("CMP request send failed with {}: {}", e, uri));
            return Err(Error::Network);
        }
    };

    if !response.status().is_success() {
        log_error(&format!(
            "Request to {uri} failed with {:?}",
            response.status()
        ));
        return Err(Error::Network);
    }

    match response.bytes().await {
        Ok(bb) => Ok(bb.to_vec()),
        Err(e) => {
            log_error(&format!("Failed to read CMP response with {}: {}", e, uri));
            Err(Error::Network)
        }
    }
}

/// Makes a POST request to the given URL and returns the result as a buffer
pub(crate) async fn post_no_body(uri: &str) -> crate::Result<Vec<u8>> {
    let client = get_client(TIMEOUT)?;
    let response = match client.post(uri).send().await {
        Ok(b) => b,
        Err(e) => {
            log_error(&format!("HTTP request send for {} failed with: {}", uri, e));
            return Err(Error::Network);
        }
    };

    if !response.status().is_success() {
        log_error(&format!(
            "Request to {uri} failed with {:?}",
            response.status()
        ));
        return Err(Error::Network);
    }

    match response.bytes().await {
        Ok(bb) => Ok(bb.to_vec()),
        Err(e) => {
            log_error(&format!("Failed to read CMP response with {}: {}", e, uri));
            Err(Error::Network)
        }
    }
}
