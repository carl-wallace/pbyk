//! Attempt to establish a connection to the pb/portal_status interface on a portal to network connectivity.

use crate::{misc::network::get_client, Error};
use log::error;

/// Timeout value for status check operations (shorter than for credential issuance  actions owing
/// to longer time required for portal to perform centralized key generation and certificate issuance)
pub(crate) static STATUS_CHECK_TIMEOUT: u64 = 10;

/// Attempt to connect to the `ca/device-enroll/pkiclient.exe?operation=GetCACert` interface on the target portal to affirm network connectivity.
pub async fn scep_check(host: &str) -> crate::Result<()> {
    let url = format!("{host}/ca/device-enroll/pkiclient.exe?operation=GetCACert");
    let client = get_client(STATUS_CHECK_TIMEOUT)?;
    match client.get(&url).send().await {
        Ok(response) => match response.bytes().await {
            Ok(_bytes) => Ok(()),
            Err(e) => {
                error!("Failed to read response from {url}: {e:?}");
                Err(Error::Network)
            }
        },
        Err(e) => {
            error!("Status check failed for {host}: {e:?}");
            Err(Error::Network)
        }
    }
}
