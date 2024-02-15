//! Attempt to establish a connection to the pb/portal_status interface on a portal to network connectivity.

use crate::misc::network::get_url;

/// Timeout value for status check operations (shorter than for credential issuance actions owing
/// to longer time required for portal to perform centralized key generation and certificate issuance)
pub(crate) static SCEP_CHECK_TIMEOUT: u64 = 10;

/// Attempt to connect to the `pb/portal_status` interface on the target portal to affirm network connectivity.
pub async fn portal_status_check(base_url: &str) -> crate::Result<()> {
    let url = format!("{base_url}/pb/portal_status");
    get_url(&url, SCEP_CHECK_TIMEOUT).await
}
