//! Provides data structures used by the methods used to enroll a YubiKey device

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub(crate) struct Preenroll {
    pub uuid: String,
    pub edipi: String,
    pub serial: String,
    pub certificate: String,
    pub otp: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub os: String,
    pub product: String,
    pub yubikey_attestation: String,
    pub version: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub(crate) struct Phase2Request {
    pub CHALLENGE: String,
    pub SERIAL: String,
    pub PRODUCT: String,
    pub VERSION: String,
    pub UDID: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub(crate) struct Phase3Request {
    pub SERIAL: String,
    pub PRODUCT: String,
    pub VERSION: String,
    pub UDID: String,
}

/// Collects values for use as query parameters in the URL used for enroll, ukm and recover phases.
///
/// # Members
/// * `otp` - time-limited one-time password value whose purpose is determined by context, i.e., enroll, ukm, recover
/// * `base_url` - base URL of Purebred portal to contact
/// * `app` - string identifying version of `pbyk` app
pub struct OtaActionInputs {
    pub(crate) serial: String,
    otp: String,
    base_url: String,
    app: String,
}

impl OtaActionInputs {
    /// Creates a new OtaActionInputs structure featuring YubiKey `serial` number, UKM OTP value, and
    /// `app` name, which will be included in URL used to contact `base_url` to request recovered keys
    pub fn new(serial: &str, ukm_otp: &str, base_url: &str, app: &str) -> Self {
        OtaActionInputs {
            serial: serial.to_string(),
            otp: ukm_otp.to_string(),
            base_url: base_url.to_string(),
            app: app.to_string(),
        }
    }

    /// Returns URL formatted with query parameters required to request recovered keys
    pub fn to_recover_url(&self) -> String {
        format!(
            "{}/pb/get_p12?&otp={}&serial={}&app={}",
            self.base_url, self.otp, self.serial, self.app
        )
    }

    /// Returns URL formatted with query parameters required to request fresh PIV and signature credentials
    /// and current encryption credential
    pub fn to_ukm_url(&self) -> String {
        format!(
            "{}/pb/update?&otp={}&serial={}&app={}",
            self.base_url, self.otp, self.serial, self.app
        )
    }

    /// Returns URL formatted with query parameters required to request fresh PIV and signature credentials
    /// and current encryption credential
    pub fn to_enroll_url(&self, uuid: &str, agent_edipi: &str) -> String {
        format!(
            "{}/pb/enroll?edipi={}&otp={}&uuid={}&serial={}&app={}",
            self.base_url, agent_edipi, self.otp, uuid, self.serial, self.app
        )
    }
}
