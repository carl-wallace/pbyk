//! Provides data structures used by the methods used to enroll a YubiKey device

use serde::{Deserialize, Serialize};

/// Conveys response following a CSR processing
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

/// Collects values for use as query parameters in URL used to request recovered keys from Purebred portal
pub struct OtaActionInputs {
    pub serial: String,
    ukm_otp: String,
    host: String,
    app: String,
}

impl OtaActionInputs {
    /// Creates a new RecoverInputs structure featuring YubiKey `serial` number, UKM OTP value, and
    /// `app` name, which will be included in URL used to contact `host` to request recovered keys
    pub fn new(serial: &str, ukm_otp: &str, host: &str, app: &str) -> Self {
        OtaActionInputs {
            serial: serial.to_string(),
            ukm_otp: ukm_otp.to_string(),
            host: host.to_string(),
            app: app.to_string(),
        }
    }

    /// Returns URL formatted with query parameters required to request recovered keys
    pub fn to_recover_url(&self) -> String {
        format!(
            "{}/pb/get_p12?&otp={}&serial={}&app={}",
            self.host, self.ukm_otp, self.serial, self.app
        )
    }

    /// Returns URL formatted with query parameters required to request fresh PIV and signature credentials
    /// and current encryption credential
    pub fn to_ukm_url(&self) -> String {
        format!(
            "{}/pb/update?&otp={}&serial={}&app={}",
            self.host, self.ukm_otp, self.serial, self.app
        )
    }

    /// Returns URL formatted with query parameters required to request fresh PIV and signature credentials
    /// and current encryption credential
    pub fn to_enroll_url(&self, uuid: &str, agent_edipi: &str) -> String {
        format!(
            "{}/pb/enroll?edipi={}&otp={}&uuid={}&serial={}&app={}",
            self.host, agent_edipi, self.ukm_otp, uuid, self.serial, self.app
        )
    }
}
