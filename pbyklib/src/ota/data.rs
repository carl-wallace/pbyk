//! Provides data structures used by the methods used to enroll YubiKey or virtual smart card devices

use serde::{Deserialize, Serialize};
use yubikey::YubiKey;

#[cfg(all(target_os = "windows", feature = "vsc"))]
use windows::Devices::SmartCards::SmartCard;

/// CryptoModule provides an abstraction for different cryptographic backends. At present, YubiKey is supported on all
/// platforms and TPM-based virtual smart cards are supported on Windows systems.
pub enum CryptoModule {
    YubiKey(YubiKey),
    #[cfg(all(target_family = "windows", feature = "vsc"))]
    SmartCard(SmartCard),
}

/// Used to convey information about a YubiKey during Pre-enrollment
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Preenroll {
    /// Random UUID generated by pbyk
    pub uuid: String,
    /// EDIPI of the Purebred Agent who supplied the Pre-enrollment OTP
    pub edipi: String,
    /// Serial number of the YubiKey
    pub serial: String,
    /// Self-signed certificate containing public key the Purebred portal should use to encrypt Phase 2 response
    pub certificate: String,
    /// Pre-enrollment one-time password generated by Purebred Agent identified by edipi field of this structure
    pub otp: String,
    /// Type of device (always Yubikey in this case)
    #[serde(rename = "type")]
    pub device_type: String,
    /// YubiKey version
    pub os: String,
    /// YubiKey model
    pub product: String,
    /// Attestation for key pair associated with self-signed certificate conveyed in the certificate field of this structure
    pub yubikey_attestation: String,
    /// YubiKey version
    pub version: String,
}

/// Used to convey information about a virtual smart card (VSC) during Pre-enrollment
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct VscPreenroll {
    /// Random UUID generated by pbyk
    pub uuid: String,
    /// EDIPI of the Purebred Agent who supplied the Pre-enrollment OTP
    pub edipi: String,
    /// Value calculated by hashing concatenation of simulated ASHWID and the VSC reader name
    pub serial: String,
    /// Self-signed certificate containing public key the Purebred portal should use to encrypt Phase 2 response
    pub certificate: String,
    /// Pre-enrollment one-time password generated by Purebred Agent identified by edipi field of this structure
    pub otp: String,
    /// Indicates type of device (always Windows in this case)
    #[serde(rename = "type")]
    pub device_type: String,
    /// Operating system version (short)
    pub os: String,
    /// Product name as read from EasClientDeviceInformation
    pub product: String,
    /// Attestation for key pair associated with self-signed certificate conveyed in the certificate field of this structure
    pub microsoft_attestation: Option<String>,
    /// Operating system version (long)
    pub version: String,
}

/// Used to convey information about Phase 2 request
#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Phase2Request {
    /// Challenge value read from Phase 1 response
    pub CHALLENGE: String,
    /// Serial number of the device, i.e., YubiKey serial number or VSC serial calculated by hashing simulated ASHWID and reader name concatenation
    pub SERIAL: String,
    /// Product name
    pub PRODUCT: String,
    /// YubiKey version or Windows operating system version
    pub VERSION: String,
    /// Random value included in self-signed cert sent in Phase 1
    pub UDID: String,
}

/// Used to convey information about Phase 3 request
#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Phase3Request {
    /// Serial number of the device, i.e., YubiKey serial number or VSC serial calculated by hashing simulated ASHWID and reader name concatenation
    pub SERIAL: String,
    /// Product name
    pub PRODUCT: String,
    /// YubiKey version or Windows operating system version
    pub VERSION: String,
    /// Random value included in self-signed cert sent in Phase 1
    pub UDID: String,
}

/// Collects values for use as query parameters in the URL used for enroll, ukm and recover phases.
///
/// # Members
/// * `serial` - serial number of the device, i.e., YubiKey serial number or VSC serial calculated by hashing simulated ASHWID and reader name concatenation
/// * `otp` - time-limited one-time password value whose purpose is determined by context, i.e., enroll, ukm, recover
/// * `base_url` - base URL of Purebred portal to contact
/// * `app` - string identifying version of `pbyk` app
pub struct OtaActionInputs {
    /// Serial number of the device, i.e., YubiKey serial number or VSC serial calculated by hashing simulated ASHWID and reader name concatenation
    pub(crate) serial: String,
    /// Time-limited one-time password value whose purpose is determined by context, i.e., enroll, ukm, recover
    otp: String,
    /// Base URL of Purebred portal to contact
    base_url: String,
    /// String identifying version of `pbyk` app
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
