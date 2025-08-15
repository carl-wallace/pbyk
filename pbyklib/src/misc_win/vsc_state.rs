//! Functions and structures to work read and retain state information when interoperating with TPM-based virtual smart cards on Windows systems

#![cfg(all(target_os = "windows", feature = "vsc"))]

use std::{collections::BTreeMap, fs, fs::File};

use home::home_dir;
use log::{error, info};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use windows::System::Profile::SystemIdentification;
use windows::{
    Security::Cryptography::{
        BinaryStringEncoding,
        Core::{HashAlgorithmNames, HashAlgorithmProvider},
        CryptographicBuffer,
    },
    System::Profile::AnalyticsInfo,
    core::HSTRING,
};

use crate::utils::state::create_app_home;
use crate::{Error, Result};

/// Returns operating system version and product name.
///
/// The operating system will vary with the environment. The product name is currently hardcoded as "Virtual Smartcard".
pub(crate) fn get_version_and_product() -> Result<(String, String, String)> {
    let device_info =
        windows::Security::ExchangeActiveSyncProvisioning::EasClientDeviceInformation::new()?;
    let vi = match AnalyticsInfo::VersionInfo() {
        Ok(vi) => vi,
        Err(e) => {
            error!("Failed to read AnalyticsInfo::VersionInfo: {e:?}");
            return Err(Error::Vsc);
        }
    };

    let dfv = match vi.DeviceFamilyVersion() {
        Ok(dfv) => dfv.to_string(),
        Err(e) => {
            error!("Failed to read DeviceFamilyVersion: {e:?}");
            return Err(Error::Vsc);
        }
    };

    match dfv.parse::<u64>() {
        Ok(v) => {
            // poached from https://stackoverflow.com/questions/31783604/windows-10-get-devicefamilyversion
            let v1 = (v & 0xFFFF000000000000u64) >> 48;
            let v2 = (v & 0x0000FFFF00000000u64) >> 32;
            let v3 = (v & 0x00000000FFFF0000u64) >> 16;
            let v4 = v & 0x000000000000FFFFu64;
            let os_version = format!("{v1}.{v2}.{v3}.{v4}").to_string();
            let os_version_short = format!("{v1}.{v2}");
            info!("Operating system version: {os_version}");
            Ok((
                os_version,
                os_version_short,
                device_info
                    .SystemProductName()
                    .unwrap_or(HSTRING::from("Virtual Smartcard"))
                    .to_string(),
            ))
        }
        Err(e) => {
            error!("Failed to parse DeviceFamilyVersion with {e:?}");
            Err(Error::Vsc)
        }
    }
}

/// Used to represent state information that is unique to how `pbyk` manages virtual smart cards (VSCs).
///
/// The UWP app that `pbyk` replaces does not separate pre-enrollment and enrollment as `pbyk` does. When the UWP app
/// starts, if there is a CA issued certificate for the "serial number" of the target VSC then the app is in the UKM
/// state. Otherwise, it is in pre-enroll state and must progress through enrollment. In the UWP app, the "serial number"
/// is a hash of a concatenation of an ASHWID and the selected VSC reader. However, ASHWID values are not (easily) available
/// to non-packaged apps. Additionally, during enrollment, a UUID value is generated and used for self-signed
/// certificates (this is due to how iOS devices progress through the OTA process and the desire to stick to that model
/// for other platforms).
///
/// Using an ASHWID may be pursued at some point, but for now, a simulated ASHWID (i.e., a UUID) is generated and saved
/// then used as an ASHWID would be. To allow for separation of pre-enroll and enroll, a map of "serial" numbers and
/// UUIDs (i.e., the ones due to OTA process) is saved.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WindowsState {
    /// Simulated ASHWID values are randomly generated UUIDs
    simulated_ashwid: String,
    /// Provides a map from a UUID (value) from a self-signed certificate (i.e., not a simulated ASHWID) to a VSC reader name (key)
    pub reader_uuid_map: BTreeMap<String, String>,
    /// Provides a map from a certificate hash (value) to a VSC reader name (key)
    pub reader_cert_hash_map: BTreeMap<String, Vec<String>>,
}
impl Default for WindowsState {
    fn default() -> Self {
        let id = get_publisher_id().unwrap_or_else(|_| Uuid::new_v4().to_string());

        WindowsState {
            simulated_ashwid: id,
            reader_uuid_map: BTreeMap::default(),
            reader_cert_hash_map: BTreeMap::default(),
        }
    }
}

impl WindowsState {
    // /// Remove reader from cert hashes map (as means of clearing all entries)
    // #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    // pub fn clear_cert_hashes_for_reader(&mut self, reader: &str) {
    //     self.reader_cert_hash_map.remove(reader);
    // }
    /// Add cert hash for the reader
    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    pub fn add_cert_hash_for_reader(&mut self, reader: &str, hash: &String) {
        let mut cur = match self.reader_cert_hash_map.get(reader) {
            Some(cur) => cur.clone(),
            None => vec![],
        };
        if !cur.contains(hash) {
            cur.push(hash.clone());
        }

        self.reader_cert_hash_map.insert(reader.to_string(), cur);
    }

    /// Return hashes that were added to the reader
    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    pub fn get_hashes_for_reader(&self, reader: &String) -> Vec<String> {
        match self.reader_cert_hash_map.get(reader) {
            Some(v) => v.clone(),
            None => vec![],
        }
    }
}

/// Saves a [WindowsState] instance to a file named vsc_state.json in a folder named .pbyk in the user's home directory
pub(crate) fn save_state(windows_state: &WindowsState) -> Result<()> {
    let app_home = create_app_home()?;
    let app_cfg = app_home.join("vsc_state.json");
    if let Ok(json_args) = serde_json::to_string(&windows_state) {
        return if let Err(e) = fs::write(app_cfg, json_args) {
            error!("Unable to write windows state to file: {e}");
            Err(Error::Unrecognized)
        } else {
            Ok(())
        };
    }
    Err(Error::Unrecognized)
}

/// Use GetSystemIdForPublisher in lieu of ASHWID.
fn get_publisher_id() -> Result<String> {
    match SystemIdentification::GetSystemIdForPublisher() {
        Ok(sys_id) => match sys_id.Id() {
            Ok(id) => match CryptographicBuffer::EncodeToHexString(&id) {
                Ok(rv) => Ok(rv.to_string()),
                Err(e) => {
                    error!("Failed to include system ID as hex: {e:?}");
                    Err(Error::Vsc)
                }
            },
            Err(e) => {
                error!("Failed to get ID from SystemIdentificationInfo with {e:?}");
                Err(Error::Vsc)
            }
        },
        Err(e) => {
            error!("GetSystemIdForPublisher() failed with {e:?}");
            Err(Error::Vsc)
        }
    }
}

/// Reads a [WindowsState] instance from a file named vsc_state.json in a folder named .pbyk in the user's home directory
pub(crate) fn read_saved_state_or_default() -> WindowsState {
    if let Some(home_dir) = home_dir() {
        let app_cfg = home_dir.join(".pbyk").join("vsc_state.json");
        if let Ok(f) = File::open(app_cfg) {
            match serde_json::from_reader(&f) {
                Ok(saved_args) => return saved_args,
                Err(e) => {
                    error!(
                        "Failed to parse saved vsc_state.json configuration: {:?}",
                        e
                    );
                }
            };
        }
    }
    let rv = WindowsState::default();
    if let Err(e) = save_state(&rv) {
        error!("Failed to save WindowsState: {e:?}");
    }
    rv
}

/// Calculates the VSC ID and retrieves the UUID for the given reader.
///
/// If no state object exists, a fresh simulated ASHWID is created. If no UUID exists for the reader, a fresh UUID
/// is created and persisted.
pub(crate) fn get_vsc_id_and_uuid(reader: &HSTRING) -> Result<(String, String)> {
    let mut win_state = read_saved_state_or_default();
    let vsc_id = get_vsc_id_from_state(reader, &win_state)?;
    if let Some(uuid) = win_state.reader_uuid_map.get(&vsc_id) {
        Ok((vsc_id, uuid.to_string()))
    } else {
        let uuid = Uuid::new_v4().to_string();
        win_state
            .reader_uuid_map
            .insert(vsc_id.clone(), uuid.clone());
        save_state(&win_state)?;
        Ok((vsc_id, uuid))
    }
}

/// Calculates the VSC ID for the given reader using available or default [WindowsState] instance.
pub(crate) fn get_vsc_id(hardware_id: &HSTRING) -> Result<String> {
    get_vsc_id_from_state(hardware_id, &read_saved_state_or_default())
}

/// Calculates the VSC ID for the given reader using the given [WindowsState] instance as the source for a simulated ASHWID.
pub(crate) fn get_vsc_id_from_state(
    hardware_id: &HSTRING,
    win_state: &WindowsState,
) -> Result<String> {
    let sys_id = get_publisher_id().unwrap_or(win_state.simulated_ashwid.clone());
    let hasher = HashAlgorithmProvider::OpenAlgorithm(&HashAlgorithmNames::Sha1()?)?;

    // Hash the simulated ASHWID
    let hashed = hasher.HashData(&CryptographicBuffer::ConvertStringToBinary(
        &HSTRING::from(&sys_id),
        BinaryStringEncoding::Utf8,
    )?)?;
    let hashed_simulated_ashwid = CryptographicBuffer::EncodeToHexString(&hashed)?;

    // Concatenate the two values (a la the UWP app)
    let concatenation = format!("{} {}", hashed_simulated_ashwid, hardware_id);
    let hasher2 = HashAlgorithmProvider::OpenAlgorithm(&HashAlgorithmNames::Sha1()?)?;
    let hashed2 = hasher2.HashData(&CryptographicBuffer::ConvertStringToBinary(
        &HSTRING::from(concatenation),
        BinaryStringEncoding::Utf8,
    )?)?;
    let hashed_string2 = CryptographicBuffer::EncodeToHexString(&hashed2)?;
    Ok(hashed_string2.to_string())
}
