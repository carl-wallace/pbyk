use std::{fs::create_dir_all, path::PathBuf};

use home::home_dir;
use log::error;

use crate::Error;

/// Create folder named .pbyk in the user's home directory and return a PathBuf referencing that folder.
pub fn create_app_home() -> crate::Result<PathBuf> {
    if let Some(hd) = home_dir() {
        let app_home = hd.join(".pbyk");
        if !app_home.exists() && create_dir_all(&app_home).is_err() {
            error!(
                "Failed to create {} directory",
                app_home.to_str().unwrap_or_default()
            );
            return Err(Error::Unrecognized);
        }
        return Ok(app_home);
    }
    Err(Error::Unrecognized)
}
