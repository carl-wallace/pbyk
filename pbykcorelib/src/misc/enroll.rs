//! Supports Purebred enrollment

use std::io::Cursor;

use log::error;
use plist::Value;

use crate::{
    Error, Result,
    misc::{network::post_no_body, utils::purebred_authorize_request},
};

/// Retrieves Phase 1 response, verifies it and returns result as a plist::Value.
pub async fn fetch_phase1(url: &str, env: &str) -> Result<Value> {
    let p1resp = post_no_body(url).await?;
    let xml = purebred_authorize_request(&p1resp, env).await?;

    let xml_cursor = Cursor::new(xml);
    match Value::from_reader(xml_cursor) {
        Ok(profile) => Ok(profile),
        Err(e) => {
            error!(
                "Failed to parse Phase 1 encapsulated content as a configuration profile: {e:?}"
            );
            Err(Error::Plist)
        }
    }
}
