//! Functions and structures to support execution of the OTA protocol to enroll virtual smart cards (VSCs) with a Purebred portal instance for use in pbyklib
#![cfg(all(target_os = "windows", feature = "vsc"))]

pub(crate) mod enroll;
pub(crate) mod pre_enroll;
pub(crate) mod recover;
pub(crate) mod ukm;
