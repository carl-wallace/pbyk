//! Structure to contain signals established at app startup

use dioxus::prelude::Signal;

use std::fmt::Display;

use crate::gui::gui_main::Phase;

pub struct AppSignals {
    pub s_phase: Signal<Phase>,
    pub s_serial: Signal<String>,
    pub s_reset_req: Signal<bool>,
    pub s_serials: Signal<Vec<String>>,
    pub s_fatal_error_val: Signal<String>,
}

impl Display for AppSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s_phase: {:?}; ", self.s_phase)?;
        write!(f, "s_serial: {:?}; ", self.s_serial)?;
        write!(f, "s_reset_req: {:?}; ", self.s_reset_req)?;
        write!(f, "s_serials: {:?}; ", self.s_serials)?;
        write!(f, "s_fatal_error_val: {:?}", self.s_fatal_error_val)?;
        Ok(())
    }
}
