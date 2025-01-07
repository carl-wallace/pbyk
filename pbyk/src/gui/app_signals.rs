use crate::gui::gui_main::Phase;
use dioxus::prelude::Signal;
use std::fmt::Display;

pub struct AppSignals {
    pub as_phase: Signal<Phase>,
    pub as_serial: Signal<String>,
    pub as_reset_req: Signal<bool>,
    pub as_serials: Signal<Vec<String>>,
    pub as_fatal_error_val: Signal<String>,
}

impl Display for AppSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "as_phase: {:?}; ", self.as_phase)?;
        write!(f, "as_serial: {:?}; ", self.as_serial)?;
        write!(f, "as_reset_req: {:?}; ", self.as_reset_req)?;
        write!(f, "as_serials: {:?}; ", self.as_serials)?;
        write!(f, "as_fatal_error_val: {:?}", self.as_fatal_error_val)?;
        Ok(())
    }
}
