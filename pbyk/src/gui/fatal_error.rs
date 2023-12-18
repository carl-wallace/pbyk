//! User interface for fatal errors (i.e., 0 YubiKeys found, > 1 YubiKey found, etc.)

use dioxus::prelude::*;

/// Fatal error is used when an error condition exists that requires the app to be relaunched, i.e.,
/// no YubiKeys are present or more than one YubiKey is present.
pub(crate) fn fatal_error<'a>(cx: Scope<'a>, fatal_error: &str) -> Element<'a> {
    cx.render(rsx! {
        style { include_str!("../../assets/pbyk.css") }
        div {
            p {
                "{fatal_error}"
            }
        }
    }) //end cx.render
}
