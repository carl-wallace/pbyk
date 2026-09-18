//! Toast notifications for the GUI: a stack of dismissible messages in the top-left corner.
//!
//! Replaces the `dioxus-toast` crate, which has no release for Dioxus 0.7. Only what pbyk used is
//! kept -- top-left placement, a close button, no automatic hiding -- and the styles are that crate's,
//! in `assets/toast.css`. One difference is deliberate: the message is rendered as text, where
//! `dioxus-toast` inserted it as HTML, so an error string from a device or a portal cannot become
//! markup.

use std::collections::BTreeMap;

use dioxus::prelude::*;

/// At most this many toasts are shown; a new one past the limit displaces the oldest.
const MAXIMUM_TOASTS: usize = 6;

/// The icon, and with it the colour, a toast is shown with.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Icon {
    Success,
    Error,
    Info,
}

/// One message to show.
#[derive(Debug, PartialEq, Clone)]
pub struct ToastInfo {
    pub heading: Option<String>,
    pub context: String,
    pub icon: Option<Icon>,
}

/// The toasts currently on screen, oldest first.
#[derive(Debug, Default)]
pub struct ToastManager {
    list: BTreeMap<usize, ToastInfo>,
    next_id: usize,
}

impl ToastManager {
    /// Shows `info`, displacing the oldest toast when the limit is reached.
    pub fn popup(&mut self, info: ToastInfo) {
        if self.list.len() >= MAXIMUM_TOASTS {
            self.list.pop_first();
        }
        self.list.insert(self.next_id, info);
        self.next_id = self.next_id.wrapping_add(1);
    }
}

/// Renders the toasts `manager` holds.
#[component]
pub fn ToastFrame(manager: Signal<ToastManager>) -> Element {
    let css = include_str!("../../assets/toast.css");
    let toasts: Vec<(usize, ToastInfo)> = manager
        .read()
        .list
        .iter()
        .map(|(id, info)| (*id, info.clone()))
        .collect();

    rsx! {
        div { class: "toast-scope",
            style { "{css}" }
            div { class: "toast-wrap top-left", id: "wrap-top-left",
                for (id, info) in toasts {
                    div {
                        key: "{id}",
                        class: match info.icon {
                            Some(Icon::Success) => "toast-single has-icon icon-success",
                            Some(Icon::Error) => "toast-single has-icon icon-error",
                            Some(Icon::Info) => "toast-single has-icon icon-info",
                            None => "toast-single",
                        },
                        div {
                            class: "close-toast-single",
                            onclick: move |_| {
                                manager.write().list.remove(&id);
                            },
                            "×"
                        }
                        if let Some(heading) = info.heading {
                            h2 { class: "toast-heading", "{heading}" }
                        }
                        span { "{info.context}" }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(text: &str) -> ToastInfo {
        ToastInfo {
            heading: None,
            context: text.to_string(),
            icon: None,
        }
    }

    #[test]
    fn the_oldest_toast_is_displaced_past_the_limit() {
        let mut manager = ToastManager::default();
        for i in 0..=MAXIMUM_TOASTS {
            manager.popup(info(&i.to_string()));
        }
        let shown: Vec<&str> = manager.list.values().map(|t| t.context.as_str()).collect();
        assert_eq!(shown.len(), MAXIMUM_TOASTS);
        assert_eq!(shown.first(), Some(&"1"));
        assert_eq!(shown.last(), Some(&MAXIMUM_TOASTS.to_string().as_str()));
    }
}
