//! On Windows, the bold() implementation from colored::Colorize does not work as expected. The
//! NoBold trait provides an alternative do-nothing implementation for use on Windows only.

#![cfg(target_os = "windows")]
pub trait NoBold {
    fn bold(self) -> String;
}

impl<'a> NoBold for &'a str {
    fn bold(self) -> String {
        self.to_string()
    }
}
impl NoBold for String {
    fn bold(self) -> String {
        self.to_string()
    }
}
