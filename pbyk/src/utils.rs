//! Utility functions used by the pbyk utility

use crate::args::PbYkArgs;
#[cfg(target_os = "windows")]
use crate::no_bold::NoBold;
#[cfg(not(target_os = "windows"))]
use colored::Colorize;
use log::LevelFilter;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

/// Configures logging per logging-related elements of the provided [PbYkArgs] instance.
///
/// There are two logging-related options: [logging_config](PbYkArgs::logging_config) and
/// [log_to_console](PbYkArgs::log_to_console). Though these options are mutually exclusive, the
/// `logging_config` option can be used to define a logging configuration that both logs to the
/// console and logs to a file. The `log_to_console` option only emits logs from the Info level.
/// To emit more granular messages to the console, use the `logging_config` option, which can also
/// be used to govern logging output from dependencies.
pub(crate) fn configure_logging(args: &PbYkArgs) {
    let mut logging_configured = false;

    if let Some(logging_config) = &args.logging_config {
        if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
            println!(
                "{}: failed to configure logging using {} with {:?}. Continuing without logging.",
                "ERROR".bold(),
                logging_config,
                e
            );
        } else {
            logging_configured = true;
        }
    }

    if !logging_configured && args.log_to_console {
        // if there's no config, prepare one using stdout
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();
        match Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        {
            Ok(config) => {
                let handle = log4rs::init_config(config);
                if let Err(e) = handle {
                    println!(
                        "{}: failed to configure logging for stdout with {:?}. Continuing without logging.",
                        "ERROR".bold(), e
                    );
                }
            }
            Err(e) => {
                println!("{}: failed to prepare default logging configuration with {:?}. Continuing without logging", "ERROR".bold(), e);
            }
        }
    }
}
