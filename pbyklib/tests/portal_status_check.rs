use pbyklib::utils::portal_status_check::portal_status_check;

#[cfg(feature = "dev")]
#[tokio::test]
async fn test_dev_pass() {
    assert!(
        portal_status_check("https://pb2.redhoundsoftware.net")
            .await
            .is_ok()
    );
}

#[cfg(feature = "om_sipr")]
#[tokio::test]
async fn test_om_sipr_pass() {
    assert!(
        portal_status_check("https://purebred.snipr.disa.mil")
            .await
            .is_ok()
    );
}

#[cfg(feature = "om_nipr")]
#[tokio::test]
async fn test_om_nipr_pass() {
    // init_console_logging();
    assert!(
        portal_status_check("https://purebred.c3pki.oandm.disa.mil")
            .await
            .is_ok()
    );
}

#[cfg(not(feature = "dev"))]
#[tokio::test]
async fn test_dev_fail() {
    assert!(
        portal_status_check("https://pb2.redhoundsoftware.net")
            .await
            .is_err()
    );
}

#[cfg(not(feature = "om_sipr"))]
#[tokio::test]
async fn test_om_sipr_fail() {
    assert!(
        portal_status_check("https://purebred.snipr.disa.mil")
            .await
            .is_err()
    );
}

#[cfg(not(feature = "om_nipr"))]
#[tokio::test]
async fn test_om_nipr_fail() {
    assert!(
        portal_status_check("https://purebred.c3pki.oandm.disa.mil")
            .await
            .is_err()
    );
}

#[cfg(not(feature = "sipr"))]
#[tokio::test]
async fn test_sipr_fail() {
    assert!(
        portal_status_check("https://purebred.csd.disa.smil.mil")
            .await
            .is_err()
    );
}

#[cfg(not(feature = "nipr"))]
#[tokio::test]
async fn test_nipr_fail() {
    assert!(
        portal_status_check("https://purebred.csd.disa.mil")
            .await
            .is_err()
    );
}

// Call this from unit tests when actively debugging (hence allow(dead_code)).
#[allow(dead_code)]
#[cfg(test)]
fn init_console_logging() {
    use log::LevelFilter;
    use log4rs::{
        append::console::ConsoleAppender,
        config::{Appender, Config, Root},
        encode::pattern::PatternEncoder,
    };
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
                    "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                    e
                );
            }
        }
        Err(e) => {
            println!(
                "ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging",
                e
            );
        }
    }
}
