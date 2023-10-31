use pbyklib::utils::portal_status_check::portal_status_check;

#[cfg(feature = "dev")]
#[tokio::test]
async fn test_dev_pass() {
    assert!(portal_status_check("https://pb2.redhoundsoftware.net")
        .await
        .is_ok());
}

#[cfg(feature = "om_sipr")]
#[tokio::test]
async fn test_om_sipr_pass() {
    assert!(portal_status_check("https://purebred.snipr.disa.mil")
        .await
        .is_ok());
}

#[cfg(feature = "om_nipr")]
#[tokio::test]
async fn test_om_nipr_pass() {
    assert!(portal_status_check("https://purebred.c3pki.oandm.disa.mil")
        .await
        .is_ok());
}

#[cfg(not(feature = "dev"))]
#[tokio::test]
async fn test_dev_fail() {
    assert!(portal_status_check("https://pb2.redhoundsoftware.net")
        .await
        .is_err());
}

#[cfg(not(feature = "om_sipr"))]
#[tokio::test]
async fn test_om_sipr_fail() {
    assert!(portal_status_check("https://purebred.snipr.disa.mil")
        .await
        .is_err());
}

#[cfg(not(feature = "om_nipr"))]
#[tokio::test]
async fn test_om_nipr_fail() {
    assert!(portal_status_check("https://purebred.c3pki.oandm.disa.mil")
        .await
        .is_err());
}

#[cfg(not(feature = "sipr"))]
#[tokio::test]
async fn test_sipr_fail() {
    assert!(portal_status_check("https://purebred.csd.disa.smil.mil")
        .await
        .is_err());
}

#[cfg(not(feature = "nipr"))]
#[tokio::test]
async fn test_nipr_fail() {
    assert!(portal_status_check("https://purebred.csd.disa.mil")
        .await
        .is_err());
}
