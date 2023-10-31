use pbyklib::portal_status_check::portal_status_check;

#[cfg(feature = "dev")]
#[tokio::test]
async fn test_dev_get_ca_cert_pass() {
    assert!(portal_status_check("https://ee-sw-ca-53.redhoundsoftware.net/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_ok());
}

#[cfg(feature = "om_sipr")]
#[tokio::test]
async fn test_om_sipr_get_ca_cert_pass() {
    assert!(portal_status_check("https://ee-nss-derility-ca-1.snipr.disa.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_ok());
    assert!(portal_status_check("https://ee-nss-derility-ca-2.snipr.disa.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_ok());
}

#[cfg(feature = "om_nipr")]
#[tokio::test]
async fn test_om_nipr_get_ca_cert_pass() {
    assert!(portal_status_check("https://ee-derility-ca-1.c3pki.oandm.disa.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_ok());
}

#[cfg(not(feature = "dev"))]
#[tokio::test]
async fn test_dev_get_ca_cert_fail() {
    assert!(portal_status_check("https://pb2.redhoundsoftware.net")
        .await
        .is_err());
}

#[cfg(not(feature = "om_sipr"))]
#[tokio::test]
async fn test_om_sipr_get_ca_cert_fail() {
    assert!(portal_status_check("https://ee-nss-derility-ca-1.snipr.disa.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_err());
    assert!(portal_status_check("https://ee-nss-derility-ca-2.snipr.disa.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_err());
}

#[cfg(not(feature = "om_nipr"))]
#[tokio::test]
async fn test_om_nipr_get_ca_cert_fail() {
    assert!(portal_status_check("https://ee-derility-ca-1.c3pki.oandm.disa.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_err());
}

#[cfg(not(feature = "sipr"))]
#[tokio::test]
async fn test_sipr_get_ca_cert_fail() {
    assert!(portal_status_check("https://ee-nss-derility-ca-1.csd.disa.smil.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_err());
    assert!(portal_status_check("https://ee-nss-derility-ca-2.csd.disa.smil.mil/ca/device-enroll/pkiclient.exe?operation=GetCACert")
        .await
        .is_err());
}

#[cfg(not(feature = "nipr"))]
#[tokio::test]
async fn test_nipr_get_ca_cert_fail() {
    assert!(portal_status_check(
        "https://ee-derility-ca-1.csd.disa.mil//ca/device-enroll/pkiclient.exe?operation=GetCACert"
    )
    .await
    .is_err());
}
