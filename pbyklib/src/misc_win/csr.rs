//! Windows-specific utility functions related to CSR preparation and consumption for use within pbyklib
//!
#![cfg(all(target_os = "windows", feature = "vsc"))]

use core::ffi::c_void;
use std::ptr::NonNull;
use std::{ffi::CString, ptr::null, time::Duration};

use log::error;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertGetCertificateContextProperty, CertOpenStore,
    CryptMemAlloc, CryptMemFree, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_A, CRYPT_KEY_PROV_INFO,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey};
use sha2::Sha256;

use base64ct::{Base64, Encoding};
use cms::{
    builder::SignedDataBuilder, cert::CertificateChoices, signed_data::EncapsulatedContentInfo,
};
use const_oid::db::rfc5912::{ID_CCT_PKI_DATA, ID_CE_SUBJECT_KEY_IDENTIFIER};
use der::{asn1::OctetString, Choice, Decode, Encode, Sequence};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    request::CertReq,
    serial_number::SerialNumber,
    time::Validity,
    Certificate,
};

use certval::{ExtensionProcessing, PDVCertificate, PDVExtension};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::asn1::Int;
use windows::core::HSTRING;

use crate::misc::utils::get_encap_content;
use crate::misc_win::csr::TaggedRequest::Tcr;
use crate::misc_win::vsc_signer::CertContext;
use crate::{Error, Result, CERT_SYSTEM_STORE_CURRENT_USER};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Takes a `Certificate` object and a byte array and returns true if the `Certificate` contains a `SubjectKeyIdentifier`
/// extension whose value matches the byte array.
fn skid_match(cert: &Certificate, target_skid: &[u8]) -> bool {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
                match OctetString::from_der(ext.extn_value.as_bytes()) {
                    Ok(os) => {
                        if os.as_bytes() == target_skid {
                            return true;
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse SubjectKeyIdentifier extension from Certificate with serial number {} as\
                         an OctetString: {}. Ignoring and continuing...", cert.tbs_certificate.serial_number, e);
                    }
                }
            }
        }
    }

    false
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Takes a `Certificate` and a [CertContext] and returns a new self-signed `Certificate` that features the subject name in
/// the issuer field and a fresh signature generated using the private key corresponding to the `signer` parameter.
///
/// The caller is responsible for assuring the `signer` parameter corresponds to the `cert` parameter. If this is not true,
/// the resulting certificate may not verify as self-signed.
///
/// # Arguments
/// * `cert` - `Certificate` object that (presumably) contains a fake certificate used to coerce Crypto API (CAPI) to
///   allow use a private key before a CA-issued certificate has been issued
/// * `signer` - [CertContext] object that (presumably) wraps a `CERT_CONTEXT` that references the `Certificate` in `cert`
pub(crate) fn resign_as_self(cert: &Certificate, signer: &CertContext) -> Result<Certificate> {
    let profile = Profile::Leaf {
        issuer: cert.tbs_certificate.subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: true,
        include_subject_key_identifier: true,
    };

    let builder = CertificateBuilder::new(
        profile,
        cert.tbs_certificate.serial_number.clone(),
        cert.tbs_certificate.validity,
        cert.tbs_certificate.subject.clone(),
        cert.tbs_certificate.subject_public_key_info.clone(),
        signer,
    )?;

    Ok(builder.build()?)
}

/// `PKIData` is defined in [RFC 5272 Section 3.2.1]. This implementation ignores the control_sequence,
/// cms_sequence and other_msg_sequence fields.
///
/// ```text
///      PKIData ::= SEQUENCE {
///          controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
///          reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
///          cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
///          otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
///      }
/// ```
/// [RFC 5272 Section 3.2.1]: https://datatracker.ietf.org/doc/html/rfc5272#section-3.2.1
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct PkiData {
    ///          controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
    pub control_sequence: Vec<u8>,
    ///          reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
    pub req_sequence: Vec<TaggedRequest>,
    ///          cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
    pub cms_sequence: Vec<u8>,
    ///          otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
    pub other_msg_sequence: Vec<u8>,
}

/// `TaggedRequest` is defined in [RFC 5272 Section 3.2.1.2]. This implementation ignores the crm and orm options.
///
/// ```text
///      TaggedRequest ::= CHOICE {
///         tcr               [0] TaggedCertificationRequest,
///         crm               [1] CertReqMsg,
///         orm               [2] SEQUENCE {
///            bodyPartID            BodyPartID,
///            requestMessageType    OBJECT IDENTIFIER,
///            requestMessageValue   ANY DEFINED BY requestMessageType
///         }
///      }
/// ```
/// [RFC 5272 Section 3.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5272#section-3.2.1.2
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum TaggedRequest {
    ///         tcr               [0] TaggedCertificationRequest,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    Tcr(TaggedCertificationRequest),
}

/// `TaggedCertificationRequest` is defined in [RFC 5272 Section 3.2.1.2.1].
///
/// ```text
///     TaggedCertificationRequest ::= SEQUENCE {
///         bodyPartID            BodyPartID,
///         certificationRequest  CertificationRequest
///     }
/// ```
/// [RFC 5272 Section 3.2.1.2.1]: https://datatracker.ietf.org/doc/html/rfc5272#section-3.2.1.2.1
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct TaggedCertificationRequest {
    ///         bodyPartID            BodyPartID,
    pub body_part_id: Int,
    ///         certificationRequest  CertificationRequest
    pub certification_request: CertReq,
}

/// Parses a PKIData message containing exactly one CertReq, which is the structure returned when an attested CSR is generated
pub(crate) async fn consume_attested_csr(b64_csr: &str) -> Result<(String, Certificate)> {
    let stripped = b64_csr.replace(['\r', '\n'], "");
    let der_content_info = Base64::decode_vec(&stripped)?;
    let ci = ContentInfo::from_der(&der_content_info)?;
    if ci.content_type != ID_SIGNED_DATA {
        error!(
            "Received unexpected content type in consume_attested_csr: {}",
            ci.content_type
        );
        return Err(Error::BadInput);
    }
    let sd_bytes = ci.content.to_der()?;
    let sd = SignedData::from_der(&sd_bytes)?;
    if sd.encap_content_info.econtent_type != ID_CCT_PKI_DATA {
        error!(
            "Received unexpected encapsulated content type in consume_attested_csr: {}",
            ci.content_type
        );
        return Err(Error::BadInput);
    }
    let der_pki_data = get_encap_content(&sd.encap_content_info)?;

    let pki_data = PkiData::from_der(&der_pki_data)?;
    let req_sequence = match pki_data.req_sequence.first() {
        Some(req_sequence) => req_sequence.clone(),
        None => {
            error!("Failed to obtain req sequence from PkiData");
            return Err(Error::BadInput);
        }
    };
    let der_tr = req_sequence.to_der()?;
    let tr = TaggedRequest::from_der(&der_tr)?;
    match tr {
        Tcr(tcr) => consume_parsed_csr(&tcr.certification_request).await,
    }
}

/// Processes a parsed CSR (i.e., an unattested request or the CSR component extracted from an attested request)
async fn consume_parsed_csr(csr: &CertReq) -> Result<(String, Certificate)> {
    // collect "CA" components
    let private_key_bytes = include_bytes!("../../assets/TrustAnchorRootCertificate.p8");
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(private_key_bytes)?;
    let signer = SigningKey::<Sha256>::new(private_key);
    let issuer_cert_bytes = include_bytes!("../../assets/TrustAnchorRootCertificate.crt");
    let issuer_cert = Certificate::from_der(issuer_cert_bytes)?;

    // generate fake certificate with a ~10 year validity period
    let profile = Profile::Leaf {
        issuer: issuer_cert.tbs_certificate.issuer.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: true,
        include_subject_key_identifier: true,
    };

    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::new(365 * 24 * 60 * 60 * 10, 0))?,
        csr.info.subject.clone(),
        csr.info.public_key.clone(),
        &signer,
    )?;

    let certificate = builder.build()?;
    let p7 = prepare_base64_certs_only_p7(&certificate)?;
    Ok((p7, certificate))
}

/// Takes a Base64-encoded CSR and returns a Base64-encoded certs-only SignedData containing a certificate signed using
/// an embedded fake CA private key.
///
/// Note, in both cases the data is Base64-encoded, not PEM-encoded. This is to align with the functions available from
/// CertificateEnrollmentManager::UserCertificateEnrollmentManager.
pub(crate) async fn consume_csr(b64_csr: &str) -> Result<(String, Certificate)> {
    // parse CSR
    let stripped = b64_csr.replace(['\r', '\n'], "");
    let der_csr = Base64::decode_vec(&stripped)?;

    let csr = CertReq::from_der(&der_csr)?;

    consume_parsed_csr(&csr).await
}

/// Takes a `Certificate` object and returns a Base64-encoded certs-only `SignedData` object containing that certificate.
pub(crate) fn prepare_base64_certs_only_p7(certificate: &Certificate) -> Result<String> {
    let mut signed_data_builder = SignedDataBuilder::new(&EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    });
    signed_data_builder.add_certificate(CertificateChoices::Certificate(certificate.clone()))?;
    Ok(Base64::encode_string(
        &signed_data_builder.build()?.to_der()?,
    ))
}

/// Returns a vector containing `CERT_CONTEXT` pointers for certificates that are present in the current user's MY store
/// and that have an associated key info structure (i.e., private key is available). The vector is sorted by notBefore value.
pub(crate) fn get_credential_list(target_cert: Option<PDVCertificate>) -> Result<Vec<CertContext>> {
    let target_skid = match target_cert {
        Some(target_cert) => match target_cert.get_extension(&ID_CE_SUBJECT_KEY_IDENTIFIER) {
            Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) => Some(skid.0.as_bytes().to_vec()),
            _ => None,
        },
        None => None,
    };

    let mut rv = vec![];
    let my_h = match CString::new("MY") {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create CString for CertOpenStore: {e}");
            return Err(Error::Unrecognized);
        }
    };
    unsafe {
        let my_v: *const c_void = my_h.as_ptr() as *const c_void;
        let cert_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
            Some(my_v),
        )?;

        let mut prev_cert_context = CertEnumCertificatesInStore(cert_store, Some(null()));
        while !prev_cert_context.is_null() {
            let mut provider_info_len = 0;

            //determine the length of the key info (so we can ignore cert contexts that have no associated key provider info structure)
            if let Ok(()) = CertGetCertificateContextProperty(
                prev_cert_context,
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &mut provider_info_len,
            ) {
                match &target_skid {
                    Some(target_skid) => {
                        let der_cur_cert = std::slice::from_raw_parts(
                            (*prev_cert_context).pbCertEncoded,
                            (*prev_cert_context).cbCertEncoded as usize,
                        );
                        match Certificate::from_der(der_cur_cert) {
                            Ok(cur_cert) => {
                                if skid_match(&cur_cert, target_skid) {
                                    match CertContext::dup(NonNull::new_unchecked(
                                        prev_cert_context as *mut _,
                                    )) {
                                        Ok(cc) => rv.push(cc),
                                        Err(e) => {
                                            error!("Failed to prepare CertContext in get_credential_list: {e:?}. Continuing...")
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse certificate from MY store: {e:?}. Ignoring and continuing...");
                            }
                        };
                    }
                    None => {
                        // ought we dup the context here too?
                    }
                }
            };
            prev_cert_context = CertEnumCertificatesInStore(cert_store, Some(prev_cert_context));
        }
        if let Err(e) = CertCloseStore(cert_store, 0) {
            error!("CertCloseStore failed with {e:?}. Ignoring and continuing...");
        }
    }

    rv.sort();
    Ok(rv)
}

/// Wrapper for pointers to CRYPT_KEY_PROV_INFO objects to ensure memory is freed when no longer used.
pub(crate) struct KpiWrapper(pub NonNull<*const CRYPT_KEY_PROV_INFO>);
unsafe impl Send for KpiWrapper {}
unsafe impl Sync for KpiWrapper {}

impl Drop for KpiWrapper {
    fn drop(&mut self) {
        unsafe {
            CryptMemFree(Some(self.0.as_ptr() as *const c_void));
        }
    }
}
impl KpiWrapper {
    /// Returns the value of the pwszContainerName member as an HSTRING
    pub fn get_container_name(&self) -> Result<HSTRING> {
        unsafe {
            let kpi = self.0.as_ptr() as *const CRYPT_KEY_PROV_INFO;
            match (*kpi).pwszContainerName.to_string() {
                Ok(n) => Ok(HSTRING::from(n)),
                Err(e) => {
                    error!("Failed to convert container name: {e:?}");
                    Err(Error::Unrecognized)
                }
            }
        }
    }
    /// Returns the value of the pwszProvName member as an HSTRING
    pub fn get_provider_name(&self) -> Result<HSTRING> {
        unsafe {
            let kpi = self.0.as_ptr() as *const CRYPT_KEY_PROV_INFO;
            match (*kpi).pwszProvName.to_string() {
                Ok(n) => Ok(HSTRING::from(n)),
                Err(e) => {
                    error!("Failed to convert provider name: {e:?}");
                    Err(Error::Unrecognized)
                }
            }
        }
    }
}

/// Takes a certificate context and returns the corresponding CRYPT_KEY_PROV_INFO wrapped in a KpiWrapper. The caller
/// must not free the pointer held by the wrapper (it will be freed when the wrapper is dropped).
pub(crate) fn get_key_provider_info(cert_context: &CertContext) -> Result<KpiWrapper> {
    let mut provider_info_len = 0;

    unsafe {
        let ctx = cert_context.cert_ctx.as_ptr() as *const CERT_CONTEXT;

        CertGetCertificateContextProperty(
            ctx,
            CERT_KEY_PROV_INFO_PROP_ID,
            None,
            &mut provider_info_len,
        )?;
        let kpi = CryptMemAlloc(provider_info_len);
        CertGetCertificateContextProperty(
            ctx,
            CERT_KEY_PROV_INFO_PROP_ID,
            Some(kpi),
            &mut provider_info_len,
        )?;
        //Ok(kpi as *const CRYPT_KEY_PROV_INFO)
        Ok(KpiWrapper(NonNull::new_unchecked(
            kpi as *mut *const CRYPT_KEY_PROV_INFO,
        )))
    }
}

//------------------------------------------------------------------------------------
// Unit tests
//------------------------------------------------------------------------------------
#[test]
fn list_container_names_test() {
    use std::ptr::NonNull;
    let my_h = match CString::new("MY") {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create CString for CertOpenStore: {e}");
            panic!();
        }
    };
    unsafe {
        let my_v: *const c_void = my_h.as_ptr() as *const c_void;
        if let Ok(cert_store) = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
            Some(my_v),
        ) {
            let mut prev_cert_context = CertEnumCertificatesInStore(cert_store, Some(null()));
            while !prev_cert_context.is_null() {
                match CertContext::wrap(NonNull::new_unchecked(prev_cert_context as *mut _)) {
                    Ok(cert_context) => {
                        let kpi_wrapper = match get_key_provider_info(&cert_context) {
                            Ok(kpi_wrapper) => kpi_wrapper,
                            Err(_) => continue,
                        };

                        match kpi_wrapper.get_container_name() {
                            Ok(cont_name) => {
                                println!("pwszContainerName: {cont_name}");
                            }
                            Err(_) => {
                                continue;
                            }
                        }
                        match kpi_wrapper.get_provider_name() {
                            Ok(prov_name) => {
                                println!("pwszProvName: {prov_name}");
                            }
                            Err(_) => {
                                continue;
                            }
                        }

                        let cur_cert = cert_context.cert();
                        let subject = cur_cert.tbs_certificate.subject.to_string();
                        println!("subject: {subject}\n");
                    }
                    Err(e) => {
                        error!("Failed to prepare CertContext in list_container_names_test: {e:?}. Continuing...");
                    }
                }
                prev_cert_context =
                    CertEnumCertificatesInStore(cert_store, Some(prev_cert_context));
            }
            if let Err(e) = CertCloseStore(cert_store, 0) {
                error!("CertCloseStore failed with {e:?}. Ignoring and continuing...");
            }
        }
    }
}

#[test]
fn get_credential_list_test() {
    let certs = match get_credential_list(None) {
        Ok(certs) => certs,
        Err(_e) => panic!(),
    };
    println!("Found {} certs", certs.len());
    for cert in certs {
        if let Err(_e) = get_key_provider_info(&cert) {
            panic!()
        }
    }
}

#[tokio::test]
async fn consume_csr_test() {
    let b64_csr = "MIICmDCCAYACAQAwIzELMAkGA1UEBhMCVVMxFDASBgNVBAMMC3BsYWNlaG9sZGVy
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0g1N+p7V4+Gzp9aDsRtj
aNgW1PNWL9alMMzDPwMXHqOH1bt5Msu+WOeResAnOsWpzyovh11P1EHn7HcafC1h
lOxgpwGwE/eKjVsAjvThF86blyF+jzpshDen45P0i0VH2nYx9M2TylSc3S58Gugm
m9VndCPMC4hAMdGzygs8FAsaKjjvvtM7dqqWS03NaeyBe3cOy0jAfMQEL1VjhElh
n5MXJgxrHnAEge41y8YzrfINk/D3ZEJPUev+iWNGShIPl307fZ1AFWpB41pMb4wW
yoEEETMUItmI6bobUuJk0UZxgC6dUYtsHbT17ZRwPlSp/Hy3dZ/Iwv8aC0lBgOeD
pQIDAQABoDAwLgYJKoZIhvcNAQkOMSEwHzAdBgNVHQ4EFgQU2NNN7GLeSohd/tPx
zejm4zYkK1IwDQYJKoZIhvcNAQELBQADggEBADlDpld76TEuzV22yIJHIv97TAQY
l4Upi2G1K1PDPALWLs7IMDaEgmDVmLjxxekjnGSq5jC3qORe+08U6pWOuTtkjSfA
OyXr/MHFeXvkEzctIBrqa3yWuBm7PtTgmCQKeIdSCAWOujBcyQPcI4dvfzk0AjQe
JGcGHnRuhe0Lb6AQnG9Xg85nSNZMW0NvrmYSEfcN5dyHJFJ2h2oJzFkcYywoS9v+
TB+ir1D9Xu/n/uESLoFd4bcknbKpZ+P4/hBGqAWXHMTuM8KdGOuWqQz4loeTIIws
8pFUHfELbsFIePZ6YFbSrFNss7TAvqdRQInICdPVpMq8rRbx7yndMSrXJqQ=";
    println!("CSR - {}", b64_csr);
    let _ = consume_csr(b64_csr).await;
}

#[tokio::test]
async fn consume_csr_with_attestation_test() {
    let b64_csr = "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
EzZOQ1UtU1RNLUtFWUlELUZCMTdENzBENzM0ODcwRTkxOUM0RThFNjAzOTc1RTY2NEUwRTQzREUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDHs92vGQYBlmNhbjct3UJ1jexUMwkGLLt4IAdUQv24Ls4h9dQZyWOkGutO0iPSBsDZYmkk38KiolF7zlA/1GD5V3s/Mq/ZQCTp5fhB+qZJr5oZ
NmyOAK1uUxmevePM14996BB60Npo/2lZFn6HxsLg/o6QhthBErj8hcmrZ5E75XRKqeBHDI9j9APktvAGIRmVu9KMuKESaEVl+khH55wNZDALMa22LiNSe+v6gBMDylQ89fsx5dCjNpzKLhI559puTveGrs74rjea2DtpLjlJEQa3HGCd2nKBZTcy3a7wXa0kBKjB7r2CJNdceQdfcRwRdDt06kgVnHRPuc3s
hYW6yzCb29d9DUMYgUEMGfv6DrwnzrwkO2Y/7GvW5gm+F2pgGNE7LNNObZ5b69Wz+qttg67C8dMnkPO4hBYePQhuq4mL+kgmwypnljmKdfWpwOcSj+kV2kp6Lo2vQVClnODIc2y4r9Me5Sz88bhSbwXesI/FcGu+YbJ5/J/yazfwr8pYwLF5gxXhh4ZndVMn3pjgAOgtTHi8Rg4iDHjsuW21j6jhnOYt2MWI
2iFT7IMMpgYXMIJXyHph49opPMl46ApPUrWs51VID+trjAC2IT8M3QIFMppLwEYACOw5Tacw6HU6Krj16HemdDgmSk/KUVKt28KcYCXlw1FSLkU6ZMqnEQIDAQABo4IBjjCCAYowDgYDVR0PAQH/BAQDAgKEMBsGA1UdJQQUMBIGCSsGAQQBgjcVJAYFZ4EFCAMwFgYDVR0gBA8wDTALBgkrBgEEAYI3FR8w
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUWgorjgKv7Fk5R1uYbVuT/z9r2egwHwYDVR0jBBgwFoAUeowKzi9IYhfilNGuVcFS7HF0pFYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmlj
YXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMTQuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
AQASKoHHMuQlCZOalrVthOYmTFbmKDIdAMi2otCtygRdt3LFhPzUKZyYlGOsGcFtYfRq/fT1EbjVM6aw39JWe+yJE41HXq2d808PKYB9qj+VD0pPfqPtHIsmX6bDrssBWHRLXCtooN2ZBEn31mVsqrX1/KjKxNE1R0CelGqUTsYmcFIF/9Ys4pfgcX6TT5t8f5RX5LUGserCEDg2rEkZnfVgwUWjv92j0xwB
5+bU2AvKSP6UTPeCezFJ20SlV37hIUcp1xe7H1Y17h6A4ttrICED+plCdbh/i8WmgG57++6EN7UC+XnUhvjMY4+tPpVhFX6EzPBUQW1F+2bNDU1V1mrf5rNGR20pxc3juwUH+BBAJ1a3xKY+1b9elfmW5lTXqlAaCqxKqVSx5G3w95k53Wrz217eKI7NVAYHbQ6czumGlAseR2AFbj1CGx9VBQdFTPwf8mZJ
D9ZUli5x2VstVik2u7IcKi79vip64oxeHrBB/AmwD8FyeoPGoJomw9F1cW0XhLVqQSnFBX6OnhYpca49ZuM+Br0EvgVktcw9Q1srzKLRQHSgBxVF2fSppqehqMJ6k+nNhjpW1bRuuFrOaFPVbIEDLCMTC7ZAagwxNqFRL8g+YM2G6aIAtxb+TIgj28L4bUrzmSeN9YzG51YftH3PjQd99dbHdrxRscwV3xjj
DjGCAYswggGHAgEDgBTSf9iC1Vxk+ruRWDcGJkuLBUJLmDANBglghkgBZQMEAgEFAKBKMBcGCSqGSIb3DQEJAzEKBggrBgEFBQcMAjAvBgkqhkiG9w0BCQQxIgQglhqfDRmwQZXCdwGLQrdcLUhfFdXTeVeUKinuguVB32cwDQYJKoZIhvcNAQEBBQAEggEAXohHv2UXU2wIwIF3Ed1LzxcFMg1u25FUSXEq
5sXXiWG1QkiSTbTsabWg1TSwobpe1tR7hXK+QZpDs3g14R2eHtoRDF8WyNUzTLX+ZY/M8ZUGqvR7i1QGfWy4EusWgGqoi6gzANM0jC82ZBBmNjK0LfSlS601fF7Xy4D+YucKsAv3avzus863ADee7T2SC6dVMZH8JWuz9VP80NfSSE7TCXhU1rUc3q5qfMoFZ0ClJvK8KfK2HqQxgyUa7czrLYMK6/nS4zdGIAvZvV4NIo1G9tza3KICLJLcWYaApClXYOxg/wBVsEfI+PlOK10T1WaTuq+lOz+yfpIjIh6GBYCwYQ==";

    let _ = consume_attested_csr(b64_csr).await.unwrap(); // allow unwrap in test
}
