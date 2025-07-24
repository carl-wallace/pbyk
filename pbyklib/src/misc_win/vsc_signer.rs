//! Provides a wrapper for pointers to [CERT_CONTEXT](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/struct.CERT_CONTEXT.html) objects to ensure memory is freed when no longer used, to allow for
//! thread safety, and to provide [Signer](https://docs.rs/signature/latest/signature/trait.Signer.html) implementation.

#![cfg(all(target_os = "windows", feature = "vsc"))]

use der::Decode;
use std::cmp::Ordering;
use std::{ffi::c_void, ptr::NonNull};

use log::{debug, error};
use rsa::RsaPublicKey;
use windows::{
    Win32::Security::Cryptography::{
        BCRYPT_PAD_PKCS1, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT,
        CERT_KEY_SPEC, CRYPT_KEY_PROV_INFO, CertDuplicateCertificateContext,
        CertFreeCertificateContext, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSignHash,
    },
    core::PCWSTR,
};

use sha2::{Digest, Sha256};
use signature::{Keypair, Signer};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};
use x509_cert::Certificate;

use pbykcorelib::misc::scep::get_rsa_key_from_cert;

use crate::Error::BadInput;
use crate::{Error, Result, misc_win::csr::get_key_provider_info};

/// Wrapper for pointers to [CERT_CONTEXT](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/struct.CERT_CONTEXT.html)
/// objects to ensure memory is freed when no longer used, to allow for thread safety, and to provide [Signer](https://docs.rs/signature/latest/signature/trait.Signer.html)
/// implementation.
///
/// When used to wrap certificates in a loop that destroys the contexts organically, i.e., when enumerating cert store
/// contents, create an instance using `wrap`. This will cause the wrapper to refrain from deleting the context.
///
/// When used to wrap certificates that are not organically deleted, use `dup`. This will cause the CERT_CONTEXT pointer
/// to be freed when the `CertContext` is dropped.
///
/// Ordering on CertContext objects is done using the notBefore value.
///
/// The `cert` field must not be freed by users of this wrapper.
#[derive(Debug, Eq, PartialEq)]
pub struct CertContext {
    /// Wrapped CERT_CONTEXT pointer
    pub cert_ctx: NonNull<*const CERT_CONTEXT>,
    /// Indicates whether cert member should be freed when CertContext instance is dropped
    free: bool,
    /// Parsed certificate
    pub cert: Certificate,
    /// RsaPublicKey extracted from certificate
    rsa: RsaPublicKey,
}

impl PartialOrd for CertContext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CertContext {
    fn cmp(&self, other: &Self) -> Ordering {
        let other_nb = other
            .cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();
        let self_nb = self
            .cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        self_nb.cmp(&other_nb)
    }
}

impl CertContext {
    /// Returns parsed certificate
    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    /// Used to wrap certificates that freed by the caller, for example, when enumerating cert store contents. [CertContext]
    /// instances created with wrap will not free the [CERT_CONTEXT](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/struct.CERT_CONTEXT.html)
    /// pointer when the instance is dropped. The caller must
    /// ensure the [CertContext] instance is not used after the CERT_CONTEXT pointer passed as `cert_to_wrap` is freed.
    pub fn wrap(cert_to_wrap: NonNull<*const CERT_CONTEXT>) -> Result<Self> {
        let der_cert = unsafe {
            let ctx = cert_to_wrap.as_ptr() as *const CERT_CONTEXT;
            std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize)
        };
        let cert = Certificate::from_der(der_cert)?;
        let rsa = match get_rsa_key_from_cert(&cert) {
            Ok(k) => k,
            Err(e) => {
                error!("Failed to get RSA key from certificate: {e:?}");
                return Err(Error::Pbykcorelib(e));
            }
        };

        Ok(CertContext {
            cert_ctx: cert_to_wrap,
            free: false,
            cert,
            rsa,
        })
    }

    /// Used to wrap certificates that are not freed by the caller, for example, when the context must outlive the certificate
    /// store from which it was received. [CertContext] instances created with dup will create a copy of the [CERT_CONTEXT](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/struct.CERT_CONTEXT.html)
    /// pointer using [CertDuplicateCertificateContext](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/fn.CertDuplicateCertificateContext.html) then free that when the instance is dropped. The caller is
    /// responsible for freeing the pointer passed as `cert_to_dup`.
    pub fn dup(cert_to_dup: NonNull<*const CERT_CONTEXT>) -> Result<Self> {
        unsafe {
            let dup_cert =
                CertDuplicateCertificateContext(Some(cert_to_dup.as_ptr() as *const CERT_CONTEXT));
            if dup_cert.is_null() {
                error!("Failed to duplicate CERT_CONTEXT");
                return Err(BadInput);
            }
            let der_cert = std::slice::from_raw_parts(
                (*dup_cert).pbCertEncoded,
                (*dup_cert).cbCertEncoded as usize,
            );
            let cert = Certificate::from_der(der_cert)?;
            let rsa = match get_rsa_key_from_cert(&cert) {
                Ok(k) => k,
                Err(e) => {
                    error!("Failed to get RSA key from certificate: {e:?}");
                    return Err(Error::Pbykcorelib(e));
                }
            };
            Ok(CertContext {
                cert_ctx: NonNull::new_unchecked(dup_cert as *mut _),
                free: true,
                cert,
                rsa,
            })
        }
    }
}
impl Drop for CertContext {
    fn drop(&mut self) {
        if self.free {
            unsafe {
                let _ =
                    CertFreeCertificateContext(Some(self.cert_ctx.as_ptr() as *const CERT_CONTEXT));
            }
        }
    }
}

unsafe impl Send for CertContext {}
unsafe impl Sync for CertContext {}

/// RSA w/ SHA256 implementation for CertContext
impl Signer<rsa::pkcs1v15::Signature> for CertContext {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<rsa::pkcs1v15::Signature> {
        unsafe {
            let kpi_wrapper = match get_key_provider_info(self) {
                Ok(kpi_wrapper) => kpi_wrapper,
                Err(e) => {
                    error!("Failed to get CRYPT_KEY_PROV_INFO for CERT_CONTEXT in try_sign: {e:?}");
                    return Err(signature::Error::default());
                }
            };
            let kpi = kpi_wrapper.0.as_ptr() as *const CRYPT_KEY_PROV_INFO;
            debug!(
                "Found CRYPT_KEY_PROV_INFO with provider {} and container {} in try_sign",
                (*kpi).pwszProvName.to_string().unwrap_or_default(),
                (*kpi).pwszContainerName.to_string().unwrap_or_default()
            );
            let prov_handle = &mut NCRYPT_PROV_HANDLE(0) as *mut NCRYPT_PROV_HANDLE;
            let prov_name: PCWSTR = PCWSTR::from_raw((*kpi).pwszProvName.as_ptr());

            if let Err(e) = NCryptOpenStorageProvider(prov_handle, prov_name, 0) {
                error!("NCryptOpenStorageProvider failed in try_sign: {e:?}");
                return Err(signature::Error::default());
            }

            let key_handle = &mut NCRYPT_KEY_HANDLE(0) as *mut NCRYPT_KEY_HANDLE;
            if let Err(e) = NCryptOpenKey(
                *prov_handle,
                key_handle,
                PCWSTR::from_raw((*kpi).pwszContainerName.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            ) {
                error!("NCryptOpenKey failed in try_sign: {e:?}");
                return Err(signature::Error::default());
            }

            let mut pi = BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
            };
            let pkcs1_padding_info = &mut pi as *mut _ as *const c_void;

            let hash = Sha256::digest(msg).to_vec();
            let mut sig_len = 0;
            if let Err(e) = NCryptSignHash(
                *key_handle,
                Some(pkcs1_padding_info),
                &hash,
                None,
                &mut sig_len,
                NCRYPT_FLAGS(BCRYPT_PAD_PKCS1.0),
            ) {
                error!("NCryptSignHash failed to read signature length in try_sign: {e:?}");
                return Err(signature::Error::default());
            }

            let mut sig = vec![0u8; sig_len as usize];
            if let Err(e) = NCryptSignHash(
                *key_handle,
                Some(pkcs1_padding_info),
                &hash,
                Some(&mut sig),
                &mut sig_len,
                NCRYPT_FLAGS(BCRYPT_PAD_PKCS1.0),
            ) {
                error!("NCryptSignHash failed in try_sign: {e:?}");
                return Err(signature::Error::default());
            }
            debug!("NCryptSignHash succeeded in try_sign");
            rsa::pkcs1v15::Signature::try_from(sig.as_slice())
        }
    }
}

impl Keypair for CertContext {
    type VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha256>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.rsa.clone().into()
    }
}

impl DynSignatureAlgorithmIdentifier for CertContext {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        self.verifying_key().signature_algorithm_identifier()
    }
}
