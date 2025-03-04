//! CAPI certificate store cleanup support

#![cfg(target_os = "windows")]

use std::{
    ffi::{CString, c_void},
    ptr::null,
};

use log::error;

#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use windows::{Security::Cryptography::Certificates::CertificateStores, core::HSTRING};

use windows::Win32::Security::Cryptography::{
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_A, CertCloseStore,
    CertDeleteCertificateFromStore, CertEnumCertificatesInStore, CertOpenStore,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use crate::misc::utils::buffer_to_hex;
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use sha2::{Digest, Sha256};

use crate::CERT_SYSTEM_STORE_CURRENT_USER;

/// Takes a DER-encoded certificate and tries to remove it from the current user's store of the given store name. Any
/// failure to delete is logged but the app tries to continue without error.
pub(crate) fn delete_cert_from_named_store(cert_bytes: &[u8], store_name: &CString) {
    unsafe {
        if let Ok(cert_store) = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
            Some(store_name.as_ptr() as *const c_void),
        ) {
            let mut prev_cert_context = CertEnumCertificatesInStore(cert_store, Some(null()));
            while !prev_cert_context.is_null() {
                if (*prev_cert_context).cbCertEncoded == cert_bytes.len() as u32 {
                    let der_cur_cert = std::slice::from_raw_parts(
                        (*prev_cert_context).pbCertEncoded,
                        (*prev_cert_context).cbCertEncoded as usize,
                    );

                    if der_cur_cert == cert_bytes {
                        if let Err(e) = CertDeleteCertificateFromStore(prev_cert_context) {
                            error!("CertDeleteCertificateFromStore failed with {e:?}");
                        }
                        // assuming cert is only present once
                        break;
                    }
                }

                prev_cert_context =
                    CertEnumCertificatesInStore(cert_store, Some(prev_cert_context));
            }

            let _ = CertCloseStore(cert_store, 0);
        }
    }
}

/// Takes a certificate and tries to remove it from the current user's MY and CA stores. That it tries the CA store is
/// an artifact of how InstallCertificateAsync works (there is never a reason to install the cert into the CA store but
/// since that happens, try to delete it). Any failure to delete is logged but the app tries to continue without error.
pub(crate) fn delete_cert_from_store(cert_bytes: &[u8]) {
    match CString::new("MY") {
        Ok(my) => delete_cert_from_named_store(cert_bytes, &my),
        Err(e) => {
            error!("Failed to create CString with MY for CertOpenStore: {e}");
        }
    };

    match CString::new("CA") {
        Ok(ca) => delete_cert_from_named_store(cert_bytes, &ca),
        Err(e) => {
            error!("Failed to create CString with CA for CertOpenStore: {e}");
        }
    };
}

#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use crate::utils::reset_vsc::CertDelete;

/// Takes a DER-encoded certificate and tries to remove it from the current user's store of the given store name. Any
/// failure to delete is logged but the app tries to continue without error.
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
pub(crate) async fn delete_cert_hashes_from_named_store(hashes: &[String], store_name: &CString) {
    let mut to_delete = vec![];
    unsafe {
        if let Ok(cert_store) = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
            Some(store_name.as_ptr() as *const c_void),
        ) {
            let mut prev_cert_context = CertEnumCertificatesInStore(cert_store, Some(null()));
            while !prev_cert_context.is_null() {
                let der_cur_cert = std::slice::from_raw_parts(
                    (*prev_cert_context).pbCertEncoded,
                    (*prev_cert_context).cbCertEncoded as usize,
                );
                let hash = Sha256::digest(der_cur_cert);
                let hex_hash = buffer_to_hex(&hash);
                if hashes.contains(&hex_hash) {
                    to_delete.push(der_cur_cert.to_vec());
                }

                prev_cert_context =
                    CertEnumCertificatesInStore(cert_store, Some(prev_cert_context));
            }

            let _ = CertCloseStore(cert_store, 0);
        }
    }

    match CertificateStores::GetUserStoreByName(&HSTRING::from("MY")) {
        Ok(cs) => {
            for c in to_delete {
                // delete_cert_from_named_store(&c, store_name);
                CertDelete::delete(&c, &cs).await;
            }
        }
        Err(e) => {
            error!("Failed to get MY user store by name: {e:?}");
        }
    }
}
