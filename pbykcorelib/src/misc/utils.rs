//! Utility functions for use within pbyklib

use std::{io::Cursor, str::FromStr};

use log::error;
use plist::Dictionary;
use subtle_encoding::hex;

use sha2::{Digest, Sha256};
use signature::Signer;

use certval::CertificationPathSettings;
use certval_cms::{SignedDataBuilder, Signer as CmsSigner, SignerCredential, SignerPolicy};
use cms::{
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    enveloped_data::RecipientIdentifier,
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use const_oid::{
    ObjectIdentifier,
    db::{rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER, rfc5911::ID_DATA},
};
use der::{Decode, Encode, asn1::OctetString};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::{Certificate, attr::Attribute, ext::pkix::SubjectKeyIdentifier, name::Name};

use crate::{
    Error, Result,
    misc::pki::{new_cms_environment, new_pki_environment, pki_environment_for},
};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// A signer borrowed for one SignedData. [`SignerCredential`] holds its signer by value, and the
/// signers here are borrowed from a device connection that outlives the message.
struct BorrowedSigner<'a, S>(&'a S);

impl<S, Sig> Signer<Sig> for BorrowedSigner<'_, S>
where
    S: Signer<Sig>,
{
    fn try_sign(&self, msg: &[u8]) -> core::result::Result<Sig, signature::Error> {
        self.0.try_sign(msg)
    }
}

impl<S> DynSignatureAlgorithmIdentifier for BorrowedSigner<'_, S>
where
    S: DynSignatureAlgorithmIdentifier,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        self.0.signature_algorithm_identifier()
    }
}

/// Builds a SignedData over `content` of type `content_type`, signed once by `signer` with
/// `attributes` beyond the content-type and message-digest attributes, and carrying `signers_cert`
/// as its only certificate.
///
/// The message has the shape the portals have always received from this crate: the signer
/// identified by the certificate's subject key identifier, the signed attributes hashed with the
/// digest the signer's algorithm uses (RFC 5754), and no signing-certificate attribute.
pub(crate) fn build_signed_data<S, Sig>(
    signer: &S,
    signers_cert: Certificate,
    content: &[u8],
    content_type: ObjectIdentifier,
    attributes: Vec<Attribute>,
) -> Result<Vec<u8>>
where
    S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
    let env = new_cms_environment(new_pki_environment());
    let credential: SignerCredential<_, Sig> =
        SignerCredential::new(signers_cert, BorrowedSigner(signer));
    let mut cms_signer = CmsSigner::explicit(&credential).without_ess_cert_id();
    for attribute in attributes {
        cms_signer = cms_signer.signed_attribute(attribute);
    }
    let built = SignedDataBuilder::new(content)
        .content_type(content_type)
        .add_signer(cms_signer)
        .build(&env)
        .map_err(|e| {
            error!("Failed to build SignedData: {e}");
            Error::from(e)
        })?;
    Ok(built.content_info.to_der()?)
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Accepts a buffer that notionally contains a PList containing a Dictionary with an
/// EncryptedPayloadContent entry. Returns the contents of entry upon success and an error otherwise
pub fn get_encrypted_payload_content(xml: &[u8]) -> Result<Vec<u8>> {
    let xml_cursor = Cursor::new(xml);
    let profile = plist::Value::from_reader(xml_cursor).map_err(|_e| Error::Plist)?;

    let profile_dict = match profile.as_dictionary() {
        Some(d) => d,
        None => {
            error!("Failed to parse profile as a dictionary");
            return Err(Error::Plist);
        }
    };

    match profile_dict.get("EncryptedPayloadContent") {
        Some(p) => match p.as_data() {
            Some(v) => Ok(v.to_vec()),
            None => {
                error!("Failed to read data from EncryptedPayloadContent entry");
                Err(Error::Plist)
            }
        },
        None => {
            error!("Profile did not contain an EncryptedPayloadContent entry");
            Err(Error::Plist)
        }
    }
}

/// Takes a buffer and returns a String containing an ASCII hex representation of the buffer's contents
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = std::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        String::new()
    }
}

/// Takes an EncapsulatedContentInfo and returned the encapsulated content as a buffer. Do not
/// log error information before returning.
pub fn get_encap_content(eci: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    let encap = match &eci.econtent {
        Some(e) => e,
        None => return Err(Error::ParseError),
    };

    let enc_os = encap.to_der()?;
    let os = OctetString::from_der(&enc_os)?;
    Ok(os.as_bytes().to_vec())
}

/// Processes the provided content as a SignedData message and verifies the signer's certificate relative to the given
/// environment. Returns the encapsulated content as a byte array.
///
/// A signer verifies when its message digest matches the content, its signature verifies with the
/// platform's crypto provider, and its certificate validates to the trust anchors compiled in for
/// `env`, building through any CA certificates the message carries. One verified signer is enough.
/// Revocation is not checked: the device holds no revocation data for the portal's certificates.
pub async fn purebred_authorize_request(content: &[u8], env: &str) -> Result<Vec<u8>> {
    let content_info = ContentInfo::from_der(content)?;
    let cms_env = new_cms_environment(pki_environment_for(env)?);
    let mut settings = CertificationPathSettings::new();
    settings.set_check_revocation_status(false);
    match cms_env.verify_signed_data(&content_info, None, Some(&settings), SignerPolicy::Any) {
        Ok(verified) => Ok(verified.content),
        Err(e) => {
            error!("Failed to verify SignedData in purebred_authorize_request: {e}");
            Err(Error::BadInput)
        }
    }
}

/// Create a SKID-based SignerIdentifier from certificate
pub fn signer_identifier_from_cert(cert: &Certificate, use_skid: bool) -> Result<SignerIdentifier> {
    if use_skid {
        let skid_bytes = skid_from_cert(cert)?;
        let os = match OctetString::new(skid_bytes) {
            Ok(os) => os,
            Err(e) => return Err(Error::Asn1(e)),
        };
        let skid = SubjectKeyIdentifier::from(os);

        Ok(SignerIdentifier::SubjectKeyIdentifier(skid))
    } else {
        let ias = IssuerAndSerialNumber {
            issuer: cert.tbs_certificate().issuer().clone(),
            serial_number: cert.tbs_certificate().serial_number().clone(),
        };
        Ok(SignerIdentifier::IssuerAndSerialNumber(ias))
    }
}

/// Create a SKID-based RecipientIdentifier from certificate
pub fn recipient_identifier_from_cert(cert: &Certificate) -> Result<RecipientIdentifier> {
    let skid_bytes = skid_from_cert(cert)?;
    let os = match OctetString::new(skid_bytes) {
        Ok(os) => os,
        Err(e) => return Err(Error::Asn1(e)),
    };
    let skid = SubjectKeyIdentifier::from(os);

    Ok(RecipientIdentifier::SubjectKeyIdentifier(skid))
}

/// Generates a SignedData object covering `data_to_sign`, signed by `signer`, whose certificate is
/// `signers_cert`. The content is of type `encap_type`, id-data when `None`.
pub fn get_signed_data<S, Sig>(
    signer: &S,
    signers_cert: &Certificate,
    data_to_sign: &[u8],
    encap_type: Option<ObjectIdentifier>,
) -> Result<Vec<u8>>
where
    S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
    build_signed_data(
        signer,
        signers_cert.clone(),
        data_to_sign,
        encap_type.unwrap_or(ID_DATA),
        vec![],
    )
}

/// Extract SKID extension value from certificate or calculate a SKID value from the SubjectPublicKeyInfo
pub fn skid_from_cert(cert: &Certificate) -> Result<Vec<u8>> {
    if let Some(exts) = cert.tbs_certificate().extensions() {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
                match OctetString::from_der(ext.extn_value.as_bytes()) {
                    Ok(b) => return Ok(b.as_bytes().to_vec()),
                    Err(e) => {
                        error!(
                            "Failed to parse SKID extension: {e:?}. Ignoring error and will use calculated value."
                        );
                    }
                }
            }
        }
    }

    let working_spki = cert.tbs_certificate().subject_public_key_info();
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            error!("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

/// Returns a vector containing distinct `rfc822Name` values read from `SubjectAltName` entries in `dict`.
/// When no `rfc822Name` values are found, an empty vector is returned.
pub fn get_email_addresses(dict: &Dictionary) -> Vec<String> {
    let mut rv: Vec<String> = vec![];
    if let Some(san) = dict.get("SubjectAltName")
        && let Some(san) = san.as_dictionary()
        && let Some(rfc822_names) = san.get("rfc822Name")
        && let Some(rfc822_names) = rfc822_names.as_array()
    {
        for email in rfc822_names {
            if let Some(s) = email.as_string() {
                let c = s.to_string();
                if !rv.contains(&c) {
                    rv.push(c);
                }
            }
        }
    }
    rv
}

/// Returns "Keysize" value read from provided dictionary. Defaults to 2048 if key is not found.
pub fn get_key_size(dict: &Dictionary) -> i32 {
    let mut retval = 2048;
    if let Some(san) = dict.get("Keysize")
        && let Some(size) = san.as_signed_integer()
    {
        retval = size as i32;
    }
    retval
}

/// Returns a Name prepared using elements in the `Subject` entry in `dict`
pub fn get_subject_name(dict: &Dictionary) -> Result<Name> {
    let mut dn = vec![];
    if let Some(subject_array) = dict.get("Subject") {
        if let Some(subject_array) = subject_array.as_array() {
            for elem in subject_array.iter().rev() {
                if let Some(rdns) = elem.as_array() {
                    let mut rdn_vec = vec![];
                    for rdn in rdns {
                        if let Some(type_and_val) = rdn.as_array()
                            && 2 == type_and_val.len()
                        {
                            let rdn_type = match type_and_val[0].as_string() {
                                Some(t) => t,
                                None => return Err(Error::Plist),
                            };
                            let rdn_value = match type_and_val[1].as_string() {
                                Some(t) => t,
                                None => return Err(Error::Plist),
                            };
                            rdn_vec.push(format!("{rdn_type}={rdn_value}"));
                        }
                    }
                    dn.push(rdn_vec.join("+"))
                } else {
                    error!("Failed to an RDN entry as an array");
                    return Err(Error::Plist);
                }
            }
        } else {
            error!("Failed to parse Subject entry as an array");
            return Err(Error::Plist);
        }
    } else {
        error!("No Subject entry was found in the dictionary");
        return Err(Error::Plist);
    }

    let s = dn.join(",");
    match Name::from_str(&s) {
        Ok(n) => Ok(n),
        Err(e) => Err(Error::Asn1(e)),
    }
}

/// Retrieves the value associated with the given key from the given dictionary as a String if possible
pub fn get_as_string(dict: &Dictionary, key: &str) -> Option<String> {
    if let Some(value) = dict.get(key)
        && let Some(rv) = value.as_string()
    {
        Some(rv.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RFC8894_ID_MESSAGE_TYPE, RFC8894_ID_SENDER_NONCE, RFC8894_ID_TRANSACTION_ID,
        misc::{
            rng::pb_rng,
            scep::{prepare_enveloped_data, prepare_scep_signed_data},
        },
    };
    use certval_cms::{SoftwareRecipientKey, VerifiedSignedData};
    use rsa::{PrivateKey as RsaPrivateKey, pkcs1v15::SigningKey, pkcs8::EncodePrivateKey};
    use signature::Keypair;
    use x509_cert::{
        TbsCertificate,
        builder::{Builder, CertificateBuilder, profile::BuilderProfile},
        ext::Extension,
        serial_number::SerialNumber,
        spki::{EncodePublicKey, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef},
        time::Validity,
    };

    /// `id-aa-signingCertificateV2` (RFC 5035), which these messages do not carry.
    const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

    /// Issues a self-signed certificate with a subject key identifier, as the device's own
    /// certificates have.
    struct SelfSigned(Name);

    impl BuilderProfile for SelfSigned {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.0.clone()
        }
        fn get_subject(&self) -> Name {
            self.0.clone()
        }
        fn build_extensions(
            &self,
            spk: SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: SubjectPublicKeyInfoRef<'_>,
            _tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let skid = SubjectKeyIdentifier(
                OctetString::new(Sha256::digest(spk.subject_public_key.raw_bytes()).to_vec())
                    .unwrap(),
            );
            Ok(vec![Extension {
                extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
                critical: false,
                extn_value: OctetString::new(skid.to_der().unwrap()).unwrap(),
            }])
        }
    }

    /// A software RSA signer, its self-signed certificate and its PKCS #8 key.
    fn device_credential() -> (SigningKey<Sha256>, Certificate, Vec<u8>) {
        let key = RsaPrivateKey::new(&mut pb_rng(), 2048).unwrap();
        let pkcs8 = key.to_pkcs8_der().unwrap();
        let signer = SigningKey::<Sha256>::new(key);
        let spki = signer.verifying_key().to_public_key_der().unwrap();
        let cert = CertificateBuilder::new(
            SelfSigned(Name::from_str("CN=pbykcorelib test device").unwrap()),
            SerialNumber::new(&[1]).unwrap(),
            Validity::from_now(core::time::Duration::from_secs(600)).unwrap(),
            SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).unwrap(),
        )
        .unwrap()
        .build::<_, rsa::pkcs1v15::Signature>(&signer)
        .unwrap();
        (signer, cert, pkcs8.as_bytes().to_vec())
    }

    /// Verifies the signatures of `signed` without vetting the signer's certificate.
    fn verify(signed: &[u8]) -> VerifiedSignedData {
        let env = new_cms_environment(new_pki_environment());
        let content_info = ContentInfo::from_der(signed).unwrap();
        env.verify_signed_data(&content_info, None, None, SignerPolicy::All)
            .unwrap()
    }

    #[test]
    fn signed_data_verifies_and_keeps_its_shape() {
        let (signer, cert, _) = device_credential();
        let signed = get_signed_data(&signer, &cert, b"phase 2 request", None).unwrap();
        let verified = verify(&signed);
        assert_eq!(verified.content_type, ID_DATA);
        assert_eq!(verified.content, b"phase 2 request");
        assert_eq!(verified.signers.len(), 1);
        let signer = &verified.signers[0];
        assert_eq!(signer.certificate, cert);
        assert!(matches!(
            signer.sid,
            SignerIdentifier::SubjectKeyIdentifier(_)
        ));
        let attrs = signer.signed_attributes.as_ref().unwrap();
        assert!(attrs.iter().all(|a| a.oid != ID_AA_SIGNING_CERTIFICATE_V2));
    }

    #[test]
    fn scep_signed_data_carries_the_pkcsreq_attributes() {
        let (signer, cert, _) = device_credential();
        let signed = prepare_scep_signed_data(&signer, cert, b"enveloped data").unwrap();
        let verified = verify(&signed);
        let attrs = verified.signers[0].signed_attributes.as_ref().unwrap();
        let oids: Vec<ObjectIdentifier> = attrs.iter().map(|a| a.oid).collect();
        for oid in [
            *RFC8894_ID_MESSAGE_TYPE,
            *RFC8894_ID_SENDER_NONCE,
            *RFC8894_ID_TRANSACTION_ID,
        ] {
            assert!(oids.contains(&oid), "{oid} missing");
        }
        assert!(!oids.contains(&ID_AA_SIGNING_CERTIFICATE_V2));
    }

    #[test]
    fn enveloped_data_decrypts_with_the_recipients_key() {
        let (_, cert, pkcs8) = device_credential();
        let enveloped = prepare_enveloped_data(b"a CSR", &cert).unwrap();
        let env = new_cms_environment(new_pki_environment());
        let key = SoftwareRecipientKey::from_pkcs8_der(cert, &pkcs8).unwrap();
        let content_info = ContentInfo::from_der(&enveloped).unwrap();
        let decrypted = env
            .decrypt_enveloped_data(&content_info, Some(&key))
            .unwrap();
        assert_eq!(decrypted.content.as_slice(), b"a CSR");
        assert!(matches!(
            decrypted.recipient,
            RecipientIdentifier::SubjectKeyIdentifier(_)
        ));
    }

    /// The trust anchors compiled in are the portal's; a self-signed signer has no path to them.
    #[cfg(feature = "dev")]
    #[tokio::test]
    async fn authorize_request_rejects_a_signer_outside_the_environment() {
        let (signer, cert, _) = device_credential();
        let signed = get_signed_data(&signer, &cert, b"not from the portal", None).unwrap();
        assert_eq!(
            purebred_authorize_request(&signed, "dev").await,
            Err(Error::BadInput)
        );
    }
}
