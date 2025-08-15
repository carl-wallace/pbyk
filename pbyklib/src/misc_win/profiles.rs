//! Profile to create device certificates for enrolling with Purebred using CertificateBuilder

use std::vec;

use spki::SubjectPublicKeyInfoRef;
use x509_cert::{TbsCertificate, builder::profile::BuilderProfile};
use x509_cert::{
    ext::{
        AsExtension, Extension,
        pkix::{AuthorityKeyIdentifier, KeyUsage, KeyUsages, SubjectKeyIdentifier},
    },
    name::Name,
};

/// Structure for profile used to build device certificates for Purebred use
#[allow(clippy::missing_docs_in_private_items)]
pub struct PurebredDevCert {
    /// issuer   Name,
    /// represents the name signing the certificate
    pub issuer: Name,

    subject: Name,
}

impl PurebredDevCert {
    /// Create a new Purebred device certficate
    pub fn new(issuer: Name, subject: Name) -> crate::Result<Self> {
        Ok(Self { issuer, subject })
    }
}
impl BuilderProfile for PurebredDevCert {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> std::result::Result<Vec<Extension>, x509_cert::builder::Error> {
        let mut extensions: vec::Vec<Extension> = vec::Vec::new();

        let ski = SubjectKeyIdentifier::try_from(spk)?;

        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(tbs.subject(), &extensions)?,
        );

        let mut key_usage = KeyUsages::DigitalSignature.into();
        key_usage |= KeyUsages::KeyEncipherment;
        extensions.push(KeyUsage(key_usage).to_extension(tbs.subject(), &extensions)?);

        extensions.push(ski.to_extension(tbs.subject(), &extensions)?);
        Ok(extensions)
    }
}
