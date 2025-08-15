//! Adaptation of Signer implementation in yubikey crate with an Arc Mutex wrapping the RefCell so that signer instance
//! can be passed to async methods in multithreaded applications.

use core::ops::Deref;
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use log::error;

use signature::Keypair;
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoRef};
use yubikey::{
    YubiKey,
    certificate::yubikey_signer::KeyType,
    piv::{SlotId, sign_data},
};

/// Adaptation of Signer implementation in yubikey crate with an Arc Mutex wrapping the RefCell so that signer instance
/// can be passed to async methods in multithreaded applications.
pub struct YkSigner<'y, KT: KeyType> {
    /// Reference to a YubiKey
    yubikey: Arc<Mutex<RefCell<&'y mut YubiKey>>>,
    /// SlotId to use for signing
    key: SlotId,
    /// Public key from that slot
    public_key: KT::VerifyingKey,
}

impl<'y, KT: KeyType> YkSigner<'y, KT> {
    /// Create new Signer
    pub fn new(
        yubikey: &'y mut YubiKey,
        key: SlotId,
        subject_pki: SubjectPublicKeyInfoRef<'_>,
    ) -> yubikey::Result<Self> {
        let public_key =
            KT::PublicKey::try_from(subject_pki).map_err(|_| yubikey::Error::ParseError)?;
        let public_key = public_key.into();

        Ok(Self {
            yubikey: Arc::new(Mutex::new(RefCell::new(yubikey))),
            key,
            public_key,
        })
    }
}

impl<KT: KeyType> Keypair for YkSigner<'_, KT> {
    type VerifyingKey = KT::VerifyingKey;
    fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
        self.public_key.clone()
    }
}

impl<KT: KeyType> DynSignatureAlgorithmIdentifier for YkSigner<'_, KT> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        self.verifying_key().signature_algorithm_identifier()
    }
}

/// Error type
type YkSigResult<T> = Result<T, signature::Error>;
impl<KT: KeyType> signature::Signer<KT::Signature> for YkSigner<'_, KT> {
    fn try_sign(&self, msg: &[u8]) -> YkSigResult<KT::Signature> {
        let data = KT::prepare(msg)?;

        let yk = match self.yubikey.lock() {
            Ok(yk) => yk,
            Err(e) => {
                error!("Failed to lock YubiKey: {e:?}");
                return Err(signature::Error::from_source(yubikey::Error::GenericError));
            }
        };

        let out = sign_data(&mut yk.deref().borrow_mut(), &data, KT::ALGORITHM, self.key)
            .map_err(signature::Error::from_source)?;
        let out = KT::read_signature(&out)?;
        Ok(out)
    }
}
