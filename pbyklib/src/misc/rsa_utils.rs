//! RSA-related utility functions

// poached from RSA crate
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Processes decrypted RSA block containing a KEK and returns the KEK. This was poached from
/// <https://github.com/RustCrypto/RSA/blob/40069a5408dc9eb531d68a50b3ada5c9ab47466d/src/algorithms/pkcs1v15.rs>
#[inline]
pub(crate) fn decrypt_inner(em: Vec<u8>, k: usize) -> crate::Result<(u8, Vec<u8>, u32)> {
    if k < 11 {
        return Err(crate::Error::Decryption);
    }

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   looking_for_index: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut looking_for_index = 1u8;
    let mut index = 0u32;

    for (i, el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.conditional_assign(&(i as u32), Choice::from(looking_for_index) & equals0);
        looking_for_index.conditional_assign(&0u8, equals0);
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    // TODO: WARNING: THIS MUST BE CONSTANT TIME CHECK:
    // Ref: https://github.com/dalek-cryptography/subtle/issues/20
    // This is currently copy & paste from the constant time impl in
    // go, but very likely not sufficient.
    let valid_ps = Choice::from((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid =
        first_byte_is_zero & second_byte_is_two & Choice::from(!looking_for_index & 1) & valid_ps;
    index = u32::conditional_select(&0, &(index + 1), valid);

    Ok((valid.unwrap_u8(), em, index))
}
