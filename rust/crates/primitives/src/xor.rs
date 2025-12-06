//! Simple XOR cipher.
//!
//!

/// Encrypts the input with the given key.
///
/// Supports both fixed and repeating keys.
/// To be specific about the type of key, call either [`encrypt_fixed`] or [`encrypt_repeating`].
pub fn encrypt(plaintext: &mut [u8], key: &[u8]) {
    if plaintext.len() == key.len() {
        encrypt_fixed(plaintext, key)
    } else {
        encrypt_repeating(plaintext, key)
    }
}

/// Encrypts the input with a fixed key.
///
/// Panics if the key is not the same length as the input.
pub fn encrypt_fixed(plaintext: &mut [u8], key: &[u8]) {
    assert_eq!(plaintext.len(), key.len());
    for (p, k) in plaintext.iter_mut().zip(key.iter()) {
        *p ^= k;
    }
}

/// Encrypts the input with a repeating key.
///
/// The input is XORed with the first `plaintext.len()` bytes of `key || key || ...`.
pub fn encrypt_repeating(plaintext: &mut [u8], key: &[u8]) {
    for (p, k) in plaintext.iter_mut().zip(key.iter().cycle()) {
        *p ^= k;
    }
}

/// Decrypts the input with the given key.
///
/// Supports both fixed and repeating keys.
/// To be specific about the type of key, call either [`decrypt_fixed`] or [`decrypt_repeating`].
pub fn decrypt(ciphertext: &mut [u8], key: &[u8]) {
    encrypt(ciphertext, key)
}

/// Decrypts the input with a fixed key.
///
/// Panics if the key is not the same length as the input.
pub fn decrypt_fixed(ciphertext: &mut [u8], key: &[u8]) {
    encrypt_fixed(ciphertext, key)
}

/// Decrypts the input with a repeating key.
///
/// The input is XORed with the first `ciphertext.len()` bytes of `key || key || ...`.
pub fn decrypt_repeating(ciphertext: &mut [u8], key: &[u8]) {
    encrypt_repeating(ciphertext, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {}
}
