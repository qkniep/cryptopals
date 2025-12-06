//! # Electronic Code Book (ECB)
//!
//! This is the most naive mode of operation for block ciphers.
//! Each block is encrypted/decrypted separately.
//!
//! It allows for easy cryptanalysis if the plaintext as any structure.
//!
//! ## Usage

use cryptopals_padding::Padding;
use cryptopals_primitives::BlockCipher;
use hybrid_array::{Array, sizes::U16};

// TODO: generalize over block size
pub struct Ecb<C: BlockCipher<U16, U16>> {
    cipher: C,
}

impl<C: BlockCipher<U16, U16>> Ecb<C> {
    ///
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    ///
    pub fn encrypt(&mut self, buffer: &mut [u8], len: usize) {
        todo!()
    }

    ///
    pub fn encrypt_padded<P: Padding<U16>>(&mut self, bytes: &mut [u8], len: usize) {
        assert!(bytes.len().is_multiple_of(C::BLOCK_SIZE));
        P::pad_bytes(bytes, len);
        for chunk in bytes.chunks_exact_mut(C::BLOCK_SIZE) {
            self.cipher.encrypt_block_in_place(chunk);
        }
    }

    ///
    pub fn decrypt(&mut self, bytes: &mut [u8], len: usize) {
        todo!()
    }

    ///
    pub fn decrypt_padded<'a, P: Padding<U16>>(&mut self, bytes: &'a mut [u8]) -> &'a [u8] {
        let unpadded_len = P::unpad_bytes(bytes).len();
        for chunk in bytes.chunks_exact_mut(C::BLOCK_SIZE) {
            self.cipher.decrypt_block_in_place(chunk);
        }
        &bytes[..unpadded_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {}
}
