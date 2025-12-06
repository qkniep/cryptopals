//! # Cipher Block Chaining (CBC)
//!
//! ## Usage

use cryptopals_padding::{Padding, pkcs7::Pkcs7};
use cryptopals_primitives::{BlockCipher, xor};
use hybrid_array::sizes::U16;
use hybrid_array::{Array, ArraySize};

// TODO: generalize over block size
pub struct Cbc<C: BlockCipher<U16, U16>> {
    cipher: C,
    // TODO: use actual block size here
    iv: Array<u8, U16>,
}

impl<C: BlockCipher<U16, U16>> Cbc<C> {
    ///
    pub fn new(cipher: C, iv: Array<u8, U16>) -> Self {
        Self { cipher, iv }
    }

    ///
    pub fn encrypt(&mut self, bytes: &mut [u8], len: usize) {
        assert!(bytes.len().is_multiple_of(C::BLOCK_SIZE));
        let mut tmp = self.iv;
        for chunk in bytes.chunks_exact_mut(C::BLOCK_SIZE) {
            xor::encrypt_fixed(chunk, &tmp);
            self.cipher.encrypt_block_in_place(chunk);
            tmp.copy_from_slice(chunk);
        }
    }

    ///
    pub fn encrypt_padded<P: Padding<U16>>(&mut self, bytes: &mut [u8], len: usize) {
        assert!(bytes.len().is_multiple_of(C::BLOCK_SIZE));
        P::pad_bytes(bytes, len);
        self.encrypt(bytes, len);
    }

    ///
    pub fn decrypt(&mut self, bytes: &mut [u8]) {
        assert!(bytes.len().is_multiple_of(C::BLOCK_SIZE));
        let mut current_xor_key = self.iv;
        let mut next_xor_key = self.iv;
        for chunk in bytes.chunks_exact_mut(C::BLOCK_SIZE) {
            next_xor_key.copy_from_slice(chunk);
            self.cipher.decrypt_block_in_place(chunk);
            xor::decrypt_fixed(chunk, &current_xor_key);
            current_xor_key.copy_from_slice(&next_xor_key);
        }
    }

    ///
    pub fn decrypt_padded<'a, P: Padding<U16>>(&mut self, bytes: &'a mut [u8]) -> &'a [u8] {
        assert!(bytes.len().is_multiple_of(C::BLOCK_SIZE));
        self.decrypt(bytes);
        let unpadded_len = P::unpad_bytes(bytes).len();
        &bytes[..unpadded_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {}
}
