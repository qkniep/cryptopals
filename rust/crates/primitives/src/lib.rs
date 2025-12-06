//! # Cryptographic Primitives
//!
//!

#![no_std]

use hybrid_array::{Array, ArraySize};

/// Generic block cipher with block size `B` and key size `K`.
pub trait BlockCipher<B: ArraySize, K: ArraySize> {
    const BLOCK_SIZE: usize = B::USIZE;
    const KEY_SIZE: usize = K::USIZE;

    fn new(key: Array<u8, K>) -> Self;
    fn encrypt_block(&mut self, block: Array<u8, B>) -> Array<u8, B>;
    fn decrypt_block(&mut self, block: Array<u8, B>) -> Array<u8, B>;
}

pub mod aes;
pub mod xor;
