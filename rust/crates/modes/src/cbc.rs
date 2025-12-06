//! # Cipher Block Chaining (CBC)
//!
//! ## Usage

use cryptopals_padding::{Padding, pkcs7::Pkcs7};

// struct Cbc<C: BlockCipher, P: Padding = Pkcs7> {
//     cipher: C,
//     iv: Array<u8, C::BlockSize>,
//     padding: P,
// }
//
// impl Cbc {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {}
}
