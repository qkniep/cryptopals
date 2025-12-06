//! # Counter (CTR) Mode
//!
//! ## Usage

use cryptopals_padding::{Padding, pkcs7::Pkcs7};

// struct Ctr<C: BlockCipher, P: Padding = Pkcs7> {
//     cipher: C,
//     iv: Array<u8, C::BlockSize>,
//     padding: P,
// }
//
// impl Ctr {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {}
}
