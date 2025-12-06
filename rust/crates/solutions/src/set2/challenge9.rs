//! # Challenge 9
//!
//! Solution to [Challenge 9](https://cryptopals.com/sets/2/challenges/9) of Cryptopals.

use cryptopals_padding::{Padding, pkcs7::Pkcs7};
use hybrid_array::sizes::U20;

/// Decrypts a base64-encoded ciphertext using AES.
///
/// Handles the case where the ciphertext is broken into multiple lines.
pub fn pad_ascii(ascii_str: &str) -> Vec<u8> {
    let padded = Pkcs7::<U20>::pad(ascii_str.as_bytes());
    padded.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let padded = pad_ascii("YELLOW SUBMARINE");
        assert_eq!(&padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }
}
