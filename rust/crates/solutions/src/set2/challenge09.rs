//! # Challenge 9
//!
//! Solution to [Challenge 9](https://cryptopals.com/sets/2/challenges/9) of Cryptopals.

use cryptopals_padding::{Padding, pkcs7::Pkcs7};
use hybrid_array::sizes::U20;

/// Pads an ASCII string using PKCS#7.
pub fn pad_ascii(ascii_str: &str) -> Vec<u8> {
    let mut buffer = [0u8; 20];
    buffer[0..ascii_str.len()].copy_from_slice(ascii_str.as_bytes());
    Pkcs7::<U20>::pad_bytes(&mut buffer, ascii_str.len());
    buffer.to_vec()
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
