//! # Challenge 1
//!
//! Solution to [Challenge 1](https://cryptopals.com/sets/1/challenges/1) of Cryptopals.

use cryptopals_utils::{base64, hex};

/// Encodes the bytes represented by a hex string to a base64 string.
pub fn convert_hex_to_base64(hex: &str) -> String {
    let bytes = hex::decode(hex);
    base64::encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            convert_hex_to_base64(
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
            ),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }
}
