//! # Challenge 2
//!
//! Solution to [Challenge 2](https://cryptopals.com/sets/1/challenges/2) of Cryptopals.

use cryptopals_primitives::xor;
use cryptopals_utils::hex;

/// XORs two byte strings given by their hex encodings.
///
/// Returns the hex encoding of the XORed bytes.
pub fn fixed_xor(input_hex: &str, key_hex: &str) -> String {
    let input_bytes = hex::decode(input_hex);
    let key_bytes = hex::decode(key_hex);
    assert!(input_bytes.len() == key_bytes.len());

    // apply XOR
    let mut buffer = input_bytes;
    xor::encrypt_fixed(&mut buffer, &key_bytes);

    hex::encode(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            fixed_xor(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }
}
