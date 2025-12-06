//! # Challenge 15
//!
//! Solution to [Challenge 15](https://cryptopals.com/sets/2/challenges/15) of Cryptopals.

use cryptopals_attacks::ByteAtATimeEcbOracle;
use cryptopals_padding::pkcs7::Pkcs7;
use hybrid_array::sizes::U16;

/// Check whether `input` has valid PKCS #7 padding.
pub fn check_padding(input: &str) -> bool {
    Pkcs7::<U16>::unpad_checked(input.as_bytes()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        assert!(check_padding("ICE ICE BABY\x04\x04\x04\x04"));
        assert!(!check_padding("ICE ICE BABY\x05\x05\x05\x05"));
        assert!(!check_padding("ICE ICE BABY\x01\x02\x03\x04"));
    }
}
