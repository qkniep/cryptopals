//! # Challenge 5
//!
//! Solution to [Challenge 5](https://cryptopals.com/sets/1/challenges/5) of Cryptopals.

use cryptopals_primitives::xor;
use cryptopals_utils::hex;

/// Encrypts the input string with repeating XOR.
pub fn encrypt(input: &str, key: &str) -> String {
    let mut buffer = input.as_bytes().to_vec();
    xor::encrypt(&mut buffer, key.as_bytes());

    hex::encode(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let ciphertext = encrypt(
            "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal",
            "ICE",
        );
        assert_eq!(
            ciphertext,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
