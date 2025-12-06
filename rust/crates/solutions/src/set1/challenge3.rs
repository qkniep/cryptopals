//! # Challenge 3
//!
//! Solution to [Challenge 3](https://cryptopals.com/sets/1/challenges/3) of Cryptopals.

use cryptopals_primitives::xor;
use cryptopals_utils::{frequency_analysis, hex};

/// Attempts to decrypt a hex-encoded ciphertext.
///
/// Returns the best guess of the decrypted string.
pub fn solve_challenge(input_hex: &str) -> String {
    let input_bytes = hex::decode(input_hex);

    let (_key, guess) = crack_single_byte_xor(&input_bytes);
    guess
}

/// Attempts to decrypt a string of hex bytes.
///
/// The input is assumed to be the hex encoding of a ciphertext as follows:
/// - plaintext is an ASCII string
/// - key is a single ASCII character
/// - plaintext is XORed with the key to obtain the ciphertext
///
/// Returns the best guess of the key and decrypted string.
pub fn crack_single_byte_xor(ciphertext: &[u8]) -> (u8, String) {
    let mut best_key = 0;
    let mut best_guess = String::new();
    let mut best_score = 0.0;
    for key in 0u8..=255 {
        // ignore non ASCII
        if !key.is_ascii() {
            continue;
        }

        // apply XOR
        let mut buffer = ciphertext.to_vec();
        xor::decrypt_repeating(&mut buffer, &[key]);

        // evaluate
        let Ok(s) = String::from_utf8(buffer) else {
            continue;
        };
        let score = frequency_analysis::string_score(&s);
        if score > best_score {
            best_key = key;
            best_guess = s.to_string();
            best_score = score;
        }
    }

    (best_key, best_guess)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let plaintext = solve_challenge(ciphertext);
        assert_eq!(plaintext, "Cooking MC's like a pound of bacon");
    }
}
