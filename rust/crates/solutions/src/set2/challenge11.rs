//! # Challenge 11
//!
//! Solution to [Challenge 11](https://cryptopals.com/sets/2/challenges/11) of Cryptopals.

use cryptopals_attacks::{ModeUsed, encryption_oracle_ecb_cbc};

/// Detects the cipher mode used by [`encryption_oracle_ecb_cbc`].
///
/// Makes `iterations` guesses and returns the number of correct guesses.
pub fn detect_cipher_mode(iterations: usize) -> usize {
    const PLAINTEXT: [u8; 64] = [0; 64];

    let mut count_correct = 0;
    for _ in 0..iterations {
        let (ciphertext, mode_used) = encryption_oracle_ecb_cbc(&PLAINTEXT);
        let guess = if detect_ecb(&ciphertext) {
            ModeUsed::ECB
        } else {
            ModeUsed::CBC
        };
        if guess == mode_used {
            count_correct += 1;
        }
    }
    count_correct
}

fn detect_ecb(ciphertext: &[u8]) -> bool {
    const BLOCK_LENGTH_BYTES: usize = 16;

    let mut repeats = 0;
    for (i, block1) in ciphertext.chunks(BLOCK_LENGTH_BYTES).enumerate() {
        for (j, block2) in ciphertext.chunks(BLOCK_LENGTH_BYTES).enumerate() {
            if i != j && block1 == block2 {
                repeats += 1;
            }
        }
    }
    repeats > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        assert_eq!(detect_cipher_mode(1000), 1000);
    }
}
