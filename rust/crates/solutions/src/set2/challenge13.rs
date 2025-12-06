//! # Challenge 13
//!
//! Solution to [Challenge 13](https://cryptopals.com/sets/2/challenges/13) of Cryptopals.

use cryptopals_attacks::EcbUserOracle;

/// Launches cut-and-paste ECB
///
/// Finds a token that can be submitted to the oracle to gain admin access.
///
/// Returns the successful token and the number of oracle queries used.
pub fn cut_and_paste_attack(oracle: &EcbUserOracle) -> (String, usize) {
    let mut queries = 0;
    let mut successful_token = String::new();

    let token = oracle.create_user("hello@test.com");
    todo!();

    (successful_token, queries)
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
        let oracle = EcbUserOracle::new();
        let (token, queries) = cut_and_paste_attack(&oracle);
        assert!(oracle.try_admin_action(&token));
        assert!(queries == 0);
    }
}
