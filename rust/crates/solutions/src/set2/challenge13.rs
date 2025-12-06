//! # Challenge 13
//!
//! Solution to [Challenge 13](https://cryptopals.com/sets/2/challenges/13) of Cryptopals.

use cryptopals_attacks::EcbUserOracle;
use cryptopals_utils::hex;

/// Launches cut-and-paste ECB
///
/// Finds a token that can be submitted to the oracle to gain admin access.
///
/// Returns the successful token and the number of oracle queries used.
pub fn cut_and_paste_attack(oracle: &EcbUserOracle) -> (String, usize) {
    let token1 = hex::decode(
        &oracle.create_user("foobar@x.xadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
    );
    let cut = &token1[16..32];
    let token2 = hex::decode(&oracle.create_user("foobar@bar.com"));
    assert!(token2.len() == 48);
    let mut custom_token = [0; 48];
    custom_token[0..32].copy_from_slice(&token2[0..32]);
    custom_token[32..48].copy_from_slice(cut);

    let succesful_token = hex::encode(&custom_token);
    (succesful_token, 2)
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
        assert!(queries == 2);
    }
}
