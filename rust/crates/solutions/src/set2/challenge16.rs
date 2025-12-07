//! # Challenge 16
//!
//! Solution to [Challenge 16](https://cryptopals.com/sets/2/challenges/16) of Cryptopals.

use cryptopals_attacks::CbcUserdataOracle;
use cryptopals_primitives::xor;
use cryptopals_utils::hex;

///
pub fn cbc_bitflipping(oracle: &CbcUserdataOracle) -> String {
    // comment2=%20
    let input = "A".repeat(16);
    let ciphertext = oracle.encrypt(&input);
    let mut ciphertext = ciphertext.into_bytes();
    println!("{:?}", ciphertext);
    xor::decrypt_fixed(&mut ciphertext[32..44], b";comment2=%2");
    xor::encrypt_fixed(&mut ciphertext[32..44], b";admin=true;");
    hex::encode(&ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let oracle = CbcUserdataOracle::new();
        let successful_ciphertext = cbc_bitflipping(&oracle);
        assert!(oracle.try_admin_action(&successful_ciphertext));
    }
}
