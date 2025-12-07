//! # Challenge 16
//!
//! Solution to [Challenge 16](https://cryptopals.com/sets/2/challenges/16) of Cryptopals.

use cryptopals_attacks::CbcUserdataOracle;
use cryptopals_primitives::xor;
use cryptopals_utils::hex;

///
pub fn cbc_bitflipping(oracle: &CbcUserdataOracle) -> String {
    let input = "A".repeat(16);
    let ciphertext = oracle.encrypt(&input);
    let mut ciphertext = hex::decode(&ciphertext);
    xor::decrypt_fixed(&mut ciphertext[32..44], b";comment2=%2");
    xor::encrypt_fixed(&mut ciphertext[32..44], b";admin=true;");
    hex::encode(&ciphertext)
}

#[cfg(test)]
mod tests {
    use cryptopals_modes::cbc::Cbc;
    use cryptopals_padding::pkcs7::Pkcs7;
    use cryptopals_primitives::{BlockCipher, aes::Aes128};
    use hybrid_array::sizes::U16;

    use super::*;

    #[test]
    fn basic() {
        // basic proof-of-concecpt
        let aes = Aes128::new([0; 16].into());
        let mut cbc = Cbc::new(aes, [0; 16].into());
        let mut buffer = *b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBB\x00\x00";
        cbc.encrypt_padded::<Pkcs7<U16>>(buffer.as_mut_slice(), 30);
        xor::decrypt_fixed(&mut buffer[0..2], b"BB");
        xor::encrypt_fixed(&mut buffer[0..2], b"CC");
        let plaintext = cbc.decrypt_padded::<Pkcs7<U16>>(buffer.as_mut_slice());
        assert!(&plaintext[16..18] == b"CC");
    }

    #[test]
    fn challenge() {
        // run attack against oracle
        let oracle = CbcUserdataOracle::new();
        let successful_ciphertext = cbc_bitflipping(&oracle);
        assert!(oracle.try_admin_action(&successful_ciphertext));
    }
}
