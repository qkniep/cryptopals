use cryptopals_modes::{cbc::Cbc, ecb::Ecb};
use cryptopals_padding::pkcs7::Pkcs7;
use cryptopals_primitives::{BlockCipher, aes::Aes128};
use hybrid_array::sizes::U16;
use rand::prelude::*;

///
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeUsed {
    ECB,
    CBC,
}

///
pub fn encryption_oracle_ecb_cbc(input: &[u8]) -> (Vec<u8>, ModeUsed) {
    // initialize AES with random key
    let mut rng = rand::rng();
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);
    let aes = Aes128::new(key.into());

    // determine additional bytes
    let prefix_len = rng.random_range(5..=10);
    let suffix_len = rng.random_range(5..=10);

    // create buffer
    let len = prefix_len + input.len() + suffix_len;
    let padding_len = 16 - len % 16;
    let mut buffer = vec![0; len + padding_len];
    rng.fill_bytes(&mut buffer[..prefix_len]);
    buffer[prefix_len..prefix_len + input.len()].copy_from_slice(input);
    rng.fill_bytes(&mut buffer[prefix_len + input.len()..len]);

    // randomly encrypt with either ECB or CBC (50/50)
    if rng.random_bool(0.5) {
        let mut ecb = Ecb::new(aes);
        ecb.encrypt_padded::<Pkcs7<U16>>(&mut buffer, len);
        (buffer, ModeUsed::ECB)
    } else {
        let mut cbc = Cbc::new(aes, [0; 16].into());
        cbc.encrypt_padded::<Pkcs7<U16>>(&mut buffer, len);
        (buffer, ModeUsed::CBC)
    }
}
