use std::collections::HashMap;

use cryptopals_modes::{cbc::Cbc, ecb::Ecb};
use cryptopals_padding::pkcs7::Pkcs7;
use cryptopals_primitives::{BlockCipher, aes::Aes128};
use cryptopals_utils::{
    base64, hex,
    url_params::{self, build_url_params, parse_url_params},
};
use hybrid_array::sizes::U16;
use rand::prelude::*;

/// Indicates which block cipher mode was used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeUsed {
    ECB,
    CBC,
}

/// Acts as an encryption oracle on `input`.
///
/// Randomly encrypts `input` with either AES in ECB mode or AES in CBC mode (50/50).
/// Also, randomly preprends and appends random bytes (5-10 bytes each).
///
/// Returns `(ciphertext, mode_used)`.
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

pub struct ByteAtATimeEcbOracle {
    aes: Aes128,
    data_to_add: Vec<u8>,
    random_prefix: Vec<u8>,
}

impl ByteAtATimeEcbOracle {
    pub fn new() -> Self {
        const DATA_TO_ADD_BASE64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

        // decode data to add
        let data_to_add = base64::decode(DATA_TO_ADD_BASE64);

        // initialize AES with random key
        let mut rng = rand::rng();
        let mut key = [0; 16];
        rng.fill_bytes(&mut key);
        let aes = Aes128::new(key.into());

        // create random prefix
        let prefix_len = rng.random_range(1..=32);
        let mut random_prefix = vec![0; prefix_len];
        rng.fill_bytes(&mut random_prefix);

        Self {
            aes,
            data_to_add,
            random_prefix,
        }
    }

    ///
    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        // create buffer with `data_to_add` appended
        let len = input.len() + self.data_to_add.len();
        let padding_len = 16 - len % 16;
        let mut buffer = vec![0; len + padding_len];
        buffer[..input.len()].copy_from_slice(input);
        buffer[input.len()..len].copy_from_slice(&self.data_to_add);

        // encrypt with ECB
        let mut ecb = Ecb::new(self.aes.clone());
        ecb.encrypt_padded::<Pkcs7<U16>>(&mut buffer, len);
        buffer
    }

    ///
    pub fn encrypt_harder(&self, input: &[u8]) -> Vec<u8> {
        let buffer = [self.random_prefix.as_slice(), input].concat();
        self.encrypt(&buffer)
    }
}

///
pub struct EcbUserOracle {
    aes: Aes128,
}

impl EcbUserOracle {
    /// Creates a new instance of the oracle with a random AES key.
    pub fn new() -> Self {
        // initialize AES with random key
        let mut rng = rand::rng();
        let mut key = [0; 16];
        rng.fill_bytes(&mut key);
        let aes = Aes128::new(key.into());

        Self { aes }
    }

    /// Creates a new user.
    ///
    /// Returns the AES-ECB encrypted user token in hex encoding.
    pub fn create_user(&self, email: &str) -> String {
        self.create_user_with_role(email, "user")
    }

    fn create_admin(&self, email: &str) -> String {
        self.create_user_with_role(email, "admin")
    }

    fn create_user_with_role(&self, email: &str, role: &str) -> String {
        let mut rng = rand::rng();
        let mut params = HashMap::new();
        let user_id = rng.random_range(10..=99);
        let sanitized_email = email
            .chars()
            .filter(|c| *c != '=' && *c != '&')
            .collect::<String>();
        params.insert("email".to_string(), sanitized_email);
        params.insert("id".to_string(), user_id.to_string());
        params.insert("role".to_string(), role.to_string());
        let raw_token = build_url_params(params);
        println!("raw_token: {}", raw_token);

        // encrypt email with AES-ECB
        let mut ecb = Ecb::new(self.aes.clone());
        let mut buffer = vec![0; raw_token.len().next_multiple_of(16)];
        buffer[..raw_token.len()].copy_from_slice(raw_token.as_bytes());
        ecb.encrypt_padded::<Pkcs7<U16>>(&mut buffer, raw_token.len());
        hex::encode(&buffer)
    }

    /// Tries to perform an admin action.
    ///
    /// Takes an hex encoded AES-ECB encrypted user token as input.
    /// Decrypts and decodes the token and validates the user's role.
    ///
    /// Returns `true` if the action was successful (the user was an admin)..
    pub fn try_admin_action(&self, token_hex: &str) -> bool {
        let mut ciphertext = hex::decode(token_hex);
        let mut ecb = Ecb::new(self.aes.clone());
        let user_token = ecb.decrypt_padded::<Pkcs7<U16>>(&mut ciphertext);

        let params = parse_url_params(&String::from_utf8_lossy(user_token));
        println!("params: {:#?}", params);
        params.get("role") == Some(&"admin".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_user_oracle() {
        let oracle = EcbUserOracle::new();
        let token = oracle.create_user("hello@test.com");
        assert!(!oracle.try_admin_action(&token));

        let token = oracle.create_admin("admin@test.com");
        assert!(oracle.try_admin_action(&token));
    }
}
