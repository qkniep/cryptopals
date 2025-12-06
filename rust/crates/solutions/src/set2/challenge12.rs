//! # Challenge 12
//!
//! Solution to [Challenge 12](https://cryptopals.com/sets/2/challenges/12) of Cryptopals.

use cryptopals_attacks::ByteAtATimeEcbOracle;

/// Launches byte-at-a-time ECB decryption attack.
///
/// Returns the recovered plaintext and the number of oracle queries used.
pub fn recover_additional_plaintext() -> (String, usize) {
    let oracle = ByteAtATimeEcbOracle::new();
    let mut queries = 0;
    let mut recovered_plaintext = String::new();

    let mut input = vec![0; 31];
    let mut offset = 0;

    let ciphertext = oracle.encrypt(&[]);
    let blocks_to_recover = ciphertext.len() / 16;

    for idx in 0..16 * blocks_to_recover {
        for guess in 0..=255 {
            if !char::from(guess).is_ascii() {
                continue;
            }

            let rolling_plaintext = &recovered_plaintext.as_bytes()[offset..];
            input[15 - rolling_plaintext.len()..15].copy_from_slice(rolling_plaintext);
            input[15] = guess;
            let ciphertext = oracle.encrypt(&input[..31 - idx % 16]);
            if detect_ecb(&ciphertext) {
                recovered_plaintext.push(char::from(guess));
                break;
            }
            queries += 1;
        }

        if idx < 15 {
            input.truncate(input.len() - 1);
        } else {
            offset += 1;
        }
        if idx % 16 == 15 {
            input.extend([0; 15]);
        }
    }

    (recovered_plaintext, queries)
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
        let (plaintext, queries) = recover_additional_plaintext();
        println!("plaintext: {}", &plaintext);
        println!("recovered in {} queries", queries);
        assert_eq!(
            &plaintext,
            "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{1}"
        );
        assert!(queries < 256 * plaintext.len());
    }
}
