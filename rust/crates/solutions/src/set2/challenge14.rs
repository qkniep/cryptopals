//! # Challenge 14
//!
//! Solution to [Challenge 14](https://cryptopals.com/sets/2/challenges/14) of Cryptopals.

use cryptopals_attacks::ByteAtATimeEcbOracle;

/// Launches byte-at-a-time ECB decryption attack.
///
/// Returns the recovered plaintext and the number of oracle queries used.
pub fn recover_additional_plaintext() -> (String, usize) {
    let oracle = ByteAtATimeEcbOracle::new();
    let mut queries = 0;
    let mut recovered_plaintext = String::new();

    // determine length of random prefix
    let ciphertext = oracle.encrypt_harder(&[0; 48]);
    let index = detect_ecb(&ciphertext).unwrap();
    let full_blocks = index - 1;
    let mut remainder = None;
    for i in 1..=16 {
        let ciphertext = oracle.encrypt_harder(&vec![0; 48 - i]);
        let res = detect_ecb(&ciphertext);
        if res.is_none() {
            remainder = Some(i - 1);
            break;
        }
    }
    let random_prefix_len = full_blocks * 16 + remainder.unwrap();
    let padding_for_prefix = 16 - random_prefix_len % 16;

    // determine length of suffix that we want to recover
    let ciphertext = oracle.encrypt_harder(&[]);
    let bytes_to_recover = ciphertext.len() - random_prefix_len;

    let mut input = vec![0; padding_for_prefix + 31];
    input[..padding_for_prefix].fill(42);
    let mut offset = 0;

    for idx in 0..bytes_to_recover {
        for guess in 0..=255 {
            if !char::from(guess).is_ascii() {
                continue;
            }

            let input_mut = &mut input[padding_for_prefix..];
            let rolling_plaintext = &recovered_plaintext.as_bytes()[offset..];
            input_mut[15 - rolling_plaintext.len()..15].copy_from_slice(rolling_plaintext);
            input_mut[15] = guess;
            let ciphertext = oracle.encrypt_harder(&input[..padding_for_prefix + 31 - idx % 16]);
            if detect_ecb(&ciphertext).is_some() {
                recovered_plaintext.push(char::from(guess));
                println!("found char: {}", guess);
                break;
            }
            queries += 1;
        }

        if idx >= 15 {
            offset += 1;
        }
    }

    (recovered_plaintext, queries)
}

/// Returns the index of the first block that repeats, if any.
fn detect_ecb(ciphertext: &[u8]) -> Option<usize> {
    const BLOCK_LENGTH_BYTES: usize = 16;
    for (i, block1) in ciphertext.chunks(BLOCK_LENGTH_BYTES).enumerate() {
        for (j, block2) in ciphertext.chunks(BLOCK_LENGTH_BYTES).enumerate() {
            if i != j && block1 == block2 {
                return Some(i.min(j));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        // repeat to avoid getting lucking on full multiples of block length
        for _ in 0..10 {
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
}
