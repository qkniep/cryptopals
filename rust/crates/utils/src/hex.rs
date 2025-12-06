//! Hex encoding and decoding.
//!
//! # Examples
//!
//! ```
//! use cryptopals_utils::hex;
//!
//! assert_eq!(hex::encode(b"hello world"), "68656c6c6f20776f726c64");
//! assert_eq!(hex::decode("68656c6c6f20776f726c64"), b"hello world");
//! assert_eq!(hex::encode_uppercase(b"hello world"), "68656C6C6F20776F726C64");
//! assert_eq!(hex::decode("68656C6C6F20776F726C64"), b"hello world");
//! ```

const CHAR_SET: &[u8] = b"0123456789abcdef";
const UPPERCASE_CHAR_SET: &[u8] = b"0123456789ABCDEF";

/// Encodes bytes into a lowercase hex string.
///
/// The resulting string is exactly `bytes.len() * 2` characters long.
/// That is, any leading zeroes are included in the output.
pub fn encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = byte / 16;
        let low = byte % 16;
        hex.push(char::from(CHAR_SET[high as usize]));
        hex.push(char::from(CHAR_SET[low as usize]));
    }
    hex
}

/// Encodes bytes into an uppercase hex string.
///
/// The resulting string is exactly `bytes.len() * 2` characters long.
/// That is, any leading zeroes are included in the output.
pub fn encode_uppercase(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = byte / 16;
        let low = byte % 16;
        hex.push(char::from(UPPERCASE_CHAR_SET[high as usize]));
        hex.push(char::from(UPPERCASE_CHAR_SET[low as usize]));
    }
    hex
}

/// Decodes a hex string into bytes.
///
/// Supports lowercase and uppercase, as well as even and odd length strings.
/// Interprets odd length strings as having a single ommitted leading zero.
pub fn decode(hex: &str) -> Vec<u8> {
    let len = hex.len().div_ceil(2);
    let mut bytes = Vec::with_capacity(len);

    // handle first char separately for odd length
    let mut offset = 0;
    if hex.len() % 2 == 1 {
        bytes.push(decode_ascii_char(hex.as_bytes()[0]).unwrap());
        offset = 1;
    }

    // decode each pair of hex chars as byte for even length rest
    for pair in hex.as_bytes()[offset..].chunks(2) {
        let high = decode_ascii_char(pair[0]).unwrap();
        let low = decode_ascii_char(pair[1]).unwrap();
        bytes.push(high << 4 | low);
    }

    bytes
}

fn decode_ascii_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(encode(b"hello world"), "68656c6c6f20776f726c64");
        assert_eq!(decode("68656c6c6f20776f726c64"), b"hello world");
        assert_eq!(encode_uppercase(b"hello world"), "68656C6C6F20776F726C64");
        assert_eq!(decode("68656C6C6F20776F726C64"), b"hello world");
    }
}
