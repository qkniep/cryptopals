//! Base64 encoding and decoding.
//!
//! This implementation follows [RFC 4648].
//! Provides compact encoding of binary data into ASCII strings.
//! Optionally performs padding to make the output a multiple of 3 bytes.
//!
//! # Usage
//!
//! ```
//! use cryptopals_utils::base64;
//!
//! // encoding can be done with or without padding explicitly
//! assert_eq!(base64::encode(b"hello world"), "aGVsbG8gd29ybGQ");
//! assert_eq!(base64::encode_with_padding(b"hello world"), "aGVsbG8gd29ybGQ=");
//!
//! // decoding handles both
//! assert_eq!(base64::decode("aGVsbG8gd29ybGQ"), b"hello world");
//! assert_eq!(base64::decode("aGVsbG8gd29ybGQ="), b"hello world");
//! ```
//!
//! # References
//!
//! - [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648)

const CHAR_SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PADDING_CHAR: u8 = b'=';

/// Encodes bytes into a base64 string.
pub fn encode(bytes: &[u8]) -> String {
    let len = (bytes.len() * 4).div_ceil(3);
    let mut base64 = String::with_capacity(len);
    let mut buffer = 0u16;
    let mut buffer_len = 0;
    for byte in bytes {
        buffer <<= 8;
        buffer |= *byte as u16;
        buffer_len += 8;
        while buffer_len >= 6 {
            let ascii = CHAR_SET[(buffer >> (buffer_len - 6)) as usize];
            base64.push(char::from(ascii));
            buffer &= (1 << (buffer_len - 6)) - 1;
            buffer_len -= 6;
        }
    }

    // handle remainder
    if buffer_len > 0 {
        let ascii = CHAR_SET[(buffer << (6 - buffer_len)) as usize];
        base64.push(char::from(ascii));
    }

    base64
}

/// Encodes bytes into a base64 string.
///
/// Performs padding to make the output a multiple of 4 bytes.
pub fn encode_with_padding(bytes: &[u8]) -> String {
    let len = (bytes.len() * 4).div_ceil(3).next_multiple_of(4);
    let mut base64 = String::with_capacity(len);

    // perform base encoding
    let mut buffer = 0u16;
    let mut buffer_len = 0;
    for byte in bytes {
        buffer <<= 8;
        buffer |= *byte as u16;
        buffer_len += 8;
        while buffer_len >= 6 {
            let ascii = CHAR_SET[(buffer >> (buffer_len - 6)) as usize];
            base64.push(char::from(ascii));
            buffer &= (1 << (buffer_len - 6)) - 1;
            buffer_len -= 6;
        }
    }

    // handle remainder
    if buffer_len > 0 {
        let ascii = CHAR_SET[(buffer << (6 - buffer_len)) as usize];
        base64.push(char::from(ascii));
    }

    // add padding
    while base64.len() < len {
        base64.push(char::from(PADDING_CHAR));
    }

    base64
}

/// Decodes a base64 string into bytes.
///
/// Handles both inputs with and without padding.
pub fn decode(base64: &str) -> Vec<u8> {
    let len = (base64.len() * 3).div_ceil(4);
    let mut bytes = Vec::with_capacity(len);
    let mut buffer = 0u16;
    let mut buffer_len = 0;
    for c in base64.bytes() {
        let Some(index) = decode_ascii_char(c) else {
            break;
        };
        buffer <<= 6;
        buffer |= index as u16;
        buffer_len += 6;
        if buffer_len >= 8 {
            buffer_len -= 8;
            bytes.push((buffer >> buffer_len) as u8);
        }
    }
    bytes
}

fn decode_ascii_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => None,
        c => panic!("invalid base64 char: {}", c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::prelude::*;

    #[test]
    fn basic() {
        let bytes = b"hello world";
        let base64 = encode(bytes);
        let decoded = decode(&base64);
        assert_eq!(bytes.as_slice(), decoded.as_slice());
    }

    #[test]
    fn arbitrary_bytes() {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let base64 = encode(&bytes);
        let decoded = decode(&base64);
        assert_eq!(bytes.as_slice(), decoded.as_slice());
    }

    #[test]
    fn padding() {
        let bytes = b"hello world";
        let base64 = super::encode_with_padding(bytes);
        let decoded = super::decode(&base64);
        assert_eq!(bytes.as_slice(), decoded.as_slice());

        // TODO: check correct padding length
        // TODO: check output always multiple of 3
    }

    #[test]
    fn rfc_test_vectors() {
        // without padding
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");

        // with padding
        assert_eq!(encode_with_padding(b""), "");
        assert_eq!(encode_with_padding(b"f"), "Zg==");
        assert_eq!(encode_with_padding(b"fo"), "Zm8=");
        assert_eq!(encode_with_padding(b"foo"), "Zm9v");
        assert_eq!(encode_with_padding(b"foob"), "Zm9vYg==");
        assert_eq!(encode_with_padding(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_with_padding(b"foobar"), "Zm9vYmFy");
    }
}

