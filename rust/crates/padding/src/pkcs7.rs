//! PKCS #7 Padding
//!
//! Implements the PKCS #7 padding scheme defined in [RFC 2315].
//!
//! ## Usage
//!
//!
//!
//! [RFC 2315]: https://www.rfc-editor.org/rfc/rfc2315

use hybrid_array::{Array, ArraySize};

use super::Padding;

pub enum InvalidPaddingError {
    PaddingTooLarge,
    MismatchingPaddingBytes,
}
pub type Result<T> = core::result::Result<T, InvalidPaddingError>;

///
pub struct Pkcs7<N: ArraySize>(core::marker::PhantomData<N>);

impl<N: ArraySize> Pkcs7<N> {
    pub fn unpad_checked(data: &[u8]) -> Result<&[u8]> {
        assert!(data.len().is_multiple_of(N::USIZE));
        let padding_byte = data[data.len() - 1];
        if padding_byte > N::USIZE as u8 {
            return Err(InvalidPaddingError::PaddingTooLarge);
        }
        for d in &data[data.len() - padding_byte as usize..] {
            if *d != padding_byte {
                return Err(InvalidPaddingError::MismatchingPaddingBytes);
            }
        }
        Ok(&data[..data.len() - padding_byte as usize])
    }
}

impl<N: ArraySize> Padding<N> for Pkcs7<N> {
    fn pad_bytes(data: &mut [u8], len: usize) {
        assert!(len <= data.len());
        let padding_byte = data.len() as u8 - len as u8;
        data[len..].fill(padding_byte);
    }

    fn unpad_bytes(data: &[u8]) -> &[u8] {
        assert!(data.len().is_multiple_of(N::USIZE));
        let padding_byte = data[data.len() - 1];
        assert!(padding_byte < N::USIZE as u8);
        &data[..data.len() - padding_byte as usize]
    }
}

#[cfg(test)]
mod tests {
    use hybrid_array::sizes::U20;

    use super::*;

    #[test]
    fn basic() {
        let mut buffer: [u8; 20] = [0; 20];
        buffer[0..16].copy_from_slice(b"YELLOW SUBMARINE");
        Pkcs7::<U20>::pad_bytes(&mut buffer, 16);
        assert_eq!(&buffer, b"YELLOW SUBMARINE\x04\x04\x04\x04");
        let unpadded = Pkcs7::<U20>::unpad_bytes(&buffer);
        assert_eq!(&unpadded, b"YELLOW SUBMARINE");
    }
}
