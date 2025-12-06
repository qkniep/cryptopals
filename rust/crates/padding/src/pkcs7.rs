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

///
pub struct Pkcs7<N: ArraySize>(core::marker::PhantomData<N>);

impl<N: ArraySize> Padding<N> for Pkcs7<N> {
    fn pad(data: &[u8]) -> Array<u8, N> {
        assert!(data.len() <= N::USIZE);
        let mut block = Array::<u8, N>::default();
        block[..data.len()].copy_from_slice(data);
        let padding_byte = N::USIZE as u8 - data.len() as u8;
        block[data.len()..].fill(padding_byte);
        block
    }

    fn unpad(data: &Array<u8, N>) -> &[u8] {
        assert!(data.len() == N::USIZE);
        data.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use hybrid_array::sizes::U20;

    use super::*;

    #[test]
    fn basic() {
        let padded = Pkcs7::<U20>::pad(b"YELLOW SUBMARINE");
        assert_eq!(&padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }
}
