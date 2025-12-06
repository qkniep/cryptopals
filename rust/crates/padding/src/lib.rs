//! # Padding
//!
//! Implementations of different padding schemes.
//!
//! ## Usage
//!
//! ```rust
//! use hybrid_array::Array;
//! use padding::{Padding, pkcs7::Pkcs7};
//!
//! let data = b"YELLOW SUBMARINE";
//! let padded = Pkcs7::pad(data);
//! let unpadded = Pkcs7::unpad(&padded);
//! assert_eq!(data, unpadded);
//! ```

#![no_std]

use hybrid_array::ArraySize;
use hybrid_array::sizes::U16;

///
pub trait Padding<N: ArraySize> {
    fn pad_bytes(data: &mut [u8], len: usize);
    fn unpad_bytes(data: &[u8]) -> &[u8];
    // fn pad_block(data: &[u8]) -> Array<u8, N>;
    // fn unpad_block(data: &Array<u8, N>) -> &[u8];
}

pub struct NoPadding;

impl Padding<U16> for NoPadding {
    fn pad_bytes(data: &mut [u8], _len: usize) {
        assert!(data.len().is_multiple_of(16));
    }

    fn unpad_bytes(data: &[u8]) -> &[u8] {
        assert!(data.len().is_multiple_of(16));
        data
    }
}

pub mod pkcs7;
