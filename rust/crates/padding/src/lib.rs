//!
//!
//!

#![no_std]

use hybrid_array::{Array, ArraySize};

///
pub trait Padding<N: ArraySize> {
    fn pad(data: &[u8]) -> Array<u8, N>;
    fn unpad(data: &Array<u8, N>) -> &[u8];
}

pub mod pkcs7;
