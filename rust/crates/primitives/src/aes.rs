//! Advanced Encryption Standard (AES)
//!
//! This is an implementation of the three algorithms in the [NIST FIPS 197].
//! Namely, AES-128, AES-192, and AES-256, which are three algorithms from the Rijndael family.
//!
//! [NIST FIPS 197]: (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

use hybrid_array::Array;
use hybrid_array::sizes::{U16, U24, U32};

use crate::BlockCipher;

/// AES-128
///
/// 128-bit key, 128-bit blocks, 10 rounds
#[derive(Clone, Debug)]
pub struct Aes128(State, [u32; 44]);

impl Aes128 {
    const KEY_BYTES: u8 = 16;
    const BLOCK_BYTES: u8 = 16;
    const ROUNDS: u8 = 10;
}

impl BlockCipher<U16, U16> for Aes128 {
    fn new(key: Array<u8, U16>) -> Self {
        let key = [
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        ];
        Self(State([0; 4]), key_expansion(key))
    }

    fn encrypt_block(&mut self, block: Array<u8, U16>) -> Array<u8, U16> {
        let block = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = cipher(State(block), Self::ROUNDS, self.1);
        aes_block_to_bytes(self.0.0).into()
    }

    fn decrypt_block(&mut self, block: Array<u8, U16>) -> Array<u8, U16> {
        let block = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = inv_cipher(State(block), Self::ROUNDS, self.1);
        aes_block_to_bytes(self.0.0).into()
    }

    // TODO: add tests
    fn encrypt_block_in_place(&mut self, block: &mut [u8]) {
        let input = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = cipher(State(input), Self::ROUNDS, self.1);
        block.copy_from_slice(aes_block_to_bytes(self.0.0).as_slice())
    }

    // TODO: add tests
    fn decrypt_block_in_place(&mut self, block: &mut [u8]) {
        let input = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = inv_cipher(State(input), Self::ROUNDS, self.1);
        block.copy_from_slice(aes_block_to_bytes(self.0.0).as_slice())
    }
}

/// AES-192
///
/// 192-bit key, 128-bit blocks, 12 rounds
#[derive(Clone, Debug)]
pub struct Aes192(State, [u32; 52]);

impl Aes192 {
    const KEY_BYTES: u8 = 24;
    const BLOCK_BYTES: u8 = 16;
    const ROUNDS: u8 = 12;
}

impl BlockCipher<U16, U24> for Aes192 {
    fn new(key: Array<u8, U24>) -> Self {
        let key = [
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
            u32::from_be_bytes(key[16..20].try_into().unwrap()),
            u32::from_be_bytes(key[20..24].try_into().unwrap()),
        ];
        Self(State([0; 4]), key_expansion_192(key))
    }

    fn encrypt_block(&mut self, block: Array<u8, U16>) -> Array<u8, U16> {
        let block = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = cipher_192(State(block), Self::ROUNDS, self.1);
        aes_block_to_bytes(self.0.0).into()
    }

    fn decrypt_block(&mut self, block: Array<u8, U16>) -> Array<u8, U16> {
        let block = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = inv_cipher_192(State(block), Self::ROUNDS, self.1);
        aes_block_to_bytes(self.0.0).into()
    }

    // TODO: add tests
    fn encrypt_block_in_place(&mut self, block: &mut [u8]) {
        let input = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = cipher_192(State(input), Self::ROUNDS, self.1);
        block.copy_from_slice(aes_block_to_bytes(self.0.0).as_slice())
    }

    // TODO: add tests
    fn decrypt_block_in_place(&mut self, block: &mut [u8]) {
        let input = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = inv_cipher_192(State(input), Self::ROUNDS, self.1);
        block.copy_from_slice(aes_block_to_bytes(self.0.0).as_slice())
    }
}

/// AES-256
///
/// 256-bit key, 128-bit blocks, 14 rounds
#[derive(Clone, Debug)]
pub struct Aes256(State, [u32; 60]);

impl Aes256 {
    const KEY_BYTES: u8 = 32;
    const BLOCK_BYTES: u8 = 16;
    const ROUNDS: u8 = 14;
}

impl BlockCipher<U16, U32> for Aes256 {
    fn new(key: Array<u8, U32>) -> Self {
        let key = [
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
            u32::from_be_bytes(key[16..20].try_into().unwrap()),
            u32::from_be_bytes(key[20..24].try_into().unwrap()),
            u32::from_be_bytes(key[24..28].try_into().unwrap()),
            u32::from_be_bytes(key[28..32].try_into().unwrap()),
        ];
        Self(State([0; 4]), key_expansion_256(key))
    }

    fn encrypt_block(&mut self, block: Array<u8, U16>) -> Array<u8, U16> {
        let block = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = cipher_256(State(block), Self::ROUNDS, self.1);
        aes_block_to_bytes(self.0.0).into()
    }

    fn decrypt_block(&mut self, block: Array<u8, U16>) -> Array<u8, U16> {
        let block = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = inv_cipher_256(State(block), Self::ROUNDS, self.1);
        aes_block_to_bytes(self.0.0).into()
    }

    // TODO: add tests
    fn encrypt_block_in_place(&mut self, block: &mut [u8]) {
        let input = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = cipher_256(State(input), Self::ROUNDS, self.1);
        block.copy_from_slice(aes_block_to_bytes(self.0.0).as_slice())
    }

    // TODO: add tests
    fn decrypt_block_in_place(&mut self, block: &mut [u8]) {
        let input = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        self.0 = inv_cipher_256(State(input), Self::ROUNDS, self.1);
        block.copy_from_slice(aes_block_to_bytes(self.0.0).as_slice())
    }
}

/// Internal state of AES.
///
/// The state can also be thought of as a 4x4 matrix of bytes.
/// Each `u32` represents one column of the state.
/// Each column's first byte is on the top row (0), and the last byte is on the bottom row (3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct State([u32; 4]);

impl State {
    fn shift_rows(&mut self) {
        // extract rows <- columns
        let r0 = (self.0[0] & 0xFF00_0000)
            | (self.0[1] & 0xFF00_0000) >> 8
            | (self.0[2] & 0xFF00_0000) >> 16
            | (self.0[3] & 0xFF00_0000) >> 24;

        let r1 = (self.0[0] & 0x00FF_0000) << 8
            | (self.0[1] & 0x00FF_0000)
            | (self.0[2] & 0x00FF_0000) >> 8
            | (self.0[3] & 0x00FF_0000) >> 16;

        let r2 = (self.0[0] & 0x0000_FF00) << 16
            | (self.0[1] & 0x0000_FF00) << 8
            | (self.0[2] & 0x0000_FF00)
            | (self.0[3] & 0x0000_FF00) >> 8;

        let r3 = (self.0[0] & 0x0000_00FF) << 24
            | (self.0[1] & 0x0000_00FF) << 16
            | (self.0[2] & 0x0000_00FF) << 8
            | (self.0[3] & 0x0000_00FF);

        // rotate row words
        let r0 = r0;
        let r1 = r1.rotate_left(8);
        let r2 = r2.rotate_left(16);
        let r3 = r3.rotate_left(24);

        // reassemble rows -> columns
        self.0[0] = (r0 & 0xFF00_0000)
            | ((r1 & 0xFF00_0000) >> 8)
            | ((r2 & 0xFF00_0000) >> 16)
            | ((r3 & 0xFF00_0000) >> 24);

        self.0[1] = ((r0 & 0x00FF_0000) << 8)
            | (r1 & 0x00FF_0000)
            | ((r2 & 0x00FF_0000) >> 8)
            | ((r3 & 0x00FF_0000) >> 16);

        self.0[2] = ((r0 & 0x0000_FF00) << 16)
            | ((r1 & 0x0000_FF00) << 8)
            | (r2 & 0x0000_FF00)
            | ((r3 & 0x0000_FF00) >> 8);

        self.0[3] = ((r0 & 0x0000_00FF) << 24)
            | ((r1 & 0x0000_00FF) << 16)
            | ((r2 & 0x0000_00FF) << 8)
            | (r3 & 0x0000_00FF);
    }

    fn inv_shift_rows(&mut self) {
        // extract rows <- columns
        let r0 = (self.0[0] & 0xFF00_0000)
            | (self.0[1] & 0xFF00_0000) >> 8
            | (self.0[2] & 0xFF00_0000) >> 16
            | (self.0[3] & 0xFF00_0000) >> 24;

        let r1 = (self.0[0] & 0x00FF_0000) << 8
            | (self.0[1] & 0x00FF_0000)
            | (self.0[2] & 0x00FF_0000) >> 8
            | (self.0[3] & 0x00FF_0000) >> 16;

        let r2 = (self.0[0] & 0x0000_FF00) << 16
            | (self.0[1] & 0x0000_FF00) << 8
            | (self.0[2] & 0x0000_FF00)
            | (self.0[3] & 0x0000_FF00) >> 8;

        let r3 = (self.0[0] & 0x0000_00FF) << 24
            | (self.0[1] & 0x0000_00FF) << 16
            | (self.0[2] & 0x0000_00FF) << 8
            | (self.0[3] & 0x0000_00FF);

        // rotate row words
        let r0 = r0;
        let r1 = r1.rotate_right(8);
        let r2 = r2.rotate_right(16);
        let r3 = r3.rotate_right(24);

        // reassemble rows -> columns
        self.0[0] = (r0 & 0xFF00_0000)
            | ((r1 & 0xFF00_0000) >> 8)
            | ((r2 & 0xFF00_0000) >> 16)
            | ((r3 & 0xFF00_0000) >> 24);

        self.0[1] = ((r0 & 0x00FF_0000) << 8)
            | (r1 & 0x00FF_0000)
            | ((r2 & 0x00FF_0000) >> 8)
            | ((r3 & 0x00FF_0000) >> 16);

        self.0[2] = ((r0 & 0x0000_FF00) << 16)
            | ((r1 & 0x0000_FF00) << 8)
            | (r2 & 0x0000_FF00)
            | ((r3 & 0x0000_FF00) >> 8);

        self.0[3] = ((r0 & 0x0000_00FF) << 24)
            | ((r1 & 0x0000_00FF) << 16)
            | ((r2 & 0x0000_00FF) << 8)
            | (r3 & 0x0000_00FF);
    }

    fn mix_columns(&mut self) {
        self.0[0] = Self::mix_column(self.0[0]);
        self.0[1] = Self::mix_column(self.0[1]);
        self.0[2] = Self::mix_column(self.0[2]);
        self.0[3] = Self::mix_column(self.0[3]);
    }

    fn mix_column(a: u32) -> u32 {
        let a0 = ((a & 0xFF00_0000) >> 24) as u8;
        let a1 = ((a & 0x00FF_0000) >> 16) as u8;
        let a2 = ((a & 0x0000_FF00) >> 8) as u8;
        let a3 = (a & 0x0000_00FF) as u8;

        let b0 = Self::x_times(a0) ^ Self::x_times(a1) ^ a1 ^ a2 ^ a3;
        let b1 = a0 ^ Self::x_times(a1) ^ Self::x_times(a2) ^ a2 ^ a3;
        let b2 = a0 ^ a1 ^ Self::x_times(a2) ^ Self::x_times(a3) ^ a3;
        let b3 = Self::x_times(a0) ^ a0 ^ a1 ^ a2 ^ Self::x_times(a3);

        ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | b3 as u32
    }

    fn inv_mix_columns(&mut self) {
        self.0[0] = Self::inv_mix_column(self.0[0]);
        self.0[1] = Self::inv_mix_column(self.0[1]);
        self.0[2] = Self::inv_mix_column(self.0[2]);
        self.0[3] = Self::inv_mix_column(self.0[3]);
    }

    fn inv_mix_column(a: u32) -> u32 {
        let a0 = ((a & 0xFF00_0000) >> 24) as u8;
        let a1 = ((a & 0x00FF_0000) >> 16) as u8;
        let a2 = ((a & 0x0000_FF00) >> 8) as u8;
        let a3 = (a & 0x0000_00FF) as u8;

        let b0 = Self::mul_e(a0) ^ Self::mul_b(a1) ^ Self::mul_d(a2) ^ Self::mul_9(a3);
        let b1 = Self::mul_9(a0) ^ Self::mul_e(a1) ^ Self::mul_b(a2) ^ Self::mul_d(a3);
        let b2 = Self::mul_d(a0) ^ Self::mul_9(a1) ^ Self::mul_e(a2) ^ Self::mul_b(a3);
        let b3 = Self::mul_b(a0) ^ Self::mul_d(a1) ^ Self::mul_9(a2) ^ Self::mul_e(a3);

        ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | b3 as u32
    }

    fn mul_9(a: u8) -> u8 {
        let a2 = Self::x_times(a);
        let a4 = Self::x_times(a2);
        let a8 = Self::x_times(a4);
        a8 ^ a
    }

    fn mul_b(a: u8) -> u8 {
        let a2 = Self::x_times(a);
        let a4 = Self::x_times(a2);
        let a8 = Self::x_times(a4);
        a8 ^ a2 ^ a
    }

    fn mul_d(a: u8) -> u8 {
        let a2 = Self::x_times(a);
        let a4 = Self::x_times(a2);
        let a8 = Self::x_times(a4);
        a8 ^ a4 ^ a
    }

    fn mul_e(a: u8) -> u8 {
        let a2 = Self::x_times(a);
        let a4 = Self::x_times(a2);
        let a8 = Self::x_times(a4);
        a8 ^ a4 ^ a2
    }

    fn x_times(a: u8) -> u8 {
        if a & 0x80 != 0 {
            (a << 1) ^ 0x1b
        } else {
            a << 1
        }
    }

    fn add_round_key(&mut self, round_key: &[u32]) {
        assert_eq!(round_key.len(), 4);
        self.0[0] ^= round_key[0];
        self.0[1] ^= round_key[1];
        self.0[2] ^= round_key[2];
        self.0[3] ^= round_key[3];
    }

    fn sub_bytes(&mut self) {
        self.0[0] = sub_word(self.0[0]);
        self.0[1] = sub_word(self.0[1]);
        self.0[2] = sub_word(self.0[2]);
        self.0[3] = sub_word(self.0[3]);
    }

    fn inv_sub_bytes(&mut self) {
        self.0[0] = inv_sub_word(self.0[0]);
        self.0[1] = inv_sub_word(self.0[1]);
        self.0[2] = inv_sub_word(self.0[2]);
        self.0[3] = inv_sub_word(self.0[3]);
    }
}

fn cipher(input: State, rounds: u8, round_keys: [u32; 44]) -> State {
    let mut state = input;
    state.add_round_key(&round_keys[0..4]);
    for round in 1..rounds {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_keys[4 * round as usize..4 * (round as usize + 1)]);
    }
    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_keys[40..44]);
    state
}

fn cipher_192(input: State, rounds: u8, round_keys: [u32; 52]) -> State {
    let mut state = input;
    state.add_round_key(&round_keys[0..4]);
    for round in 1..rounds {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_keys[4 * round as usize..4 * (round as usize + 1)]);
    }
    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_keys[48..52]);
    state
}

fn cipher_256(input: State, rounds: u8, round_keys: [u32; 60]) -> State {
    let mut state = input;
    state.add_round_key(&round_keys[0..4]);
    for round in 1..rounds {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_keys[4 * round as usize..4 * (round as usize + 1)]);
    }
    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_keys[56..60]);
    state
}

fn inv_cipher(input: State, rounds: u8, round_keys: [u32; 44]) -> State {
    let mut state = input;
    state.add_round_key(&round_keys[40..44]);
    for round in (1..rounds).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&round_keys[4 * round as usize..4 * (round as usize + 1)]);
        state.inv_mix_columns();
    }
    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&round_keys[0..4]);
    state
}

fn inv_cipher_192(input: State, rounds: u8, round_keys: [u32; 52]) -> State {
    let mut state = input;
    state.add_round_key(&round_keys[48..52]);
    for round in (1..rounds).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&round_keys[4 * round as usize..4 * (round as usize + 1)]);
        state.inv_mix_columns();
    }
    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&round_keys[0..4]);
    state
}

fn inv_cipher_256(input: State, rounds: u8, round_keys: [u32; 60]) -> State {
    let mut state = input;
    state.add_round_key(&round_keys[56..60]);
    for round in (1..rounds).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&round_keys[4 * round as usize..4 * (round as usize + 1)]);
        state.inv_mix_columns();
    }
    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&round_keys[0..4]);
    state
}

fn inv_sub_bytes() {
    todo!()
}

// TODO: generalize, currently 10 rounds hard-coded
fn key_expansion(key: [u32; 4]) -> [u32; 44] {
    const ROUND_CONSTANTS: [u32; 10] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1b000000, 0x36000000,
    ];

    let mut keys = [0; 44];

    for (i, k) in key.iter().enumerate() {
        keys[i] = *k;
    }

    let mut i = 4;
    while i < 44 {
        let temp = keys[i - 1];
        if i % 4 == 0 {
            keys[i] = keys[i - 4] ^ sub_word(rot_word(temp)) ^ ROUND_CONSTANTS[i / 4 - 1];
        } else {
            keys[i] = keys[i - 4] ^ keys[i - 1];
        }
        i += 1;
    }

    keys
}

pub fn key_expansion_192(key: [u32; 6]) -> [u32; 52] {
    const ROUND_CONSTANTS: [u32; 10] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1b000000, 0x36000000,
    ];
    const NK: usize = 6;

    let mut keys = [0; 52];

    for (i, k) in key.iter().enumerate() {
        keys[i] = *k;
    }

    let mut i = NK;
    while i < 52 {
        let temp = keys[i - 1];
        if i.is_multiple_of(NK) {
            keys[i] = keys[i - NK] ^ sub_word(rot_word(temp)) ^ ROUND_CONSTANTS[i / NK - 1];
        } else {
            keys[i] = keys[i - NK] ^ keys[i - 1];
        }
        i += 1;
    }

    keys
}

pub fn key_expansion_256(key: [u32; 8]) -> [u32; 60] {
    const ROUND_CONSTANTS: [u32; 10] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1b000000, 0x36000000,
    ];
    const NK: usize = 8;

    let mut keys = [0; 60];

    for (i, k) in key.iter().enumerate() {
        keys[i] = *k;
    }

    let mut i = NK;
    while i < 60 {
        let temp = keys[i - 1];
        if i.is_multiple_of(NK) {
            keys[i] = keys[i - NK] ^ sub_word(rot_word(temp)) ^ ROUND_CONSTANTS[i / NK - 1];
        } else if i % NK == 4 {
            keys[i] = keys[i - NK] ^ sub_word(temp);
        } else {
            keys[i] = keys[i - NK] ^ keys[i - 1];
        }
        i += 1;
    }

    keys
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

fn sub_word(word: u32) -> u32 {
    let mut output = 0u32;
    for i in 0..4 {
        let byte = (word >> (i * 8)) % 256;
        output |= (SBOX[byte as usize] as u32) << (i * 8);
    }
    output
}

fn inv_sub_word(word: u32) -> u32 {
    let mut output = 0u32;
    for i in 0..4 {
        let byte = (word >> (i * 8)) % 256;
        output |= (INV_SBOX[byte as usize] as u32) << (i * 8);
    }
    output
}

fn aes_block_to_bytes(block: [u32; 4]) -> [u8; 16] {
    unsafe {
        core::mem::transmute([
            block[0].to_be(),
            block[1].to_be(),
            block[2].to_be(),
            block[3].to_be(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shift_rows() {
        let mut state = State([0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f]);
        state.shift_rows();
        assert_eq!(state.0, [0x00050a0f, 0x04090e03, 0x080d0207, 0x0c01060b]);

        let mut state = State([0xD937AB59, 0xBF2F0F1C, 0xFDD85D80, 0x0D7B9F8A]);
        state.shift_rows();
        assert_eq!(state.0, [0xD92F5D8A, 0xBFD89F59, 0xFD7BAB1C, 0x0D370F80]);

        let mut state = State([0x73C11B4E, 0x37C0AC12, 0x7501E10C, 0x02DA1BD5]);
        state.shift_rows();
        assert_eq!(state.0, [0x73C0E1D5, 0x37011B4E, 0x75DA1B12, 0x02C1AC0C]);
    }

    #[test]
    fn sub_bytes() {
        let mut state = State([0x40BFABF4, 0x06EE4D30, 0x42CA6B99, 0x7A5C5816]);
        state.sub_bytes();
        assert_eq!(state.0, [0x090862BF, 0x6F28E304, 0x2C747FEE, 0xDA4A6A47]);

        let mut state = State([0xF265E8D5, 0x1FD2397B, 0xC3B9976D, 0x9076505C]);
        state.sub_bytes();
        assert_eq!(state.0, [0x894D9B03, 0xC0B51221, 0x2E56883C, 0x6038534A]);

        let mut state = State([0x8FDD44B6, 0xB21FAA39, 0x3F09E081, 0x6A7A44B5]);
        state.sub_bytes();
        assert_eq!(state.0, [0x73C11B4E, 0x37C0AC12, 0x7501E10C, 0x02DA1BD5]);
    }

    #[test]
    fn mix_columns() {
        let mut state = State([0x09287F47, 0x6F746ABF, 0x2C4A6204, 0xDA08E3EE]);
        state.mix_columns();
        assert_eq!(state.0, [0x529F16C2, 0x978615CA, 0xE01AAE54, 0xBA1A2659]);

        let mut state = State([0x89B5884A, 0xC0565303, 0x2E389B21, 0x604D123C]);
        state.mix_columns();
        assert_eq!(state.0, [0x0F31E929, 0x319A3558, 0xAEC95893, 0x39F04D87]);

        let mut state = State([0xD4A37996, 0x74026806, 0xF24F0F09, 0x317268F5]);
        state.mix_columns();
        assert_eq!(state.0, [0xA294248A, 0x80CEACFA, 0x2874B85F, 0x699897B8]);
    }

    /// Key Expansion Example (128-bit key)
    ///
    /// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    #[test]
    fn key_expansion_128() {
        const KEY: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

        let expanded_key = key_expansion(KEY);
        assert_eq!(&expanded_key[0..4], &KEY[0..4]);
        assert_eq!(expanded_key[4], 0xa0fafe17);
        assert_eq!(expanded_key[5], 0x88542cb1);
        assert_eq!(expanded_key[6], 0x23a33939);
        assert_eq!(expanded_key[7], 0x2a6c7605);
        assert_eq!(expanded_key[8], 0xf2c295f2);
        assert_eq!(expanded_key[9], 0x7a96b943);
        assert_eq!(expanded_key[10], 0x5935807a);
        assert_eq!(expanded_key[20], 0xd4d1c6f8);
        assert_eq!(expanded_key[32], 0xead27321);
        assert_eq!(expanded_key[40], 0xd014f9a8);
        assert_eq!(expanded_key[43], 0xb6630ca6);
    }

    /// Key Expansion Example (192-bit key)
    ///
    /// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    #[test]
    fn key_expansion_192() {
        const KEY: [u32; 6] = [
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
        ];

        let expanded_key = super::key_expansion_192(KEY);
        assert_eq!(&expanded_key[0..6], &KEY[0..6]);
        assert_eq!(expanded_key[6], 0xfe0c91f7);
        assert_eq!(expanded_key[7], 0x2402f5a5);
        assert_eq!(expanded_key[8], 0xec12068e);
        assert_eq!(expanded_key[9], 0x6c827f6b);
        assert_eq!(expanded_key[10], 0x0e7a95b9);
        assert_eq!(expanded_key[12], 0x4db7b4bd);
        assert_eq!(expanded_key[20], 0xa448f6d9);
        assert_eq!(expanded_key[32], 0x485f7032);
        assert_eq!(expanded_key[40], 0xa7e1466c);
        assert_eq!(expanded_key[50], 0x8ecc7204);
        assert_eq!(expanded_key[51], 0x01002202);
    }

    /// Key Expansion Example (256-bit key)
    ///
    /// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    #[test]
    fn key_expansion_256() {
        const KEY: [u32; 8] = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4,
        ];

        let expanded_key = super::key_expansion_256(KEY);
        assert_eq!(&expanded_key[0..8], &KEY[0..8]);
        assert_eq!(expanded_key[8], 0x9ba35411);
        assert_eq!(expanded_key[9], 0x8e6925af);
        assert_eq!(expanded_key[10], 0xa51a8b5f);
        assert_eq!(expanded_key[12], 0xa8b09c1a);
        assert_eq!(expanded_key[16], 0xd59aecb8);
        assert_eq!(expanded_key[20], 0xb5a9328a);
        assert_eq!(expanded_key[32], 0x68007bac);
        assert_eq!(expanded_key[40], 0xde136967);
        assert_eq!(expanded_key[50], 0xe2757e4f);
        assert_eq!(expanded_key[59], 0x706c631e);
    }

    /// Cipher Example (128-bit key)
    ///
    /// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    #[test]
    fn cipher_example() {
        const PLAINTEXT: [u32; 4] = [0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734];
        const KEY: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

        let expanded_key = key_expansion(KEY);
        let output = cipher(State(PLAINTEXT), 10, expanded_key);
        assert_eq!(output.0, [0x3925841d, 0x02dc09fb, 0xdc118597, 0x196a0b32]);

        let plaintext = inv_cipher(output, 10, expanded_key);
        assert_eq!(plaintext.0, PLAINTEXT);
    }

    /// Example Vector (128-bit key)
    ///
    /// Source: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
    #[test]
    fn example_vector_128() {
        const PLAINTEXT: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        const KEY: [u32; 4] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];

        let expanded_key = key_expansion(KEY);
        let output = cipher(State(PLAINTEXT), 10, expanded_key);
        assert_eq!(output.0, [0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a]);

        let plaintext = inv_cipher(output, 10, expanded_key);
        assert_eq!(plaintext.0, PLAINTEXT);
    }

    /// Example Vector (192-bit key)
    ///
    /// Source: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
    #[test]
    fn example_vector_192() {
        const PLAINTEXT: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        const KEY: [u32; 6] = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
        ];

        let expanded_key = super::key_expansion_192(KEY);
        let output = cipher_192(State(PLAINTEXT), 12, expanded_key);
        assert_eq!(output.0, [0xdda97ca4, 0x864cdfe0, 0x6eaf70a0, 0xec0d7191]);

        let plaintext = inv_cipher_192(output, 12, expanded_key);
        assert_eq!(plaintext.0, PLAINTEXT);
    }

    /// Example Vector (256-bit key)
    ///
    /// Source: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
    #[test]
    fn example_vector_256() {
        const PLAINTEXT: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        const KEY: [u32; 8] = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
            0x1c1d1e1f,
        ];

        let expanded_key = super::key_expansion_256(KEY);
        let output = cipher_256(State(PLAINTEXT), 14, expanded_key);
        assert_eq!(output.0, [0x8ea2b7ca, 0x516745bf, 0xeafc4990, 0x4b496089]);

        let plaintext = inv_cipher_256(output, 14, expanded_key);
        assert_eq!(plaintext.0, PLAINTEXT);
    }

    /// ECB Encryption/Decryption Test Vector (128-bit key)
    ///
    /// Source: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    #[test]
    fn ecb_128() {
        const KEY: [u32; 4] = [0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C];
        const PLAINTEXT: [[u32; 4]; 4] = [
            [0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A],
            [0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51],
            [0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF],
            [0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710],
        ];
        const CIPHERTEXT: [[u32; 4]; 4] = [
            [0x3AD77BB4, 0x0D7A3660, 0xA89ECAF3, 0x2466EF97],
            [0xF5D3D585, 0x03B9699D, 0xE785895A, 0x96FDBAAF],
            [0x43B1CD7F, 0x598ECE23, 0x881B00E3, 0xED030688],
            [0x7B0C785E, 0x27E8AD3F, 0x82232071, 0x04725DD4],
        ];

        let expanded_key = key_expansion(KEY);

        // encryption
        for i in 0..4 {
            let output = cipher(State(PLAINTEXT[i]), 10, expanded_key);
            assert_eq!(output.0, CIPHERTEXT[i]);
        }

        // decryption
        for i in 0..4 {
            let output = inv_cipher(State(CIPHERTEXT[i]), 10, expanded_key);
            assert_eq!(output.0, PLAINTEXT[i]);
        }
    }

    /// ECB Encryption/Decryption Test Vector (192-bit key)
    ///
    /// Source: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    #[test]
    fn ecb_192() {
        const KEY: [u32; 6] = [
            0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B,
        ];
        const PLAINTEXT: [[u32; 4]; 4] = [
            [0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A],
            [0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51],
            [0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF],
            [0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710],
        ];
        const CIPHERTEXT: [[u32; 4]; 4] = [
            [0xBD334F1D, 0x6E45F25F, 0xF712A214, 0x571FA5CC],
            [0x97410484, 0x6D0AD3AD, 0x7734ECB3, 0xECEE4EEF],
            [0xEF7AFD22, 0x70E2E60A, 0xDCE0BA2F, 0xACE6444E],
            [0x9A4B41BA, 0x738D6C72, 0xFB166916, 0x03C18E0E],
        ];

        let expanded_key = super::key_expansion_192(KEY);

        // encryption
        for i in 0..4 {
            let output = cipher_192(State(PLAINTEXT[i]), 12, expanded_key);
            assert_eq!(output.0, CIPHERTEXT[i]);
        }

        // decryption
        for i in 0..4 {
            let output = inv_cipher_192(State(CIPHERTEXT[i]), 12, expanded_key);
            assert_eq!(output.0, PLAINTEXT[i]);
        }
    }

    /// ECB Encryption/Decryption Test Vector (256-bit key)
    ///
    /// Source: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    #[test]
    fn ecb_256() {
        const KEY: [u32; 8] = [
            0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, 0x1F352C07, 0x3B6108D7, 0x2D9810A3,
            0x0914DFF4,
        ];
        const PLAINTEXT: [[u32; 4]; 4] = [
            [0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A],
            [0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51],
            [0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF],
            [0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710],
        ];
        const CIPHERTEXT: [[u32; 4]; 4] = [
            [0xF3EED1BD, 0xB5D2A03C, 0x064B5A7E, 0x3DB181F8],
            [0x591CCB10, 0xD410ED26, 0xDC5BA74A, 0x31362870],
            [0xB6ED21B9, 0x9CA6F4F9, 0xF153E7B1, 0xBEAFED1D],
            [0x23304B7A, 0x39F9F3FF, 0x067D8D8F, 0x9E24ECC7],
        ];

        let expanded_key = super::key_expansion_256(KEY);

        // encryption
        for i in 0..4 {
            let output = cipher_256(State(PLAINTEXT[i]), 14, expanded_key);
            assert_eq!(output.0, CIPHERTEXT[i]);
        }

        // decryption
        for i in 0..4 {
            let output = inv_cipher_256(State(CIPHERTEXT[i]), 14, expanded_key);
            assert_eq!(output.0, PLAINTEXT[i]);
        }
    }
}
