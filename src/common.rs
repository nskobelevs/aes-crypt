use paste::paste;
use crate::constants::*;

#[inline]
pub const fn rotl_word(word: u32, byte_count: u8) -> u32 {
    (word << (byte_count * 8)) | (word >> (32 - (byte_count * 8)))
}

/// Transposes the 4x4 matrix of bytes in the state
pub fn transpose(state: [u32; 4]) -> [u32; 4] {
    return [
        ((state[0] >> 24) & 0xff) << 24 | ((state[1] >> 24) & 0xff) << 16 | ((state[2] >> 24) & 0xff) << 8 | ((state[3] >> 24) & 0xff),
        ((state[0] >> 16) & 0xff) << 24 | ((state[1] >> 16) & 0xff) << 16 | ((state[2] >> 16) & 0xff) << 8 | ((state[3] >> 16) & 0xff),
        ((state[0] >> 8 ) & 0xff) << 24 | ((state[1] >> 8 ) & 0xff) << 16 | ((state[2] >> 8 ) & 0xff) << 8 | ((state[3] >> 8 ) & 0xff),
        ((state[0]      ) & 0xff) << 24 | ((state[1]      ) & 0xff) << 16 | ((state[2]      ) & 0xff) << 8 | ((state[3]      ) & 0xff),
    ];
}

/// Performs XOR on each byte of a state with each byte of a round key
#[allow(non_snake_case)]
pub fn AddRoundKey(state: &mut [u32; 4], round_key: &[u32]) {
    for i in 0..state.len() {
        state[i] ^= round_key[i];
    }
}

/// Applies the AES S-box to each byte of a word
#[allow(non_snake_case)]
pub const fn SubWord(word: u32) -> u32 {
    let b0 = (word >> 24) as u8;
    let b1 = (word >> 16) as u8;
    let b2 = (word >> 8) as u8;
    let b3 = (word) as u8;

    let s0 = sbox(b0) as u32;
    let s1 = sbox(b1) as u32;
    let s2 = sbox(b2) as u32;
    let s3 = sbox(b3) as u32;

    (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
}

macro_rules! create_gmul_funcs {
    ( $( $n:literal ),* ) => {$(
        paste! {
            #[doc = concat!("Multiplies value by ", stringify!($n), " using Galois Multiplication")]
            pub const fn [<gmul $n>](value: u8) -> u8 {
                [<GMUL $n>][value as usize]
            }
        })*
    };
}

// This creates a bunch of gmulX functions for Galois Multiplication
create_gmul_funcs!(2, 3, 9, 11, 13, 14);

#[cfg(test)]
mod tests {
    use assert_hex::assert_eq_hex;

    use crate::expand_128_bit_key;

    use super::*;

    #[test]
    pub fn test_rotl_word() {
        let inputs: [(u32, u8); 3] = [(0x12345678, 1), (0x12345678, 2), (0x12345678, 3)];
        let expected: [u32; 5] = [0x12345678, 0x34567812, 0x56781234, 0x78123456, 0x12345678];

        for (&(input, shift), &output) in inputs.iter().zip(expected.iter()) {
            assert_eq_hex!(output, rotl_word(input, shift), "rotl_word({}, {}) output doesn't match expected", input, shift);
        }
    }

    #[test]
    pub fn test_sub_word() {
        let input: u32 = 0x01020304;
        let expected = (sbox(0x01) as u32) << 24 | (sbox(0x02) as u32) << 16 | (sbox(0x03) as u32) << 8 | sbox(0x04) as u32;

        assert_eq_hex!(expected, SubWord(input), "SubWord({:#010x}) output doesn't match expected", input);
    }

    #[test]
    pub fn test_add_round_key() {
        let input: [u32; 4] = [0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734];
        let mut state = input.clone();

        let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

        let expanded_key = expand_128_bit_key(key);

        AddRoundKey(&mut state, &expanded_key[0..4]);

        let expected: [u32; 4] = [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808];

        assert_eq_hex!(expected, state, "AddRoundKey({:#010x?}, {:#010x?}) output doesn't match", input, expanded_key[0]);
    }
}
