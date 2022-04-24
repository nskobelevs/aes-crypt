use crate::{common::{transpose, rotl_word, gmul2, gmul3}, SubWord};

macro_rules! create_aes_ecryption_functions {
    ( $key_length:literal, $key_words_count:literal, $round_count:literal, $expanded_key_size:literal) => {
        paste! {
            #[doc = concat!("Performs AES-", stringify!($key_length), " encryption on a block with a ", stringify!($key_length), "-bit key length.")]
            pub fn [<aes_ $key_length _encrypt>](state: &mut [u32; 4], key: [u32; $key_words_count]) {
                let expanded_key = [<expand_ $key_length _bit_key>](key);

                for i in 0..$round_count {
                    if i != 0 {
                        SubBytes(state);
                        ShiftRows(state);
                        if i != $round_count - 1 {
                            MixColumns(state);
                        }
                    }

                    AddRoundKey(state, &expanded_key[i*4..(i+1)*4]);
                }
            }

        }
    };
}
pub(crate) use create_aes_ecryption_functions;


/// Performs the AES S-box on each byte of a block
#[allow(non_snake_case)]
pub fn SubBytes(state: &mut [u32; 4]) {
    for i in 0..state.len() {
        state[i] = SubWord(state[i]);
    }
}

/// Performs the shift rows operation, shifting every row circularly to the left by one byte
///
/// As specified by AES, the input is in column-major order
#[allow(non_snake_case)]
pub fn ShiftRows(state: &mut [u32; 4]) {
    let rows = transpose(*state);

    let shifted_rows = transpose([
        rows[0],
        rotl_word(rows[1], 1),
        rotl_word(rows[2], 2),
        rotl_word(rows[3], 3)
    ]);

    for i in 0..state.len() {
        state[i] = shifted_rows[i];
    }
}

/// Performs the mix column operation on a word
#[allow(non_snake_case)]
pub const fn MixColumn(word: u32) -> u32 {
    let b0 = (word >> 24) as u8;
    let b1 = (word >> 16) as u8;
    let b2 = (word >> 8) as u8;
    let b3 = word as u8;

    let d0 = gmul2(b0) ^ gmul3(b1) ^ b2 ^ b3;
    let d1 = b0 ^ gmul2(b1) ^ gmul3(b2) ^ b3;
    let d2 = b0 ^ b1 ^ gmul2(b2) ^ gmul3(b3);
    let d3 = gmul3(b0) ^ b1 ^ b2 ^ gmul2(b3);

    (d0 as u32) << 24 | (d1 as u32) << 16 | (d2 as u32) << 8 | d3 as u32
}

/// Performs the mix column operation on each word of the state
#[allow(non_snake_case)]
pub fn MixColumns(state: &mut [u32; 4]) {
    state[0] = MixColumn(state[0]);
    state[1] = MixColumn(state[1]);
    state[2] = MixColumn(state[2]);
    state[3] = MixColumn(state[3]);
}

#[cfg(test)]
mod tests {
    use assert_hex::assert_eq_hex;

    use crate::{aes_128_encrypt, aes_196_encrypt, aes_256_encrypt};

    use super::*;

    #[test]
    pub fn test_sub_bytes() {
        let input: [u32; 4] = [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808];
        let mut state = input.clone();

        SubBytes(&mut state);

        let expected: [u32; 4] = [0xd42711ae, 0xe0bf98f1, 0xb8b45de5, 0x1e415230];

        assert_eq_hex!(expected, state, "SubBytes({:#010x?}) output doesn't match", input);
    }

    #[test]
    pub fn test_shift_rows() {
        let mut input: [u32; 4] = [0xd42711ae, 0xe0bf98f1, 0xb8b45de5, 0x1e415230];

        ShiftRows(&mut input);

        let expected: [u32; 4] = [0xd4bf5d30, 0xe0b452ae, 0xb84111f1, 0x1e2798e5];

        assert_eq_hex!(expected, input, "ShiftRows({:#010x?}) otuput doesn't match", input);
    }

    #[test]
    pub fn test_mix_column() {
        let inputs: [u32; 6] = [0xdb135345, 0xf20a225c, 0x01010101, 0xc6c6c6c6, 0xd4d4d4d5, 0x2d26314c];
        let expected: [u32; 6] = [0x8e4da1bc, 0x9fdc589d, 0x01010101, 0xc6c6c6c6, 0xd5d5d7d6, 0x4d7ebdf8];

        for (&input, &expected) in inputs.iter().zip(expected.iter()) {
            assert_eq_hex!(expected, MixColumn(input), "MixColumn({:#010x}) output doesn't match", input);
        }
    }

    #[test]
    pub fn test_mix_columns() {
        let input: [u32; 4] = [0xd4bf5d30, 0xe0b452ae, 0xb84111f1, 0x1e2798e5];
        let mut state: [u32; 4] = input.clone();

        MixColumns(&mut state);

        let expected: [u32; 4] = [0x046681e5, 0xe0cb199a, 0x48f8d37a, 0x2806264c];

        assert_eq_hex!(expected, state, "MixColumns({:#010x?}) output doesn't match", input);
    }

    pub fn subtest_aes_128_encrypt(mut state: [u32; 4], key: [u32; 4], expected: [u32; 4]) {
        aes_128_encrypt(&mut state, key);
        assert_eq_hex!(expected, state, "AES-128 output doesn't match expected")
    }

    #[test]
    pub fn test_aes_128_encrypt() {
        subtest_aes_128_encrypt([0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734], [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c], [0x3925841d, 0x02dc09fb, 0xdc118597, 0x196a0b32]);
        subtest_aes_128_encrypt([0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff], [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f], [0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a]);
    }


    #[test]
    pub fn test_aes_196_encrypt() {
        let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        let key: [u32; 6] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617];
        let expected: [u32; 4] =  [0xdda97ca4, 0x864cdfe0, 0x6eaf70a0, 0xec0d7191];

        aes_196_encrypt(&mut input, key);

        assert_eq_hex!(expected, input, "AES-196 output doesn't match expected")
    }

    #[test]
    pub fn test_aes_256_encrypt() {
        let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        let key: [u32; 8] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];
        let expected: [u32; 4] = [0x8ea2b7ca, 0x516745bf, 0xeafc4990, 0x4b496089];

        aes_256_encrypt(&mut input, key);

        assert_eq_hex!(expected, input, "AES-256 output doesn't match expected")
    }
}
