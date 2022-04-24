use crate::{inverse_sbox, common::{transpose, rotl_word, gmul14, gmul11, gmul9, gmul13}};

macro_rules! create_aes_decryption_functions {
    ( $key_length:literal, $key_words_count:literal, $round_count:literal, $expanded_key_size:literal) => {
        paste! {
            #[doc = concat!("Performs AES-", stringify!($key_length), " decryption on a block with a ", stringify!($key_length), "-bit key length.")]
            pub fn [<aes_ $key_length _decrypt>](state: &mut [u32; 4], key: [u32; $key_words_count]) {
                let expanded_key = [<expand_ $key_length _bit_key>](key);

                AddRoundKey(state, &expanded_key[($expanded_key_size - 4)..$expanded_key_size]);

                for i in (2..$round_count).rev() {
                        InvShiftRows(state);
                        InvSubBytes(state);
                        AddRoundKey(state, &expanded_key[(i-1)*4..i*4]);
                        InvMixColumns(state);
                }

                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, &expanded_key[0..4]);
            }

        }
    };
}
pub(crate) use create_aes_decryption_functions;

/// Applies the AES inverse S-box to each byte of a word
#[allow(non_snake_case)]
pub const fn InvSubWord(word: u32) -> u32 {
    let b0 = (word >> 24) as u8;
    let b1 = (word >> 16) as u8;
    let b2 = (word >> 8) as u8;
    let b3 = (word) as u8;

    let s0 = inverse_sbox(b0) as u32;
    let s1 = inverse_sbox(b1) as u32;
    let s2 = inverse_sbox(b2) as u32;
    let s3 = inverse_sbox(b3) as u32;

    (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
}

/// Performs the inverse AES S-box on each byte of a block
#[allow(non_snake_case)]
pub fn InvSubBytes(state: &mut [u32; 4]) {
    for i in 0..state.len() {
        state[i] = InvSubWord(state[i]);
    }
}

/// Performs the inverse shift rows operation, shifting every row circularly to the left by one byte
///
/// As specified by AES, the input is in column-major order
#[allow(non_snake_case)]
pub fn InvShiftRows(state: &mut [u32; 4]) {
    let rows = transpose(*state);

    let shifted_rows = transpose([
        rows[0],
        rotl_word(rows[1], 3),
        rotl_word(rows[2], 2),
        rotl_word(rows[3], 1)
    ]);

    for i in 0..state.len() {
        state[i] = shifted_rows[i];
    }
}

/// Performs the inverse mix column operation on a word
#[allow(non_snake_case)]
pub const fn InvMixColumn(word: u32) -> u32 {
    let b0 = (word >> 24) as u8;
    let b1 = (word >> 16) as u8;
    let b2 = (word >> 8) as u8;
    let b3 = word as u8;

    let d0 = gmul14(b0) ^ gmul11(b1) ^ gmul13(b2) ^ gmul9(b3);
    let d1 = gmul9(b0) ^ gmul14(b1) ^ gmul11(b2) ^ gmul13(b3);
    let d2 = gmul13(b0) ^ gmul9(b1) ^ gmul14(b2) ^ gmul11(b3);
    let d3 = gmul11(b0) ^ gmul13(b1) ^ gmul9(b2) ^ gmul14(b3);

    (d0 as u32) << 24 | (d1 as u32) << 16 | (d2 as u32) << 8 | d3 as u32
}

/// Performs the inverse mix column operation on each word of the state
#[allow(non_snake_case)]
pub fn InvMixColumns(state: &mut [u32; 4]) {
    state[0] = InvMixColumn(state[0]);
    state[1] = InvMixColumn(state[1]);
    state[2] = InvMixColumn(state[2]);
    state[3] = InvMixColumn(state[3]);
}

#[cfg(test)]
mod tests {
    use assert_hex::assert_eq_hex;

    use crate::{aes_128_decrypt, aes_196_decrypt, aes_256_decrypt};

    use super::*;

    #[test]
    pub fn test_inverse_mix_column() {
        let inputs: [u32; 6] = [0x8e4da1bc, 0x9fdc589d, 0x01010101, 0xc6c6c6c6, 0xd5d5d7d6, 0x4d7ebdf8];
        let expected: [u32; 6] = [0xdb135345, 0xf20a225c, 0x01010101, 0xc6c6c6c6, 0xd4d4d4d5, 0x2d26314c];

        for (&input, &expected) in inputs.iter().zip(expected.iter()) {
            assert_eq_hex!(expected, InvMixColumn(input), "InvMixColumn({:#010x}) output doesn't match", input);
        }
    }

    #[test]
    pub fn test_inv_mix_columns() {
        let input: [u32; 4] = [0x046681e5, 0xe0cb199a, 0x48f8d37a, 0x2806264c];
        let mut state: [u32; 4] = input.clone();

        InvMixColumns(&mut state);

        let expected: [u32; 4] = [0xd4bf5d30, 0xe0b452ae, 0xb84111f1, 0x1e2798e5];

        assert_eq_hex!(expected, state, "InvMixColumns({:#010x?}) output doesn't match", input);
    }

    #[test]
    pub fn test_aes_128_decrypt() {
        let mut input: [u32; 4] = [0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a];
        let key: [u32; 4] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
        let expected: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];

        aes_128_decrypt(&mut input, key);

        assert_eq_hex!(expected, input, "AES-128 output doesn't match expected")
    }

    #[test]
    pub fn test_aes_196_decrypt() {
        let mut input: [u32; 4] =  [0xdda97ca4, 0x864cdfe0, 0x6eaf70a0, 0xec0d7191];
        let key: [u32; 6] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617];
        let expected: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];

        aes_196_decrypt(&mut input, key);

        assert_eq_hex!(expected, input, "AES-196 output doesn't match expected")
    }

    #[test]
    pub fn test_aes_256_decrypt() {
        let mut input: [u32; 4] = [0x8ea2b7ca, 0x516745bf, 0xeafc4990, 0x4b496089];
        let key: [u32; 8] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];
        let expected: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];

        aes_256_decrypt(&mut input, key);

        assert_eq_hex!(expected, input, "AES-256 output doesn't match expected")
    }
}
