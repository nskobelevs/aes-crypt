use paste::paste;

mod constants;

use crate::constants::*;

/// Puts a value through the Rijndael S-box
pub const fn sbox(value: u8) -> u8 {
    SBOX[value as usize]
}

/// Puts a value through the inverse Rijndael S-box
pub const fn inverse_sbox(value: u8) -> u8 {
    INVERSE_SBOX[value as usize]
}

/// Returns the round constant for the round i of key-expansion
///
/// panics if i is out of bounds 1..=10
pub const fn rcon(i: u8) -> u32 {
    if i < 1 {
        panic!("rcon() called with i < 1");
    }

    if i > 10 {
        panic!("rcon() called with i > 10");
    }

    RCON[(i - 1) as usize]
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

create_gmul_funcs!(2, 3, 9, 11, 13, 14);

/// Performs a 1-byte left circular shift
#[allow(non_snake_case)]
pub const fn RotWord(word: u32) -> u32 {
    rotl_word(word, 1)
}

const fn rotl_word(word: u32, byte_count: u8) -> u32 {
    (word << (byte_count * 8)) | (word >> (32 - (byte_count * 8)))
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

macro_rules! create_aes_functions {
    ( $key_length:literal, $key_words_count:literal, $round_count:literal, $expanded_key_size:literal) => {
        paste! {
            #[doc = concat!("Expands a ", stringify!($key_length), " bit length key for AES-", stringify!($key_length), " encryption.")]
            pub const fn [<expand_ $key_length _bit_key>](key: [u32; $key_words_count]) -> [u32; $expanded_key_size] {
                let mut key_words = [0u32; $expanded_key_size];

                let mut i = 0;

                while i < key_words.len() {
                    key_words[i] = if i < $key_words_count {
                        key[i]
                    } else if i >= $key_words_count && (i % $key_words_count) == 0 {
                        key_words[i - $key_words_count] ^ SubWord(RotWord(key_words[i - 1])) ^ rcon((i / $key_words_count) as u8)
                    } else if i >= $key_words_count && $key_words_count > 6 && (i % $key_words_count) == 4 {
                        key_words[i - $key_words_count] ^ SubWord(key_words[i - 1])
                    } else {
                        key_words[i - $key_words_count] ^ key_words[i - 1]
                    };

                    i += 1;
                }

                key_words
            }

            #[doc = concat!("Performs AES-", stringify!($key_length), " on a block with a ", stringify!($key_length), "-bit key length.")]
            pub fn [<aes_ $key_length>](state: &mut [u32; 4], key: [u32; $key_words_count]) {
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

create_aes_functions!(128, 4, 11, 44);
create_aes_functions!(196, 6, 13, 52);
create_aes_functions!(256, 8, 15, 60);

/// Performs XOR on each byte of a state with each byte of a round key
#[allow(non_snake_case)]
pub fn AddRoundKey(state: &mut [u32; 4], round_key: &[u32]) {
    for i in 0..state.len() {
        state[i] ^= round_key[i];
    }
}

/// Performs the AES S-box on each byte of a block
#[allow(non_snake_case)]
pub fn SubBytes(state: &mut [u32; 4]) {
    for i in 0..state.len() {
        state[i] = SubWord(state[i]);
    }
}

/// Performs the inverse AES S-box on each byte of a block
#[allow(non_snake_case)]
pub fn InvSubBytes(state: &mut [u32; 4]) {
    for i in 0..state.len() {
        state[i] = InvSubWord(state[i]);
    }
}

/// Transposes the 4x4 matrix of bytes in the state
fn transpose(state: [u32; 4]) -> [u32; 4] {
    return [
        ((state[0] >> 24) & 0xff) << 24 | ((state[1] >> 24) & 0xff) << 16 | ((state[2] >> 24) & 0xff) << 8 | ((state[3] >> 24) & 0xff),
        ((state[0] >> 16) & 0xff) << 24 | ((state[1] >> 16) & 0xff) << 16 | ((state[2] >> 16) & 0xff) << 8 | ((state[3] >> 16) & 0xff),
        ((state[0] >> 8 ) & 0xff) << 24 | ((state[1] >> 8 ) & 0xff) << 16 | ((state[2] >> 8 ) & 0xff) << 8 | ((state[3] >> 8 ) & 0xff),
        ((state[0]      ) & 0xff) << 24 | ((state[1]      ) & 0xff) << 16 | ((state[2]      ) & 0xff) << 8 | ((state[3]      ) & 0xff),
    ];
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

    use super::*;

    #[test]
    pub fn test_sbox() {
        for value in 0..=255u8 {
            assert_eq_hex!(value, inverse_sbox(sbox(value)), "expected inverse_sbox(sbox({0:#04x})) == {0:#04x}", value);
        }
    }

    #[test]
    pub fn test_rot_word() {
        let inputs: [u32; 4] = [0x12345678, 0xaabbccdd, 0x87654321, 0x98abcdef];
        let outputs: [u32; 4] = [0x34567812, 0xbbccddaa, 0x65432187, 0xabcdef98];

        for (&input, &output) in inputs.iter().zip(outputs.iter()) {
            assert_eq_hex!(output, RotWord(input), "RotWord({}) output doesn't match expected", input);
        }
    }

    #[test]
    pub fn test_expand_128_bit_key() {
        let key: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
        let w = expand_128_bit_key(key);

        let expected = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
            0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
            0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
            0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
            0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
            0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
            0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
            0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
            0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
            0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
        ];

        assert_eq!(expected.len(), w.len(), "expected length of expanded key to be {0}", expected.len());

        for i in 0..w.len() {
            assert_eq_hex!(expected[i], w[i], "Key expansion for index {} doesn't match", i);
        }
    }

    #[test]
    pub fn test_expand_196_bit_key() {
        let key: [u32; 6] = [0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b];
        let w = expand_196_bit_key(key);

        let expected = [
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5,
            0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5,
            0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
            0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd,
            0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f,
            0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
            0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
            0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971,
            0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
            0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e,
            0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753,
            0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
            0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202,
        ];

        assert_eq!(expected.len(), w.len(), "expected length of expanded key to be {0}", expected.len());

        for i in 0..w.len() {
            assert_eq_hex!(expected[i], w[i], "Key expansion for index {} doesn't match", i);
        }
    }

    #[test]
    pub fn test_expand_256_bit_key() {
        let key: [u32; 8] = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4];
        let w = expand_256_bit_key(key);

        let expected = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
            0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
            0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
            0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
            0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
            0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
            0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
            0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
            0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
            0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
            0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15,
            0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
            0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a,
            0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
            0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
        ];

        assert_eq!(expected.len(), w.len(), "expected length of expanded key to be {0}", expected.len());

        for i in 0..w.len() {
            assert_eq_hex!(expected[i], w[i], "Key expansion for index {} doesn't match", i);
        }
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

    pub fn subtest_aes_128(mut state: [u32; 4], key: [u32; 4], expected: [u32; 4]) {
        aes_128(&mut state, key);
        assert_eq_hex!(expected, state, "AES-128 output doesn't match expected")
    }

    #[test]
    pub fn test_aes_128() {
        subtest_aes_128([0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734], [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c], [0x3925841d, 0x02dc09fb, 0xdc118597, 0x196a0b32]);
        subtest_aes_128([0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff], [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f], [0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a]);
    }


    #[test]
    pub fn test_aes_196() {
        let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        let key: [u32; 6] =       [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617];
        let expected: [u32; 4] =  [0xdda97ca4, 0x864cdfe0, 0x6eaf70a0, 0xec0d7191];

        aes_196(&mut input, key);

        assert_eq_hex!(expected, input, "AES-196 output doesn't match expected")
    }

    #[test]
    pub fn test_aes_256() {
        let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
        let key: [u32; 8] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];
        let expected: [u32; 4] = [0x8ea2b7ca, 0x516745bf, 0xeafc4990, 0x4b496089];

        aes_256(&mut input, key);

        assert_eq_hex!(expected, input, "AES-256 output doesn't match expected")
    }
}
