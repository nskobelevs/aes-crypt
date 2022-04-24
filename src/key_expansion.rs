use crate::common::rotl_word;

/// Performs a 1-byte left circular shift
#[allow(non_snake_case)]
pub const fn RotWord(word: u32) -> u32 {
    rotl_word(word, 1)
}

macro_rules! create_key_expansion_functions {
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
        }
    };
}
pub(crate) use create_key_expansion_functions;

#[cfg(test)]
mod tests {
    use assert_hex::assert_eq_hex;

    use crate::{expand_128_bit_key, expand_196_bit_key, expand_256_bit_key};

    use super::*;

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
}
