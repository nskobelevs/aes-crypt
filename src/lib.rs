use paste::paste;

mod constants;
mod common;
mod key_expansion;
mod encryption;
mod decryption;

pub use crate::constants::{sbox, inverse_sbox, rcon};
pub use key_expansion::{RotWord};
pub use encryption::{SubBytes, ShiftRows, MixColumns};
pub use decryption::{InvSubBytes, InvShiftRows, InvMixColumns};
pub use common::{AddRoundKey, SubWord};

use key_expansion::create_key_expansion_functions;
use encryption::create_aes_ecryption_functions;

macro_rules! create_aes_functions {
    ( $key_length:literal, $key_words_count:literal, $round_count:literal, $expanded_key_size:literal) => {
        paste! {
            create_key_expansion_functions!($key_length, $key_words_count, $round_count, $expanded_key_size);
            create_aes_ecryption_functions!($key_length, $key_words_count, $round_count, $expanded_key_size);
        }
    };
}

// Create the three AES variants
// (key-size, key-size in words, number of rounds, expanded key size in words)
create_aes_functions!(128, 4, 11, 44);
create_aes_functions!(196, 6, 13, 52);
create_aes_functions!(256, 8, 15, 60);
