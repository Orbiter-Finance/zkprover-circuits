pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{halo2curves::group::ff::PrimeField, arithmetic::Field};
use num_traits::Num;
use rand::{random, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{i64, str::FromStr};

use num_bigint::BigInt;

pub fn hash_str_to_fp(hash_str: &str) -> Fp {
    let hash_int = BigInt::from_str_radix(&hash_str.trim_start_matches("0x"), 16)
        .unwrap()
        .to_string();
    // let hash_int = BigInt::from_str
    let tx1_hash_fp: Fp = Fp::from_str_vartime(&hash_int).unwrap();

    tx1_hash_fp
}

pub fn rand_gen(seed: [u8; 32]) -> ChaCha8Rng {
    ChaCha8Rng::from_seed(seed)
}

pub fn rand_bytes_array<const N: usize>() -> [u8; N] {
    [(); N].map(|_| random())
}

pub fn rand_fp() -> Fp {
    let arr = rand_bytes_array::<32>();
    Fp::random(rand_gen(arr))
}
