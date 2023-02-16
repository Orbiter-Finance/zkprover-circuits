pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::halo2curves::group::ff::PrimeField;
use num_traits::Num;
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
