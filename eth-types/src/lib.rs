pub mod sign_types;

use ethers_core::types::U256;
use halo2_proofs::{
    arithmetic::{Field as Halo2Field, FieldExt},
    halo2curves::{group::ff::PrimeField, bn256::{Fr, Fq}},
};

/// Trait used to reduce verbosity with the declaration of the [`FieldExt`]
/// trait and its repr.
pub trait Field: FieldExt + Halo2Field + PrimeField<Repr = [u8; 32]> {}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}

/// Ethereum Word (256 bits).
pub type Word = U256;
