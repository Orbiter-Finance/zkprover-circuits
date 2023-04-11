use halo2_proofs::{
    arithmetic::{Field as Halo2Field, FieldExt},
    halo2curves::group::ff::PrimeField,
};

/// Trait used to reduce verbosity with the declaration of the [`FieldExt`]
/// trait and its repr.
pub trait Field: FieldExt + Halo2Field + PrimeField<Repr = [u8; 32]> {}
