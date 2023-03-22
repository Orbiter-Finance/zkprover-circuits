use std::marker::PhantomData;

use halo2_proofs::{
    circuit::Layouter,
    halo2curves::{
        secp256k1::{self, Secp256k1Affine},
        FieldExt,
    },
    plonk::{ConstraintSystem, Expression},
};

/// Return a copy of the serialized public key with swapped Endianness.
pub(crate) fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk)
        .map(|r| r.clone())
        .expect("pk.len() != 64");
    pk_swap[..32].reverse();
    pk_swap[32..].reverse();
    pk_swap
}

#[derive(Clone, Debug)]
pub(crate) struct SignData {
    pub(crate) signature: (secp256k1::Fq, secp256k1::Fq),
    pub(crate) pk: Secp256k1Affine,
    pub(crate) msg_hash: secp256k1::Fq,
}

/// Power of randomness vector size required for the SignVerifyChip
pub const POW_RAND_SIZE: usize = 63;
/// SignVerify Configuration
#[derive(Debug, Clone)]
pub(crate) struct SignVerifyConfig<F: FieldExt> {
    power_of_randomness: [Expression<F>; POW_RAND_SIZE],
}

impl<F: FieldExt> SignVerifyConfig<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; POW_RAND_SIZE],
    ) -> Self {
        Self {
            power_of_randomness,
        }
    }
}

/// Auxiliary Gadget to verify a that a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Default, Debug)]
pub struct SignVerifyChip<F: FieldExt, const MAX_VERIF: usize> {
    /// Aux generator for EccChip
    pub aux_generator: Secp256k1Affine,
    /// Window size for EccChip
    pub window_size: usize,
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: FieldExt, const MAX_VERIF: usize> SignVerifyChip<F, MAX_VERIF> {
    pub(crate) fn assign(
        &self,
        config: &SignVerifyConfig<F>,
        layouter: &mut impl Layouter<F>,
        randomness: F,
        signatures: &[SignData],
    ) {
    }
}
