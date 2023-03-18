use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem},
};

use crate::{
    gadgets::{ecsdsa::Spec256k1Gadget, table_util::MPTProofType},
    operation::AccountOp,
    serde::{Hash, MPTTransTrace},
    ERC4337::geth_types::Transaction,
};

// entry point
#[derive(Clone, Debug)]
pub struct ZkProverCircuitConfig {
    // speck256k1: Spec256k1Gadget,
}

// impl ZkProverCircuitConfig {
//     pub fn configure<FE: FieldExt>(meta: &mut ConstraintSystem<FE>) -> Self {
//         ZkProverCircuitConfig {

//         }
//     }
// }

#[derive(Clone, Default)]
pub struct ZkProverCircuit<Fp: FieldExt, const TX_NUM: usize> {
    // the maxium records in circuits (would affect vk)
    pub mpt_root_before: Fp,
    pub mpt_root_after: Fp,
    //  pub mpt_proofs: Vec<>
    pub txs: Vec<Transaction>,
    //  pub ops: Vec<AccountOp<Fp>>,
}

impl<Fp: FieldExt, const TX_NUM: usize> ZkProverCircuit<Fp, TX_NUM> {
    // Constructs a new ZkProverCircuit
    // pub fn new(
    //     start_mpt_root_hash: Hash,
    //     end_mpt_root_hash: Hash,
    //     mpt_transaction: MPTTransTrace,
    // ) -> Self {
    //     // let start_mpt_root = start_mpt_root_hash.

    //     Self {}
    // }
}

impl<Fp: FieldExt, const TX_NUM: usize> Circuit<Fp> for ZkProverCircuit<Fp, TX_NUM> {
    type Config = ZkProverCircuitConfig;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // ZkProverCircuitConfig::configure(meta)

        ZkProverCircuitConfig {}
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fp>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_func() {}
}
