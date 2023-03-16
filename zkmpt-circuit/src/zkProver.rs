use std::marker::PhantomData;

use halo2_proofs::{
    plonk::{ Circuit, ConstraintSystem}, 
    circuit::{SimpleFloorPlanner, Layouter}, 
    arithmetic::FieldExt,
    halo2curves::bn256::Fr,
};

use crate::{operation::AccountOp, gadgets::table_util::MPTProofType};

// entry point 
#[derive(Clone, Debug)]
pub struct ZkProverCircuitConfig {
    // speck256k1Gadget: 
}

impl ZkProverCircuitConfig {
    pub fn configure<FE: FieldExt>(meta: &mut ConstraintSystem<FE>) -> Self {
        ZkProverCircuitConfig {

        }
    }
}

#[derive(Clone, Default)]
pub struct ZkProverCircuit<FE: FieldExt> {
     /// the maxium records in circuits (would affect vk)
     pub calcs: usize,
     pub ops: Vec<AccountOp<FE>>,
 
    //   /// the mpt table for operations,
    //  /// if NONE, circuit work under lite mode
    //  /// no run-time checking for the consistents between ops and generated mpt table
    //  pub mpt_table: Vec<MPTProofType>,
}

impl <FE: FieldExt> Circuit<FE> for ZkProverCircuit<FE> {
    type Config = ZkProverCircuitConfig;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<FE>) -> Self::Config {
        ZkProverCircuitConfig::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<FE>) -> Result<(), halo2_proofs::plonk::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_func() {
        
    }
}