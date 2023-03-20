use std::marker::PhantomData;

use ethers::{types::Address, utils::rlp::RlpStream};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::{
        bn256::Fr,
        group::GroupEncoding,
        secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
    },
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;

use jsonrpsee::tracing::log::error;
/// Represents a point in bytes.
#[derive(Copy, Clone)]
pub struct Serialized([u8; 64]);

impl Default for Serialized {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl AsMut<[u8]> for Serialized {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

use crate::{
    gadgets::{
        ecsdsa::Spec256k1Gadget,
        sign_verify::{pk_bytes_swap_endianness, SignData},
        table_util::MPTProofType,
        ToBigEndian, ToLittleEndian,
    },
    operation::AccountOp,
    serde::{Hash, MPTTransTrace},
    ERC4337::bundler::{BundlerRpcData, Transaction, Word},
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
    pub chain_id: u64,
}

impl<Fp: FieldExt, const TX_NUM: usize> ZkProverCircuit<Fp, TX_NUM> {
    // Constructs a new ZkProverCircuit
    // pub fn new(
    //     start_mpt_root_hash: Hash,
    //     end_mpt_root_hash: Hash,
    //     rpc_txs: Vec<BundlerRpcData>,
    // ) -> Self {
    //     // let start_mpt_root = start_mpt_root_hash.

    //     let eth_txs: Vec<Transaction> = rpc_txs.iter().map(|tr|
    // tr.try_into().unwrap()).collect();

    //     Self { mpt_root_before: todo!(), mpt_root_after: todo!(), txs: todo!() }
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

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx.sign_1559_data().map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", tx);
                    e
                })
            })
            .try_collect()
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{fs::File, io::Read};

    use halo2_proofs::{dev::MockProver, halo2curves::secp256k1::Fp};

    use crate::ERC4337::bundler::BundlerRpcData;

    use super::ZkProverCircuit;
    #[test]
    fn test_zkprover_circuit() {
        let mut buffer = Vec::new();
        let mut f = File::open("src/ERC4337/rpc_data_test.json").unwrap();
        f.read_to_end(&mut buffer).unwrap();
        // println!("buffer {buffer:?}");

        let rpc_txs = serde_json::from_slice::<BundlerRpcData>(&buffer)
            .unwrap()
            .result
            .tx_list;

        const TX_NUM: usize = 2;
        let k = 7;

        let circuit = ZkProverCircuit::<Fp, TX_NUM> {
            mpt_root_before: Fp::zero(),
            mpt_root_after: Fp::zero(),
            txs: rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect(),
            chain_id: 5u64,
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_circuit_consistency() {

    }
}
