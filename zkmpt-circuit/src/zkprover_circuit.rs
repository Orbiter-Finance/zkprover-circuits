use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;

use jsonrpsee::tracing::log::error;
use std::fmt::Debug;

use crate::gadgets::hashes_sum::{SumChip, SumConfig};

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
    gadgets::sign_verify::SignData, serde::Hash, verifier::circuit_deploy::TargetCircuit,
    ERC4337::bundler::Transaction,
};

// entry point
#[derive(Clone, Debug)]
pub struct ZkProverCircuitConfig<Fp: FieldExt> {
    sum_config: SumConfig<Fp>,
    _marker: PhantomData<Fp>,
}

impl<Fp: FieldExt> ZkProverCircuitConfig<Fp> {
    pub fn new(meta: &mut ConstraintSystem<Fp>) -> Self {
        let sum_config = SumChip::configure(meta);
        ZkProverCircuitConfig {
            sum_config,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct ZkProverCircuit<Fp: FieldExt, const TX_NUM: usize> {
    // the maxium records in circuits (would affect vk)
    pub mpt_root_before: Fp,
    pub mpt_root_after: Fp,
    //  pub mpt_proofs: Vec<>
    pub txs: Vec<Transaction>,
    //  pub ops: Vec<AccountOp<Fp>>,
    pub chain_id: u64,

    pub hash_sum_chip: SumChip<Fp>,
    // pub tx_verify_chip:

    // for the test mock data
    pub mock_hashes_element: Vec<Value<Fp>>,
    pub mock_hashes_sum: Value<Fp>,
    pub mock_zero: Value<Fp>,
}

impl<Fp: FieldExt, const TX_NUM: usize> ZkProverCircuit<Fp, TX_NUM> {
    // Constructs a new ZkProverCircuit
    pub fn new(
        start_mpt_root_hash: Hash,
        end_mpt_root_hash: Hash,
        txs: Vec<Transaction>,
        chain_id: u64,
    ) -> Self {
        // let start_mpt_root = start_mpt_root_hash.

        Self {
            mpt_root_before: todo!(),
            mpt_root_after: todo!(),
            txs: todo!(),
            chain_id: todo!(),
            hash_sum_chip: todo!(),
            mock_hashes_element: todo!(),
            mock_hashes_sum: todo!(),
            mock_zero: todo!(),
        }
    }
}

impl<Fp: FieldExt, const TX_NUM: usize> Circuit<Fp> for ZkProverCircuit<Fp, TX_NUM> {
    type Config = ZkProverCircuitConfig<Fp>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // ZkProverCircuitConfig::configure(meta)

        ZkProverCircuitConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx.sign_data().map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", tx);
                    e
                })
            })
            .try_collect()
            .unwrap();

        let hash_sum = self
            .hash_sum_chip
            .constraint_list_sum(
                &mut layouter,
                &config.sum_config,
                &self.mock_hashes_element,
                self.mock_zero,
            )
            .unwrap();

        // start expose public inputs

        // for the Tx hashes Sum
        self.hash_sum_chip
            .expose_public(layouter, &config.sum_config, hash_sum, 0)
            .unwrap();

        // end expose public inputs

        Ok(())
    }
}

pub struct IntergrateCircuit;

impl<E: MultiMillerLoop> TargetCircuit<E> for IntergrateCircuit {
    const TARGET_CIRCUIT_K: u32 = 10;
    const PUBLIC_INPUT_SIZE: usize = 1;
    const N_PROOFS: usize = 2;
    const NAME: &'static str = "zkProver_circuit";
    const PARAMS_NAME: &'static str = "zkProver_circuit";
    const READABLE_VKEY: bool = true;

    type Circuit = ZkProverCircuit<E::Scalar, 128>;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<E::Scalar>>) {
        let circuit = ZkProverCircuit {
            mpt_root_before: todo!(),
            mpt_root_after: todo!(),
            txs: todo!(),
            chain_id: todo!(),
            hash_sum_chip: todo!(),
            mock_hashes_element: todo!(),
            mock_hashes_sum: todo!(),
            mock_zero: todo!(),
        };
        let instances = vec![];
        (circuit, instances)
    }

    fn load_instances(buf: &[u8]) -> Vec<Vec<Vec<E::Scalar>>> {
        vec![vec![]]
    }
}

#[cfg(test)]
mod tests {

    use std::{fs::File, io::Read, marker::PhantomData, path::Path};

    use crate::{
        gadgets::hashes_sum::SumChip,
        test_utils::Fp,
        verifier::{evm_verify, gen_evm_verifier},
    };
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
        halo2curves::{bn256::Bn256, pairing::Engine},
        plonk::keygen_pk,
    };

    use crate::{
        verifier::{
            circuit_deploy::{
                keygen, load_target_circuit_params, load_target_circuit_vk, sample_circuit_setup,
                TargetCircuit,
            },
            gen_proof,
        },
        ERC4337::bundler::BundlerRpcData,
    };

    use super::{IntergrateCircuit, ZkProverCircuit};
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

        let mock_element_list = vec![
            Value::known(Fp::from(1)),
            Value::known(Fp::from(2)),
            Value::known(Fp::from(3)),
            Value::known(Fp::from(4)),
            Value::known(Fp::from(5)),
        ];
        let mock_zero = Value::known(Fp::from(0));
        let mock_hashes_sum = Value::known(Fp::from(15));

        let circuit = ZkProverCircuit::<Fp, TX_NUM> {
            mpt_root_before: Fp::from(0),
            mpt_root_after: Fp::from(0),
            txs: rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect(),
            chain_id: 5u64,
            hash_sum_chip: SumChip {
                _marker: PhantomData::default(),
            },
            mock_hashes_element: mock_element_list,
            mock_hashes_sum,
            mock_zero,
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![vec![Fp::from(15)]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let mut folder = Path::new("output/").to_path_buf();
        let params = load_target_circuit_params::<Bn256, IntergrateCircuit>(&mut folder);
        let vk = load_target_circuit_vk::<Bn256, IntergrateCircuit>(&mut folder, &params);
        let pk = keygen(&params, circuit.clone()).unwrap();
        let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);
        let proof_bytes = gen_proof(&params, &pk, circuit, vec![vec![Fp::from(15)]]);
        evm_verify(deployment_code, vec![vec![Fp::from(15)]], proof_bytes);

        // println!("proof_bytes {:?}", hex::encode(proof_bytes));
    }

    #[test]
    fn test_circuit_setup_data() {
        sample_circuit_setup::<Bn256, IntergrateCircuit>("output/".into());
    }

    #[test]
    fn test_gen_proof() {}
}
