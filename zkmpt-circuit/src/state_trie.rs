use std::hash::{self, Hash};

use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner, Table},
    dev::metadata::VirtualCell,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::{
    gadgets::{
        account::AccountGadget,
        hash_util,
        layer::LayerGadget,
        table_util::{self, MPTProofType},
    },
    operation::{Account, AccountOp, HashTracesSrc},
};
use hash_circuit::{
    hash::Hashable, hash::PoseidonHashChip, hash::PoseidonHashConfig, hash::PoseidonHashTable,
};

use lazy_static::lazy_static;
use std::sync::Mutex;
lazy_static! {
    static ref RAND_BASE: Mutex<Vec<u64>> = Mutex::new(vec![0x10000u64]);
}

fn get_rand_base() -> u64 {
    *RAND_BASE
        .lock()
        .unwrap()
        .last()
        .expect("always has init element")
}

#[derive(Clone, Default)]
pub struct StateTrie<Fp: FieldExt> {
    start_root: Fp,
    final_root: Fp,
    ops: Vec<AccountOp<Fp>>,
}

const OP_TRIE_ACCOUNT: u32 = 1;
const OP_TRIE_STATE: u32 = 2;
const OP_ACCOUNT: u32 = 3;
const OP_STORAGE: u32 = 4;

impl<Fp: FieldExt> StateTrie<Fp> {
    /// Obtain the wrapped operation sequence
    pub fn get_ops(&self) -> &[AccountOp<Fp>] {
        &self.ops
    }

    /// Add an op into the circuit data
    pub fn add_op(&mut self, op: AccountOp<Fp>) {
        if self.ops.is_empty() {
            self.start_root = op.account_root_before()
        } else {
            assert_eq!(self.final_root, op.account_root_before());
        }
        self.final_root = op.account_root_after();
        self.ops.push(op)
    }

    /// Add an op array
    pub fn add_ops(&mut self, ops: impl IntoIterator<Item = AccountOp<Fp>>) {
        for op in ops {
            self.add_op(op)
        }
    }

    /// Obtain the final root
    pub fn final_root(&self) -> Fp {
        self.final_root
    }

    pub fn circuits(self, rows: usize, tips: &[MPTProofType]) -> StateTrieCircuit<Fp> {
        StateTrieCircuit::new(rows, self.ops, Vec::from(tips))
    }
}

impl<Fp: Hashable> StateTrie<Fp> {
    // pub fn hash_traces(&self) -> impl Iteratro<Item = &(Fp, Fp, Fp) + Clone {
    //     HashTracesSrc::from(self.ops.iter().flat_map(|op| op.hash_traces()))
    // }
}

#[derive(Clone, Debug)]
pub struct StateTrieConfig {
    layer: LayerGadget,
    account: AccountGadget,
    tables: table_util::MPTOpTables,
    hash_tbl: hash_util::HashTable,
}

impl StateTrieConfig {
    /// configure for lite circuit (no mpt table included, for fast testing)
    pub fn configure_base<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        hash_tbl: [Column<Advice>; 5],
    ) -> Self {
        let tables = table_util::MPTOpTables::configure_create(meta);
        let hash_tbl = hash_util::HashTable::configure_assign(&hash_tbl);

        let layer =
            LayerGadget::configure(meta, 5, std::cmp::max(0, AccountGadget::min_free_cols()), 4);

        let account = AccountGadget::configure(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_ACCOUNT).as_slice(),
            layer.get_ctrl_type_flags(),
            layer.get_free_cols(),
            Some(layer.get_address_index()),
            tables.clone(),
            hash_tbl.clone(),
        );
        Self {
            layer,
            account,
            tables,
            hash_tbl,
        }
    }

    pub fn configure_sub<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        mpt_tbl: [Column<Advice>; 7],
        hash_tbl: [Column<Advice>; 5],
        randomness: Expression<Fp>,
    ) -> Self {
        let mut lite_cfg = Self::configure_base(meta, hash_tbl);
        lite_cfg
    }

    pub fn synthesize_core<'d, Fp: Hashable>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        ops: impl Iterator<Item = &'d AccountOp<Fp>> + Clone,
        rows: usize,
    ) -> Result<(), Error> {
        let start_root = ops
            .clone()
            .next()
            .map(|op| op.account_root_before())
            .unwrap_or_else(Fp::zero);
        layouter.assign_region(
            || "main",
            |mut region| {
                let mut series: usize = 1;
                let mut last_op_code = self.layer.start_op_code();
                let mut start = self.layer.assign(&mut region, rows, start_root).unwrap();

                // let empty_account = Default::default();
                for op in ops.clone() {
                    let block_start = start;
                    self.layer
                        .pace_op(
                            &mut region,
                            start,
                            (last_op_code, OP_TRIE_ACCOUNT),
                            op.use_rows_trie_account(),
                        )
                        .unwrap();
                    // start = self.account
                }
                Ok(())
            },
        )
    }
}

/// StateTrie
#[derive(Clone, Default, Debug)]
pub struct StateTrieCircuit<F: FieldExt> {
    /// the maxium records in circuits (would affect vk)
    pub calcs: usize,
    /// the user Tx operations in circuits
    pub ops: Vec<AccountOp<F>>,

    /// the mpt table for operations,
    /// if NONE, circuit work under lite mode
    /// no run-time checking for the consistents between ops and generated mpt
    /// table
    pub mpt_table: Vec<MPTProofType>,
}

impl<Fp: Hashable> StateTrieCircuit<Fp> {
    /// create circuit without mpt table
    pub fn new_lite(calcs: usize, ops: Vec<AccountOp<Fp>>) -> Self {
        Self {
            calcs,
            ops,
            ..Default::default()
        }
    }
}

impl<Fp: FieldExt> StateTrieCircuit<Fp> {
    /// create circuit
    pub fn new(calcs: usize, ops: Vec<AccountOp<Fp>>, mpt_table: Vec<MPTProofType>) -> Self {
        Self {
            calcs,
            ops,
            mpt_table,
        }
    }
}

impl<Fp: Hashable> Circuit<Fp> for StateTrieCircuit<Fp> {
    type Config = StateTrieConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            calcs: self.calcs,
            ops: Vec::new(),
            mpt_table: Vec::new(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        let mpt_tbl = [0; 7].map(|_| meta.advice_column());
        let randomness = Expression::Constant(Fp::from(get_rand_base()));
        StateTrieConfig::configure_sub(meta, mpt_tbl, hash_tbl, randomness)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        todo!()
    }
}

/// test
#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use std::hash::Hash;

    use crate::{
        gadgets::hash_util::HashCircuit,
        test_utils::{hash_str_to_fp, Fp},
    };
    use halo2_proofs::{dev::MockProver, halo2curves::group::ff::PrimeField};
    use hash_circuit::{
        hash::{MessageHashable, PoseidonHashTable},
        Hashable,
    };

    #[test]
    fn test_poseidon_hash_table() {
        let message1 = [
            Fp::from_str_vartime("1").unwrap(),
            Fp::from_str_vartime("2").unwrap(),
        ];

        let message2 = [Fp::from_str_vartime("11111").unwrap(), Fp::zero()];

        let msg = vec![message1, message2];

        let b1: Fp = Fp::from_str_vartime("1").unwrap();
        let b2: Fp = Fp::from_str_vartime("2").unwrap();

        let k = 8;
        let hash_result = <Fp as Hashable>::hash([b1, b2]);
        println!("hash_result {hash_result:?} b1 {b1:?} b2 {b2:?}");
        let hash_rows = 1;

        // let org_circuit = PoseidonHashTable::<Fp> {
        //     inputs: vec![[b1, b2]],
        //     controls: vec![Fp::from(45), Fp::from(13)],
        //     checks: vec![Some(hash_result)],
        // };

        // let prover = MockProver::<Fp>::run(k, &org_circuit, vec![]).unwrap();
        // assert_eq!(prover.verify(), Ok(()));

        let hashes = &[&(b1, b2, hash_result)];
        let hash_circuit = HashCircuit::new(hash_rows, hashes);
        let prover_hash = MockProver::<Fp>::run(k, &hash_circuit, vec![]).unwrap();

        // assert_eq!(prover_hash.verify(), Ok(()));
    }
}
