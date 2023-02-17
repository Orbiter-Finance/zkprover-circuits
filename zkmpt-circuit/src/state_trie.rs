use std::hash::{self, Hash};

use halo2_proofs::{
    arithmetic::{FieldExt, Field},
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, VirtualCells}, dev::metadata::VirtualCell, poly::Rotation,
};

use crate::operation::AccountOp;
use hash_circuit::{
    hash::Hashable, hash::PoseidonHashChip, hash::PoseidonHashConfig, hash::PoseidonHashTable,
};

/// StateTrie
#[derive(Clone, Default, Debug)]
pub struct StateTrieCircuit<F: FieldExt> {
    /// the maxium records in circuits (would affect vk)
    pub calcus: usize,
    /// the user Tx operations in circuits
    pub ops: Vec<AccountOp<F>>,
}

/// poseidon hash circuit
pub struct HashCircuit<F: Hashable>(PoseidonHashTable<F>, usize);

impl<Fp: Hashable> HashCircuit<Fp> {
    /// re-warped, all-in-one creation
    pub fn new(calcs: usize, input_with_check: &[&(Fp, Fp, Fp)]) -> Self {
        let mut tbl = PoseidonHashTable::default();
        tbl.constant_inputs_with_check(input_with_check.iter().copied());
        Self(tbl, calcs)
    }
}

impl<Fp: Hashable> Circuit<Fp> for HashCircuit<Fp> {
    type Config = PoseidonHashConfig<Fp>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(Default::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        PoseidonHashConfig::configure_sub(meta, hash_tbl, hash_circuit::DEFAULT_STEP)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = PoseidonHashChip::<Fp, { hash_circuit::DEFAULT_STEP }>::construct(
            config, &self.0, self.1, true, None,
        );
        chip.load(&mut layouter)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HashTable(pub [Column<Advice>; 5]);

impl HashTable {
    pub fn configure_create<Fp: Field>(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self([0; 5].map(|_| meta.advice_column()))
    }

    pub fn configrue_assign(cols: &[Column<Advice>]) -> Self {
        Self([cols[0], cols[1], cols[2], cols[3], cols[4]])
    }

    pub fn commitment_index() {}

    pub fn build_lookup<Fp: FieldExt>(
        &self,
        meta: &mut VirtualCells<'_, Fp>,
        enable: Expression<Fp>,
        fst: Expression<Fp>,
        snd: Expression<Fp>,
        hash: Expression<Fp>,
    ) -> Vec<(Expression<Fp>, Expression<Fp>)> {
        vec![
            (
                enable.clone() * hash,
                meta.query_advice(self.0[0], Rotation::cur()), 
            ),
            (
                enable.clone() * fst,
                meta.query_advice(self.0[1], Rotation::cur()),
            ),
            (
                enable.clone() * snd,
                meta.query_advice(self.0[2], Rotation::cur()),
            ),
            (
                enable * Expression::Constant(Fp::zero()),
                meta.query_advice(self.0[3], Rotation::cur()),
            )
        ]
    }
}

/// test
#[cfg(test)]
mod tests {

    use std::hash::Hash;

    use crate::{
        state_trie::HashCircuit,
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
