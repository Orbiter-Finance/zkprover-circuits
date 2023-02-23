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

/// test
#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use std::hash::Hash;

    use crate::{
        test_utils::{hash_str_to_fp, Fp}, gadgets::hash_util::HashCircuit,
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

        assert_eq!(prover_hash.verify(), Ok(()));
    }
}
