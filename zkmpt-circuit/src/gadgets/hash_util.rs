use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use hash_circuit::hash::{Hashable, PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};

/// a companied hash circuit as the companion of mpt hashes
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
            config,
            &self.0,
            self.1,
            false,
            Some(Fp::from(42u64)),
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

    pub fn configure_assign(cols: &[Column<Advice>]) -> Self {
        Self([cols[0], cols[1], cols[2], cols[3], cols[4]])
    }

    pub fn commitment_index(&self) -> [usize; 5] {
        self.0.map(|col| col.index())
    }

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
            ),
            // TODO: also lookup from `self.0[4]` after https://github.com/scroll-tech/mpt-circuit/issues/9
            // has been resolved
        ]
    }

    /// a helper entry to fill hash table with specified rows, use padding
    /// record when hashing_records is not enough
    pub fn dev_fill_with_paddings<'d, Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hashing_records: impl Iterator<Item = &'d (Fp, Fp, Fp)> + Clone,
        padding: (Fp, Fp, Fp),
        filled_rows: usize,
    ) -> Result<(), Error> {
        self.dev_fill(
            layouter,
            hashing_records
                .map(|i| i) //shrink the lifetime from 'd
                .chain(std::iter::repeat(&padding))
                .take(filled_rows),
        )
    }

    /// a helper entry to fill hash table, only for dev (in using cases)
    pub fn dev_fill<'d, Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        hashing_records: impl Iterator<Item = &'d (Fp, Fp, Fp)> + Clone,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "hash table",
            |mut table| {
                // default: 0, 0, 0
                for col in self.0 {
                    table.assign_advice(|| "default", col, 0, || Value::known(Fp::zero()))?;
                }

                hashing_records
                    .clone()
                    .enumerate()
                    .try_for_each(|(offset, val)| {
                        let (lh, rh, h) = val;
                        let offset = offset + 1;

                        table.assign_advice(|| "result", self.0[0], offset, || Value::known(*h))?;

                        table.assign_advice(|| "left", self.0[1], offset, || Value::known(*lh))?;

                        table.assign_advice(|| "right", self.0[2], offset, || Value::known(*rh))?;

                        table.assign_advice(
                            || "ctrl_pad",
                            self.0[3],
                            offset,
                            || Value::known(Fp::zero()),
                        )?;

                        table.assign_advice(
                            || "heading mark",
                            self.0[4],
                            offset,
                            || Value::known(Fp::one()),
                        )?;

                        Ok(())
                    })
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use crate::{gadgets::hash_util::HashCircuit, test_utils::{Fp, rand_fp}};

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error}, halo2curves::group::ff::PrimeField,
    };
    use hash_circuit::{
        hash::{PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable},
        Hashable, DEFAULT_STEP,
    };
    use rand::rngs::OsRng;

    struct TestCircuit(PoseidonHashTable<Fp>, usize);
    // test circuit derived from table data
    impl Circuit<Fp> for TestCircuit {
        type Config = PoseidonHashConfig<Fp>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self(PoseidonHashTable::default(), self.1)
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let hash_tbl = [0; 5].map(|_| meta.advice_column());
            PoseidonHashConfig::configure_sub(meta, hash_tbl, DEFAULT_STEP)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = PoseidonHashChip::<Fp, DEFAULT_STEP>::construct(
                config,
                &self.0,
                self.1,
                false,
                Some(Fp::from(42u64)),
            );
            chip.load(&mut layouter)
        }
    }

    #[test]
    fn test_hash_circuit_degree() {
        // let mut cs: ConstraintSystem<Fp> = Default::default();
        // HashCircuit::configure(&mut cs);

        // println!("hash circuit degree: {}", cs.degree());
        // assert!(cs.degree() <= 9);
    }

    #[test]
    fn test_hash_circuit_with_check() {
        let k = 7;
        let m1: Fp = Fp::from_str_vartime("9").unwrap();
        let m2: Fp = Fp::from_str_vartime("2").unwrap();

        // let m1 = Fp::zero();
        // let m2 = Fp::zero();
        let hash_rows = 1;

        let hash_result = <Fp as Hashable>::hash([m1, m2]);
        println!("m1 {m1:?} m2 {m2:?} hash_result {hash_result:?}");
        let hashes = &[&(m1, m2, hash_result)];
        let hash_circuit = HashCircuit::new(hash_rows, hashes);
        let prover_hash = MockProver::<Fp>::run(k, &hash_circuit, vec![]).unwrap();

        assert_eq!(prover_hash.verify(), Ok(()));
    }

    #[test]
    fn test_hash_circuit_without_check() {
        let message1 = [
            Fp::from_str_vartime("1").unwrap(),
            Fp::from_str_vartime("2").unwrap(),
        ];
        let message2 = [
            Fp::from_str_vartime("0").unwrap(),
            Fp::from_str_vartime("1").unwrap(),
        ];

        let k = 7;
        let circuit = TestCircuit(
            PoseidonHashTable {
                inputs: vec![message1, message2],
                ..Default::default()
            },
            3,
        );
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }



}
