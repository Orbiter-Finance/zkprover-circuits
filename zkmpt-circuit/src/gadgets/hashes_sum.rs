use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation
};

use eth_types::Field;

#[derive(Clone)]
pub struct Number<F: Field>(AssignedCell<F, F>);

// Config that contains the columns used in the circuit
#[derive(Debug, Clone)]
pub struct SumConfig<F: Field> {
    pre_sum: Column<Advice>,
    element: Column<Advice>,
    post_sum: Column<Advice>,
    sum: Column<Instance>,
    s: Selector,
    _marker: PhantomData<F>,
}

// The chip that configures the gate and fills in the witness
#[derive(Debug, Clone)]
pub struct SumChip<F: Field> {
    pub _marker: PhantomData<F>,
}

impl<F: Field> Default for SumChip<F> {
    fn default() -> Self {
        Self {
            _marker: PhantomData::default(),
        }
    }
}

impl<F: Field> SumChip<F> {
    fn construct() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> SumConfig<F> {
        // create columns
        let pre_sum = meta.advice_column();
        let element = meta.advice_column();
        let post_sum = meta.advice_column();
        let sum = meta.instance_column();
        let s = meta.selector();

        // enable permutation checks for the following columns
        meta.enable_equality(pre_sum);
        meta.enable_equality(element);
        meta.enable_equality(post_sum);
        meta.enable_equality(sum);

        // define the custom gate
        meta.create_gate("gate sum acc", |meta| {
            let s = meta.query_selector(s);
            let lhs = meta.query_advice(pre_sum, Rotation::cur());
            let rhs = meta.query_advice(element, Rotation::cur());
            let out = meta.query_advice(post_sum, Rotation::cur());
            vec![s * (lhs + rhs - out)]
            // vec![s * Expression::Constant(F::from(0))]
        });

        SumConfig {
            pre_sum,
            element,
            post_sum,
            sum,
            s,
            _marker: PhantomData,
        }
    }

    fn load_first_row(
        &self,
        mut layouter: impl Layouter<F>,
        config: &SumConfig<F>,
        first_element: Value<F>,
        zero: Value<F>,
    ) -> Result<(Number<F>, Number<F>, Number<F>), Error> {
        // load first row
        layouter.assign_region(
            || "first row",
            |mut region| {
                // enable the selector
                config.s.enable(&mut region, 0)?;

                let first_pre_sum = region
                    .assign_advice(|| "first_pre_sum", config.pre_sum, 0, || zero)
                    .map(Number)?;

                let first_element_num = region
                    .assign_advice(|| "first_element", config.element, 0, || first_element)
                    .map(Number)?;
                let first_post_sum = region
                    .assign_advice(
                        || "first_post_sum",
                        config.post_sum,
                        0,
                        || zero + first_element,
                    )
                    .map(Number)?;

                Ok((first_pre_sum, first_element_num, first_post_sum))
            },
        )
    }

    fn load_row(
        &self,
        mut layouter: impl Layouter<F>,
        config: &SumConfig<F>,
        post_sum_num_ref: &Number<F>,
        element: Value<F>,
    ) -> Result<Number<F>, Error> {
        layouter.assign_region(
            || "row",
            |mut region| {
                // enable the selector
                config.s.enable(&mut region, 0)?;

                // copy the cell from previous row

                post_sum_num_ref
                    .0
                    .copy_advice(|| "pre_sum", &mut region, config.pre_sum, 0)?;

                let element_num = region
                    .assign_advice(|| "element", config.element, 0, || element)
                    .map(Number)?;

                let element_num_ref = &element_num;

                let post_sum_num = region
                    .assign_advice(
                        || "sum_acc",
                        config.post_sum,
                        0,
                        || {
                            (post_sum_num_ref.0.value().and_then(|post_sum_num_ref| {
                                element_num_ref
                                    .0
                                    .value()
                                    .map(|element_num_ref| *post_sum_num_ref + *element_num_ref)
                            }))
                        },
                    )
                    .map(Number)?;

                Ok(post_sum_num)
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        config: &SumConfig<F>,
        num: Number<F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(num.0.cell(), config.sum, row)
    }

    pub fn constraint_list_sum(
        &self,
        layouter: &mut impl Layouter<F>,
        config: &SumConfig<F>,
        element_list: &Vec<Value<F>>,
        zero: Value<F>,
    ) -> Result<Number<F>, Error> {
        let (_, _, mut post_sum) = self.load_first_row(
            layouter.namespace(|| "first row"),
            config,
            element_list[0],
            zero,
        )?;
        for i in 1..element_list.len() {
            let new_sum_acc = self.load_row(
                layouter.namespace(|| "row"),
                config,
                &post_sum,
                element_list[i],
            )?;
            post_sum = new_sum_acc;
        }
        // self.expose_public(layouter.namespace(|| "expose sum"), config, post_sum,
        // 0)?;
        Ok(post_sum)
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::circuit_dot_graph;
    use eth_types::Field;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::bn256::Fr as Fp};
    use num::Zero;
    use num_bigint::BigUint;

    use super::{SumChip, SumConfig};

    fn get_hashes_sum(hashes_num: Vec<BigUint>) -> BigUint {
        let mut sum = BigUint::zero();
        for i in hashes_num {
            sum = sum + i
        }
        sum
    }

    #[derive(Default)]
    struct SumCircuit<F> {
        element_list: Vec<Value<F>>,
        zero: Value<F>,
        // public_sum: Value<F>,
    }

    impl<F: Field> Circuit<F> for SumCircuit<F> {
        type Config = SumConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            SumChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = SumChip::construct();
            let post_sum = chip
                .constraint_list_sum(&mut layouter, &config, &self.element_list, self.zero)
                .unwrap();

            chip.expose_public(layouter.namespace(|| "expose sum"), &config, post_sum, 0)
        }
    }

    #[test]
    fn test_sum_hashes() {
        // Instantiate the circuit with the private inputs.
        let circuit = SumCircuit {
            element_list: vec![
                Value::known(Fp::from(1)),
                Value::known(Fp::from(2)),
                Value::known(Fp::from(3)),
                Value::known(Fp::from(4)),
                Value::known(Fp::from(5)),
            ],
            zero: Value::known(Fp::zero()),
        };

        // Arrange the public input. We expose the multiplication result in row 0
        // of the instance column, so we position it there in our public inputs.
        let mut public_inputs = vec![Fp::from(15)];

        // Set circuit size
        let k = 4;

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // If we try some other public input, the proof will fail!
        public_inputs = vec![Fp::from(14)];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }
}
