use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone)]
pub struct Number<F: FieldExt>(AssignedCell<F, F>);

// Config that contains the columns used in the circuit
#[derive(Debug, Clone)]
pub struct SumConfig {
    pre_sum: Column<Advice>,
    element: Column<Advice>,
    post_sum: Column<Advice>,
    sum: Column<Instance>,
    s: Selector,
}

// The chip that configures the gate and fills in the witness
#[derive(Debug, Clone)]
pub struct SumChip<F: FieldExt> {
    config: SumConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> SumChip<F> {
    fn construct(config: SumConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> SumConfig {
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
        }
    }

    fn load_first_row(
        &self,
        mut layouter: impl Layouter<F>,
        first_element: Value<F>,
        zero: Value<F>,
    ) -> Result<(Number<F>, Number<F>, Number<F>), Error> {
        // load first row
        layouter.assign_region(
            || "first row",
            |mut region| {
                // enable the selector
                self.config.s.enable(&mut region, 0)?;

                let first_pre_sum = region
                    .assign_advice(|| "first_pre_sum", self.config.pre_sum, 0, || zero)
                    .map(Number)?;

                let first_element_num = region
                    .assign_advice(|| "first_element", self.config.element, 0, || first_element)
                    .map(Number)?;
                let first_post_sum = region
                    .assign_advice(
                        || "first_post_sum",
                        self.config.post_sum,
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
        post_sum_num_ref: &Number<F>,
        element: Value<F>,
    ) -> Result<Number<F>, Error> {
        layouter.assign_region(
            || "row",
            |mut region| {
                // enable the selector
                self.config.s.enable(&mut region, 0)?;

                // copy the cell from previous row

                post_sum_num_ref.0.copy_advice(
                    || "pre_sum",
                    &mut region,
                    self.config.pre_sum,
                    0,
                )?;

                let element_num = region
                    .assign_advice(|| "element", self.config.element, 0, || element)
                    .map(Number)?;

                let element_num_ref = &element_num;

                let post_sum_num = region
                    .assign_advice(
                        || "sum_acc",
                        self.config.post_sum,
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

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Number<F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(num.0.cell(), self.config.sum, row)
    }

    pub fn constraint_list_sum(
        &self,
        mut layouter: impl Layouter<F>,
        element_list: &Vec<Value<F>>,
        zero: Value<F>,
    ) -> Result<(), Error> {
        let (_, _, mut post_sum) =
            self.load_first_row(layouter.namespace(|| "first row"), element_list[0], zero)?;
        for i in 1..element_list.len() {
            let new_sum_acc =
                self.load_row(layouter.namespace(|| "row"), &post_sum, element_list[i])?;
            post_sum = new_sum_acc;
        }
        self.expose_public(layouter.namespace(|| "expose sum"), post_sum, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::circuit_dot_graph;
    use halo2_proofs::halo2curves::FieldExt;
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

    impl<F: FieldExt> Circuit<F> for SumCircuit<F> {
        type Config = SumConfig;
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
            layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = SumChip::construct(config);
            chip.constraint_list_sum(layouter, &self.element_list, self.zero)
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
