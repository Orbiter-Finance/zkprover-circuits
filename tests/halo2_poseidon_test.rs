use std::{marker::PhantomData, vec};

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{
        group::ff::PrimeField,
        pasta::{pallas, vesta, EqAffine, Fp},
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error,
    },
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
}

struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
where
    S: Spec<Fp, WIDTH, RATE> + Clone + Copy,
{
    message: Value<[Fp; L]>,
    // For the purpose of this test, witness the result.
    // TODO: Move this into an instance column.
    output: Value<Fp>,
    _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    input: [Column<Advice>; L],
    poseidon_config: Pow5Config<Fp, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for HashCircuit<S, WIDTH, RATE, L>
where
    S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
{
    type Config = MyConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        Self::Config {
            input: state[..RATE].try_into().unwrap(),
            poseidon_config: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_var =
                    region.assign_advice(|| "load output", config.input[0], 0, || self.output)?;
                region.constrain_equal(output.cell(), expected_var.cell())
            },
        )
    }
}

#[test]
fn halo2_poseidon_test() {
    const K: u32 = 6;
    const WIDTH: usize = 5;
    const RATE: usize = 4;

    // Initialize the polynomial commitment parameters
    let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(K);

    let empty_circuit = HashCircuit::<MySpec<WIDTH, RATE>, WIDTH, RATE, RATE> {
        message: Value::unknown(),
        output: Value::unknown(),
        _spec: PhantomData,
    };

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let mut rng = OsRng;
    // let message: [Fp; RATE] = [1, 2].map(|i|
    // pallas::Base::from(i)).try_into().unwrap();
    let message: [Fp; RATE] = [
        pallas::Base::from(1),
        pallas::Base::from_str_vartime("2").unwrap(),
        pallas::Base::from(2),
        pallas::Base::from(0),
    ];
    let output =
        poseidon::Hash::<_, MySpec<WIDTH, RATE>, ConstantLength<RATE>, WIDTH, RATE>::init()
            .hash(message);

    let circuit = HashCircuit::<MySpec<WIDTH, RATE>, WIDTH, RATE, RATE> {
        message: Value::known(message),
        output: Value::known(output),
        _spec: PhantomData,
    };

    use plotters::prelude::*;
    let root = SVGBackend::new("halo2_poseidon_test—layout.svg", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root1 = root
        .titled("halo2_poseidon_test-layout", ("sans—serif", 60))
        .unwrap();
    halo2_proofs::dev::CircuitLayout::default()
        .show_equality_constraints(true)
        .render(K, &circuit, &root1)
        .unwrap();

    use chrono::Utc;
    let now = Utc::now().timestamp_millis();

    // Create a proof
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    println!(
        "Create_proof time used: {}",
        Utc::now().timestamp_millis() - now
    );

    let proof = transcript.finalize();

    let strategy = SingleStrategy::new(&params);
    let mut v_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut v_transcript).is_ok());
}
