use halo2_proofs::{
    halo2curves::pairing::{Engine, MultiMillerLoop},
    halo2curves::serde::SerdeObject,
    plonk::{keygen_pk, keygen_vk, Circuit, Error, ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};

use rand::{rngs::OsRng, RngCore};

use std::{
    fmt::Debug,
    io::{Cursor, Read},
    path::PathBuf,
};

/// Ported from https://github.com/scroll-tech/halo2-snark-aggregator/blob/main/halo2-snark-aggregator-circuit/src/sample_circuit.rs

pub trait TargetCircuit<E: MultiMillerLoop> {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;
    const PARAMS_NAME: &'static str;
    const READABLE_VKEY: bool;

    type Circuit: Circuit<<E as Engine>::Scalar> + Default;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<<E as Engine>::Scalar>>);
    fn load_instances(buf: &[u8]) -> Vec<Vec<Vec<<E as Engine>::Scalar>>>;
}

/// This is only for test or demo environment!
pub fn sample_circuit_setup<E: MultiMillerLoop + Debug, CIRCUIT: TargetCircuit<E>>(
    mut folder: std::path::PathBuf,
) where
    <E as Engine>::G2Affine: SerdeObject,
    <E as Engine>::G1Affine: SerdeObject,
    <E as Engine>::Scalar: SerdeObject,
{
    // TODO: Do not use setup in production
    let params = ParamsKZG::<E>::setup(CIRCUIT::TARGET_CIRCUIT_K, OsRng);

    let circuit = CIRCUIT::Circuit::default();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

    {
        folder.push(format!("sample_circuit_{}.params", CIRCUIT::PARAMS_NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        params.write(&mut fd).unwrap();
    }

    {
        folder.push(format!("sample_circuit_{}.vkey", CIRCUIT::PARAMS_NAME));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        vk.write(&mut fd, SerdeFormat::Processed).unwrap();
    }
}

pub fn read_file(folder: &mut PathBuf, filename: &str) -> Vec<u8> {
    let mut buf = vec![];

    folder.push(filename);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn read_target_circuit_params<E: MultiMillerLoop, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.params", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_params<E: MultiMillerLoop + Debug + Engine, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
) -> ParamsKZG<E>
where
    <E as Engine>::G2Affine: SerdeObject,
    <E as Engine>::G1Affine: SerdeObject,
{
    ParamsKZG::read(&mut Cursor::new(&read_target_circuit_params::<E, Circuit>(
        &mut folder.clone(),
    )))
    .unwrap()
}

pub fn read_target_circuit_vk<E: MultiMillerLoop, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.vkey", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_vk<E: MultiMillerLoop + Debug + Engine, Circuit: TargetCircuit<E>>(
    folder: &mut PathBuf,
    params: &ParamsKZG<E>,
) -> VerifyingKey<E::G1Affine>
where
    <E as Engine>::G2Affine: SerdeObject,
    <E as Engine>::G1Affine: SerdeObject,
    <E as Engine>::Scalar: SerdeObject,
{
    if Circuit::READABLE_VKEY {
        VerifyingKey::<E::G1Affine>::read::<_, Circuit::Circuit>(
            &mut Cursor::new(&read_target_circuit_vk::<E, Circuit>(&mut folder.clone())),
            SerdeFormat::Processed,
        )
        .unwrap()
    } else {
        let circuit = Circuit::Circuit::default();

        keygen_vk::<E::G1Affine, _, Circuit::Circuit>(params, &circuit)
            .expect("keygen_vk should not fail")
    }
}

/// Proving/verifying key generation.
pub fn keygen<E: Engine + Debug, C: Circuit<E::Scalar>>(
    params: &ParamsKZG<E>,
    circuit: C,
) -> Result<ProvingKey<<E as Engine>::G1Affine>, Error>
where
    E::G1Affine: SerdeObject,
    E::G2Affine: SerdeObject,
{
    let vk = keygen_vk::<<E as Engine>::G1Affine, ParamsKZG<E>, _>(params, &circuit)?;
    let pk = keygen_pk::<<E as Engine>::G1Affine, ParamsKZG<E>, _>(params, vk, &circuit)?;

    Ok(pk)
}
