use halo2_proofs::{
    halo2curves::pairing::{Engine, MultiMillerLoop},
    halo2curves::serde::SerdeObject,
    plonk::{Circuit, keygen_vk}, poly::{kzg::commitment::ParamsKZG, commitment::Params}, SerdeFormat,
};

use rand::{rngs::OsRng, RngCore};

use std::fmt::Debug;
use std::io::Write;


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



