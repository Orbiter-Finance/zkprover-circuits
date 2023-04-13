use halo2_proofs::{
    halo2curves::pairing::{Engine, MultiMillerLoop},
    halo2curves::{serde::SerdeObject, bn256::Bn256},
    plonk::{keygen_pk, keygen_vk, Circuit, Error, ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};

use hash_circuit::Bn256Fr;
use rand::{rngs::OsRng, RngCore};

use std::{
    fmt::Debug,
    io::{Cursor, Read},
    path::PathBuf,
};

use crate::zkprover_circuit::ZkProverCircuit;

pub fn init_trusted_setup(
    circuit_k: u32, 
    circuit_name: &str,
    mut folder: std::path::PathBuf,
) 
{
    let params = ParamsKZG::<Bn256>::setup(circuit_k, OsRng);
    let zkprover_circuit_instance = ZkProverCircuit::<Bn256Fr, 128>::random();

    let vk = keygen_vk(&params, &zkprover_circuit_instance).expect("keygen_vk should not fail");

    {
        folder.push(format!("sample_circuit_{}.params", &circuit_name));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        params.write(&mut fd).unwrap();
    }

    {
        folder.push(format!("sample_circuit_{}.vkey", &circuit_name));
        let mut fd = std::fs::File::create(folder.as_path()).unwrap();
        folder.pop();
        vk.write(&mut fd, SerdeFormat::Processed).unwrap();
    }
}

/// Ported from https://github.com/scroll-tech/halo2-snark-aggregator/blob/main/halo2-snark-aggregator-circuit/src/sample_circuit.rs

pub trait TargetCircuit {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;
    const PARAMS_NAME: &'static str;
    const READABLE_VKEY: bool;
}

/// This is only for test or demo environment!
// pub fn sample_circuit_setup<E: MultiMillerLoop + Debug, CIRCUIT: TargetCircuit<E>>(
//     mut folder: std::path::PathBuf,
// ) where
//     <E as Engine>::G2Affine: SerdeObject,
//     <E as Engine>::G1Affine: SerdeObject,
//     <E as Engine>::Scalar: SerdeObject,
// {
//     // TODO: Do not use setup in production
//     let params = ParamsKZG::<E>::setup(CIRCUIT::TARGET_CIRCUIT_K, OsRng);

//     let circuit = CIRCUIT::Circuit::default();
//     let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

//     {
//         folder.push(format!("sample_circuit_{}.params", CIRCUIT::PARAMS_NAME));
//         let mut fd = std::fs::File::create(folder.as_path()).unwrap();
//         folder.pop();
//         params.write(&mut fd).unwrap();
//     }

//     {
//         folder.push(format!("sample_circuit_{}.vkey", CIRCUIT::PARAMS_NAME));
//         let mut fd = std::fs::File::create(folder.as_path()).unwrap();
//         folder.pop();
//         vk.write(&mut fd, SerdeFormat::Processed).unwrap();
//     }
// }

pub fn read_file(folder: &mut PathBuf, filename: &str) -> Vec<u8> {
    let mut buf = vec![];

    folder.push(filename);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn read_target_circuit_params<Circuit: TargetCircuit>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.params", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_params<Circuit: TargetCircuit>(
    folder: &mut PathBuf,
) -> ParamsKZG<Bn256>
{
    ParamsKZG::read(&mut Cursor::new(&read_target_circuit_params::<Circuit>(
        &mut folder.clone(),
    )))
    .unwrap()
}

pub fn read_target_circuit_vk<E: MultiMillerLoop, Circuit: TargetCircuit>(
    folder: &mut PathBuf,
) -> Vec<u8> {
    read_file(
        folder,
        &format!("sample_circuit_{}.vkey", Circuit::PARAMS_NAME),
    )
}

pub fn load_target_circuit_vk< Circuit: TargetCircuit>(
    folder: &mut PathBuf,
    params: &ParamsKZG<Bn256>,
) -> VerifyingKey<<Bn256 as Engine>::G1Affine>
{

    let zkprover_circuit_instance = ZkProverCircuit::<Bn256Fr, 128>::random();
    
    if Circuit::READABLE_VKEY {
        VerifyingKey::<<Bn256 as Engine>::G1Affine>::read::<_, ZkProverCircuit::<Bn256Fr, 128>>(
            &mut Cursor::new(&read_target_circuit_vk::<Bn256, Circuit>(&mut folder.clone())),
            SerdeFormat::Processed,
        )
        .unwrap()
    } else {

        keygen_vk::<<Bn256 as Engine>::G1Affine, _,ZkProverCircuit::<Bn256Fr, 128>>(params, &zkprover_circuit_instance)
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
