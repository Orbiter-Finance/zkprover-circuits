use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverGWC,
        },
    },
    transcript::TranscriptWriterBuffer,
};
use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::{
    loader::evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::rc::Rc;

use bytes::Bytes;
use std::fs::File;
use std::io::prelude::*;

pub mod circuit_deploy;
mod halo2_verify;
/// Halo2 loader
pub mod loader;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

// Generate Proof
pub fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    proof
}

pub fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();
    // print!("yul code: {:}", &loader.yul_code());

    let mut file = File::create("zkpVerifier.yul").unwrap();
    file.write_all(&loader.yul_code().as_bytes()).unwrap();
    // let file = File::create("t").unwrap();
    // file.write(file.to).unwrap();

    evm::compile_yul(&loader.yul_code())
}

pub fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    println!("proof calldata: {:?}", calldata);
    let mut evm = ExecutorBuilder::default()
        .with_gas_limit(u64::MAX.into())
        .build();

    let deployment_code_bytes: Bytes = deployment_code.into();
    // println!("deployment_code_bytes {:?}", &deployment_code_bytes);

    let caller = Address::from_low_u64_be(0xfe);
    let deployment_result = evm.deploy(caller, deployment_code_bytes, 0.into());
    dbg!(deployment_result.exit_reason);

    let verifier_address = deployment_result.address.unwrap();
    // println!("calldata {:?}", &calldata);
    // println!("calldata string {:?}",
    // String::from_utf8(calldata.clone()).unwrap());
    let calldata_bytes: Bytes = calldata.into();
    // println!("calldata BytesLike {:?}", &calldata_bytes);

    let result = evm.call_raw(caller, verifier_address, calldata_bytes, 0.into());

    dbg!(result.gas_used);
    dbg!(result.reverted);
    dbg!(result.exit_reason);

    let success = !result.reverted;
    assert!(success);
}
