use ethers::solc::resolver::print;
use ethers::types::{Bytes, H256, U256};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use hash_circuit::Bn256Fr;
use std::{path::Path, time::Duration};

use crate::verifier::evm_verify;
use crate::zkprover_circuit::MOCK_RPC_TXS;
use crate::{
    verifier::{
        circuit_deploy::{keygen, load_target_circuit_params, load_target_circuit_vk},
        gen_evm_verifier, gen_proof,
    },
    zkprover_circuit::{IntergrateCircuit, ZkProverCircuit},
    ERC4337::bundler::{BundlerRpcData, BundlerRpcTxData},
};
use reqwest::ClientBuilder;
use reqwest::Error;
use reqwest::{Client, Response};
use serde_json::json;

pub struct BundlerRpcClient {
    base_url: String, // default http:://127.0.0.1:4337
    client: Client,
}

impl BundlerRpcClient {
    pub fn new(base_url: String) -> Self {
        let timeout = Duration::new(5, 0);
        let client = ClientBuilder::new().timeout(timeout).build().unwrap();
        BundlerRpcClient { base_url, client }
    }

    pub fn get_url(&self) -> String {
        let url = self.base_url.clone();
        url
    }

    pub async fn pull_mission(&self) -> Result<Response, Error> {
        let mission_body = json!({
            "jsonrpc": "2.0",
            "method": "zkp_getPoolBatch",
            "params": [

            ],
            "id": 1
        });
        self.client
            .post(self.get_url())
            .json(&mission_body)
            .send()
            .await
    }

    pub async fn push_mission_result(
        &self,
        batch_hash: H256,
        zk_proof: Bytes,
        zk_pub_inputs: Vec<U256>,
    ) -> Result<Response, Error> {
        let mission_body = json!({
            "jsonrpc": "2.0",
            "method": "zkp_sendProofAndPublicInput",
            "params": [
                batch_hash,
                zk_proof,
                zk_pub_inputs
            ],
            "id": 1
        });

        self.client
            .post(self.get_url())
            .json(&mission_body)
            .send()
            .await
    }
}

pub struct Manager {
    params: ParamsKZG<Bn256>,
    proving_key: ProvingKey<G1Affine>,
    verifier_code: Vec<u8>,
    bundler_rpc_client: BundlerRpcClient,
}

impl Manager {
    pub fn new() -> Self {
        let mut folder = Path::new("output/").to_path_buf();
        let params = load_target_circuit_params::<Bn256, IntergrateCircuit>(&mut folder);
        let vk = load_target_circuit_vk::<Bn256, IntergrateCircuit>(&mut folder, &params);
        let zkprover = ZkProverCircuit::<Bn256Fr, 1>::random();

        let pk = keygen(&params, zkprover).unwrap();
        let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);
        let rpc_client = BundlerRpcClient::new("http://127.0.0.1:4337".to_owned());
        Manager {
            params,
            proving_key: pk,
            verifier_code: deployment_code,
            bundler_rpc_client: rpc_client,
        }
    }

    pub async fn execute_mission(&self) -> Result<(), Error> {
        let mission = self.bundler_rpc_client.pull_mission().await;
        let bundler_rpc_data = match mission {
            Ok(m) => m,
            Err(e) => {
                eprintln!("rpc bundler Error : {}", e);
                return Err(e);
            }
        };
        let bundler_rpc_data: BundlerRpcData = bundler_rpc_data.json().await.unwrap();
        // let bundler_rpc_data = MOCK_RPC_TXS.clone();
        let result = bundler_rpc_data.result;
        let task_id = bundler_rpc_data.id;
        let result_data = match result {
            Some(result) => result,
            _ => {
                println!("no mission");
                return Ok(());
            }
        };
        let batch_hash = result_data.batch_hash;
        let tx_list = result_data.tx_list;
        let status = result_data.status;

        let (proof, instances) = self.generate_proof(&tx_list).unwrap();

        let instances_vec = instances.into_iter().flatten().collect::<Vec<Fp>>();

        let instances_u256: Vec<U256> = instances_vec
            .iter()
            .map(|x| U256::from(x.to_bytes()))
            .collect();

        let push_result = self
            .bundler_rpc_client
            .push_mission_result(batch_hash, Bytes::from(proof), instances_u256)
            .await;
        let push_result_data = match push_result {
            Ok(result) => result,
            Err(e) => {
                println!("push result error: {}", e);
                return Err(e);
            }
        };
        println!(
            "push task_id {:?} batch_hash{:?} result success",
            task_id, batch_hash
        );

        // let push_result = hex::encode(push_result_data.bytes().await.unwrap());
        // println!("push_result_data {:?}", push_result);

        Ok(())
    }

    pub fn generate_proof(
        &self,
        tx_list: &Vec<BundlerRpcTxData>,
    ) -> Result<(Vec<u8>, Vec<Vec<Fp>>), Error> {
        let circuit = ZkProverCircuit::<Fp, 1>::default();
        let instances = vec![vec![Fp::from(15)]];

        let proof_bytes = gen_proof(&self.params, &self.proving_key, circuit, instances.clone());
        // santiy check
        evm_verify(
            self.verifier_code.clone(),
            instances.clone(),
            proof_bytes.clone(),
        );

        Ok((proof_bytes, instances))
    }
}
