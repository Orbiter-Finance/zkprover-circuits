use rocksdb::{DBVector, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sparse_merkle_tree::{blake2b::Blake2bHasher, traits::Value, SparseMerkleTree, H256};
use std::env;
use std::time::Duration;
use tokio::{task, time};
use zkprover_mpt_circuits::{
    manager::Manager, smt_rocksdb_store::default_store::DefaultStore,
    ERC4337::bundler::BundlerRpcData,
};

use reqwest::Error;

/// pull the mission from bundler rpc service
pub async fn pull_bundler_mission() {
    println!("do sth");

    // url : http:://127.0.0.1:4337/zkp_getPoolBatch
    // let request_url = format!("http:://127.0.0.1:4337/{uri}", uri =
    // "zkp_getPoolBatch"); let response =
    // reqwest::get(&request_url).await.unwrap(); let mission_result:
    // BundlerRpcData = response.json().await.unwrap(); Ok(mission_result)
}

/// push zkp result to the bundler rpc service
pub async fn push_zkp_result(task_id: u64) {
    println!("push zkp result");
}

/// cargo run --package zkprover-mpt-circuits --bin service --
/// /tmp/smt-store-dir
#[tokio::main]
pub async fn main() {
    let args: Vec<String> = env::args().collect();
    let db_path = args.get(1).expect("args db_path not found");
    println!("db_path {:?}", db_path);
    // futures::future::pending().await

    let mut manager = Manager::new();

    let forever = task::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(3000));

        loop {
            interval.tick().await;
            // pull_bundler_mission().await;
            manager.execute_mission().await;
        }
    });

    forever.await;
}
