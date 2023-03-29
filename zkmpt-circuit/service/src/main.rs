use rocksdb::{DBVector, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sparse_merkle_tree::{blake2b::Blake2bHasher, traits::Value, SparseMerkleTree, H256};
use std::time::Duration;
use tokio::{task, time};
use zkprover_mpt_circuits::{
    manager::Manager, smt_rocksdb_store::default_store::DefaultStore,
    ERC4337::bundler::BundlerRpcData,
};

use dotenv::dotenv;
use reqwest::Error;
use std::env;

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

/*
cargo run --package zkprover-mpt-circuits --bin service -- /tmp/smt-store-dir /tmp/zk-setup
 */
#[tokio::main]
pub async fn main() {
    dotenv().ok();
    let setup_path = env::var("SETUP_PATH").unwrap();
    let db_path = env::var("DB_PATH").unwrap();
    // let setup_path = "/data/setup";
    // let db_path = "/data/rocksdb/";
    println!("SETUP_PATH {:?}", setup_path);
    println!("DB_PATH {:?}", db_path);

    let mut manager = Manager::new(setup_path.to_string());

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
