// use rocksdb::{DBVector, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
// use sparse_merkle_tree::{blake2b::Blake2bHasher, traits::Value,
// SparseMerkleTree, H256};
use dotenv::dotenv;
use std::time::Duration;
use tokio::{task, time};
use zkprover_mpt_circuits::{
    manager::Manager,
    // smt_rocksdb_store::default_store::DefaultStore,
    ERC4337::bundler::BundlerRpcData,
};

/*
cargo run --package zkprover-mpt-circuits --bin service 
 */
#[tokio::main]
pub async fn main() {
    dotenv().ok();
    let setup_path = std::env::var("SETUP_PATH").unwrap_or(String::from("/data/setup/"));
    let db_path = std::env::var("ROCKS_DP_PATH").unwrap_or(String::from("/data/rocksdb/"));
    let rpc_url = std::env::var("BUNDLER_RPC_URL").unwrap_or(String::from("http://bundler:4337"));
    println!("SETUP_PATH {:?}", setup_path);
    println!("DB_PATH {:?}", db_path);

    let mut manager = Manager::new(setup_path.to_string(), rpc_url.to_string());

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
