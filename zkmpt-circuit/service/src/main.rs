use std::fmt::Error;
use std::{env};
use std::time::Duration;
use rocksdb::{OptimisticTransactionDB, DBVector};
use tokio::{task, time};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sparse_merkle_tree::{
    SparseMerkleTree, H256,
    blake2b::Blake2bHasher,
    traits::Value,
};
use zkprover_mpt_circuits::smt_rocksdb_store::default_store::DefaultStore;


/// pull the mission from bundler rpc service
pub async fn pull_bundler_mission() {
    println!("do sth");
}

/// push zkp result to the bundler rpc service
pub async fn push_zkp_result() {
    println!("push zkp result");
}

/// cargo run --package zkprover-mpt-circuits --bin service -- /tmp/smt-store-dir
#[tokio::main]
pub async fn main() {
    let args: Vec<String> = env::args().collect();
    let db_path = args.get(1).expect("args db_path not found");
    println!("db_path {:?}", db_path);
    // futures::future::pending().await

    let forever = task::spawn(async {
        let mut interval = time::interval(Duration::from_millis(3000));

        loop {
            interval.tick().await;
            pull_bundler_mission().await;
        }
    });

    forever.await;
}
