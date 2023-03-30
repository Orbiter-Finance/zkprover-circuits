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

/*
cargo run --package zkprover-mpt-circuits --bin service -- /tmp/smt-store-dir /tmp/zk-setup
 */
#[tokio::main]
pub async fn main() {
    let setup_path = "/data/setup/";
    let db_path = "/data/rocksdb/";
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
