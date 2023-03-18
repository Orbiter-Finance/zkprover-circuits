use super::default_store::DefaultStore;
use rocksdb::{DBVector, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sparse_merkle_tree::default_store;
use sparse_merkle_tree::{blake2b::Blake2bHasher, traits::Value, SparseMerkleTree, H256};
use std::fmt::Error;

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtRoot(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtKey(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtValue(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtProof(#[serde_as(as = "serde_with::hex::Hex")] Vec<u8>);

impl Value for SmtValue {
    fn to_h256(&self) -> H256 {
        self.0.into()
    }

    fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl From<DBVector> for SmtValue {
    fn from(vec: DBVector) -> Self {
        SmtValue(vec.as_ref().try_into().expect("stored value is 32 bytes"))
    }
}

impl AsRef<[u8]> for SmtValue {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub async fn pull_bundler_mission() {
    println!("do sth");
}

type DefaultStoreSMT<'a, T, W> = SparseMerkleTree<Blake2bHasher, SmtValue, DefaultStore<'a, T, W>>;

pub struct SmtKV {
    db: OptimisticTransactionDB,
}

impl SmtKV {
    fn new(db: OptimisticTransactionDB) -> Self {
        Self { db }
    }
    fn update_all(&self, kvs: Vec<(SmtKey, SmtValue)>) -> Result<SmtRoot, Error> {
        let kvs: Vec<(H256, SmtValue)> = kvs.into_iter().map(|(k, v)| (k.0.into(), v)).collect();

        let tx = self.db.transaction_default();
        let mut rocksdb_store_smt =
            DefaultStoreSMT::new_with_store(DefaultStore::new(&tx)).unwrap();
        rocksdb_store_smt.update_all(kvs).expect("update_all error");
        tx.commit().expect("db commit error");
        Ok(SmtRoot(rocksdb_store_smt.root().clone().into()))
    }

    fn merkle_proof(&self, keys: Vec<SmtKey>) -> Result<SmtProof, Error> {
        let keys: Vec<H256> = keys.into_iter().map(|k| k.0.into()).collect();
        let snapshot = self.db.snapshot();
        let rocksdb_store_smt =
            DefaultStoreSMT::new_with_store(DefaultStore::<_, ()>::new(&snapshot)).unwrap();
        let proof = rocksdb_store_smt
            .merkle_proof(keys.clone())
            .expect("merkle_proof error");
        Ok(SmtProof(proof.compile(keys).expect("compile error").0))
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rocksdb::{prelude::Open, OptimisticTransactionDB};

    use crate::smt_rocksdb_store;

    use super::{SmtKV, SmtKey, SmtValue};

    #[test]
    fn test_smtkv() {
        let db = OptimisticTransactionDB::open_default("/tmp/rocskdb/").unwrap();
        let smt = SmtKV::new(db);
        let test_kv_data: Vec<(SmtKey, SmtValue)> = vec![(
            SmtKey(hex!(
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            )),
            SmtValue(hex!(
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            )),
        )];
        smt.update_all(test_kv_data);
        let proof = smt
            .merkle_proof(vec![SmtKey(hex!(
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            ))])
            .unwrap();
        println!("proof {:?}", proof);
    }
}
