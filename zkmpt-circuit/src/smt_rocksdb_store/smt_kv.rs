use super::default_store::DefaultStore;
use rocksdb::{DBVector, OptimisticTransactionDB};
use rustc_hex::ToHex;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sparse_merkle_tree::default_store;
use sparse_merkle_tree::{blake2b::Blake2bHasher, traits::Value, SparseMerkleTree, H256};
use std::fmt::Error;

#[serde_as]
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SmtRoot(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

impl SmtRoot {
    pub fn to_hex(&self) -> String {
        let hex_str: String = self.0.to_hex();
        hex_str
    }
}
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

type DefaultStoreSMT<'a, T, W> = SparseMerkleTree<Blake2bHasher, SmtValue, DefaultStore<'a, T, W>>;

pub struct SmtKV {
    db: OptimisticTransactionDB,
}

/// SMT KV: Sparse Binanry Merkle Tree + RocksDB
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
    use rustc_hex::ToHex;

    use super::{SmtKV, SmtKey, SmtRoot, SmtValue};

    #[test]
    fn test_smtkv() {
        let db = OptimisticTransactionDB::open_default("/tmp/rocskdb/").unwrap();
        let smt = SmtKV::new(db);
        let test_kv_data: Vec<(SmtKey, SmtValue)> = vec![
            (
                SmtKey(hex!(
                    "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
                )),
                SmtValue(hex!(
                    "a939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82"
                )),
            ),
            // (
            //     SmtKey(hex!(
            //         "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            //     )),
            //     SmtValue(hex!(
            //         "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2b"
            //     )),
            // )
        ];
        let smt_root = smt.update_all(test_kv_data).unwrap();

        println!("smt_root {:}", smt_root.to_hex());
        assert_eq!(
            smt_root,
            SmtRoot(hex!(
                "3ec3865db0f76a135283a908e5b2847164c3bc732ce3ad89e917de45c6d72ac9"
            ))
        );
        let proof = smt
            .merkle_proof(vec![SmtKey(hex!(
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            ))])
            .unwrap();
        println!("proof {:?}", proof);
    }
}
