use std::marker::PhantomData;

use rocksdb::prelude::*;
use sparse_merkle_tree::{
    error::Error,
    traits::{StoreReadOps, StoreWriteOps, Value},
    BranchKey, BranchNode, H256,
};

use crate::smt_rocksdb_store::smt_serde::{
    branch_key_to_vec, branch_node_to_vec, slice_to_branch_node,
};

/// A SMT `Store` implementation backed by a RocksDB database, using different
/// column families to store the branches and the leaves.
pub struct ColumnFamilyStore<'a, T, W> {
    // The RocksDB database which stores the data, can be a `DB` / `OptimisticTransactionDB` /
    // `Snapshot` etc.
    inner: &'a T,
    branch_col: &'a ColumnFamily,
    leaf_col: &'a ColumnFamily,
    // A generic write options, can be a `WriteOptions` / `()` etc.
    write_options: PhantomData<W>,
}

impl<'a, T, W> ColumnFamilyStore<'a, T, W> {
    pub fn new(db: &'a T, branch_col: &'a ColumnFamily, leaf_col: &'a ColumnFamily) -> Self {
        ColumnFamilyStore {
            inner: db,
            write_options: PhantomData,
            branch_col,
            leaf_col,
        }
    }
}

impl<'a, V, T, W> StoreReadOps<V> for ColumnFamilyStore<'a, T, W>
where
    V: Value + AsRef<[u8]> + From<DBVector>,
    T: GetCF<ReadOptions>,
{
    fn get_branch(&self, branch_key: &BranchKey) -> Result<Option<BranchNode>, Error> {
        self.inner
            .get_cf(self.branch_col, &branch_key_to_vec(branch_key))
            .map(|s| s.map(|v| slice_to_branch_node(&v)))
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn get_leaf(&self, leaf_key: &H256) -> Result<Option<V>, Error> {
        self.inner
            .get_cf(self.leaf_col, leaf_key.as_slice())
            .map(|s| s.map(|v| v.into()))
            .map_err(|e| Error::Store(e.to_string()))
    }
}

impl<'a, V, T, W> StoreWriteOps<V> for ColumnFamilyStore<'a, T, W>
where
    V: Value + AsRef<[u8]> + From<DBVector>,
    T: DeleteCF<W> + PutCF<W>,
{
    fn insert_branch(&mut self, node_key: BranchKey, branch: BranchNode) -> Result<(), Error> {
        self.inner
            .put_cf(
                self.branch_col,
                &branch_key_to_vec(&node_key),
                &branch_node_to_vec(&branch),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn insert_leaf(&mut self, leaf_key: H256, leaf: V) -> Result<(), Error> {
        self.inner
            .put_cf(self.branch_col, leaf_key.as_slice(), leaf)
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn remove_branch(&mut self, node_key: &BranchKey) -> Result<(), Error> {
        self.inner
            .delete_cf(self.branch_col, &branch_key_to_vec(node_key))
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), Error> {
        self.inner
            .delete_cf(self.branch_col, leaf_key.as_slice())
            .map_err(|e| Error::Store(e.to_string()))
    }
}

/// A SMT `Store` implementation backed by a RocksDB database, using different
/// column families to store the branches and the leaves, supports multiple
/// trees.
pub struct ColumnFamilyStoreMultiTree<'a, T, W> {
    // A key prefix to distinguish different trees.
    prefix: &'a [u8],
    // The RocksDB database which stores the data, can be a `DB` / `OptimisticTransactionDB` /
    // `Snapshot` etc.
    inner: &'a T,
    branch_col: &'a ColumnFamily,
    leaf_col: &'a ColumnFamily,
    // A generic write options, can be a `WriteOptions` / `()` etc.
    write_options: PhantomData<W>,
}

impl<'a, T, W> ColumnFamilyStoreMultiTree<'a, T, W> {
    pub fn new(
        prefix: &'a [u8],
        db: &'a T,
        branch_col: &'a ColumnFamily,
        leaf_col: &'a ColumnFamily,
    ) -> Self {
        ColumnFamilyStoreMultiTree {
            prefix,
            inner: db,
            write_options: PhantomData,
            branch_col,
            leaf_col,
        }
    }
}

impl<'a, V, T, W> StoreReadOps<V> for ColumnFamilyStoreMultiTree<'a, T, W>
where
    V: Value + AsRef<[u8]> + From<DBVector>,
    T: GetCF<ReadOptions>,
{
    fn get_branch(&self, branch_key: &BranchKey) -> Result<Option<BranchNode>, Error> {
        self.inner
            .get_cf(
                self.branch_col,
                &[self.prefix, &branch_key_to_vec(branch_key)].concat(),
            )
            .map(|s| s.map(|v| slice_to_branch_node(&v)))
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn get_leaf(&self, leaf_key: &H256) -> Result<Option<V>, Error> {
        self.inner
            .get_cf(self.leaf_col, &[self.prefix, leaf_key.as_slice()].concat())
            .map(|s| s.map(|v| v.into()))
            .map_err(|e| Error::Store(e.to_string()))
    }
}

impl<'a, V, T, W> StoreWriteOps<V> for ColumnFamilyStoreMultiTree<'a, T, W>
where
    V: Value + AsRef<[u8]> + From<DBVector>,
    T: DeleteCF<W> + PutCF<W>,
{
    fn insert_branch(&mut self, node_key: BranchKey, branch: BranchNode) -> Result<(), Error> {
        self.inner
            .put_cf(
                self.branch_col,
                &[self.prefix, &branch_key_to_vec(&node_key)].concat(),
                &branch_node_to_vec(&branch),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn insert_leaf(&mut self, leaf_key: H256, leaf: V) -> Result<(), Error> {
        self.inner
            .put_cf(
                self.branch_col,
                &[self.prefix, leaf_key.as_slice()].concat(),
                leaf,
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn remove_branch(&mut self, node_key: &BranchKey) -> Result<(), Error> {
        self.inner
            .delete_cf(
                self.branch_col,
                &[self.prefix, &branch_key_to_vec(node_key)].concat(),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), Error> {
        self.inner
            .delete_cf(
                self.branch_col,
                &[self.prefix, leaf_key.as_slice()].concat(),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }
}
