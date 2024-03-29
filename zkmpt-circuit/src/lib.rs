//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_macros)]
#![allow(clippy::too_many_arguments)]
// #![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(test)]
mod test_utils;

pub use hash_circuit::{hash, poseidon};

pub mod operation;

pub mod state_trie;

pub mod gadgets;

pub mod serde;

pub mod verifier;

pub mod zkprover_circuit;

pub mod utils;

pub mod ERC4337;

// pub mod smt_rocksdb_store;

pub mod manager;
