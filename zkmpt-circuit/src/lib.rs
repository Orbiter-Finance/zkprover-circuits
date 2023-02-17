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
