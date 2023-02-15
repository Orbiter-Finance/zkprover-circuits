//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_macros)]
#![allow(clippy::too_many_arguments)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod operation;

#[cfg(test)]
mod test_utils;

pub use hash_circuit::{hash, poseidon};
