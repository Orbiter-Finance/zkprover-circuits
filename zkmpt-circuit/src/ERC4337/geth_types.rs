//! Error module for the eth-types crate

use core::fmt::{Display, Formatter, Result as FmtResult};
use std::error::Error as StdError;

use ethers::core::types::Eip1559TransactionRequest;
use ethers::types::{NameOrAddress, TransactionRequest};

use super::bundler::Transaction;

/// Error type for any BusMapping related failure.
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    SerdeError(serde_json::error::Error),
    /// Error while generating a trace.
    TracingError(String),
    /// Block is missing information about number or base_fee
    IncompleteBlock,
    /// Denotes that the byte in the bytecode does not match with any Opcode ID.
    InvalidOpcodeIdByte(u8),
    /// Error while parsing an `Instruction/Opcode`.
    OpcodeParsing(String),
    /// Error while parsing a `MemoryAddress`.
    MemAddressParsing,
    /// Error while parsing a `StackAddress`.
    StackAddressParsing,
    /// Error while trying to convert to an incorrect `OpcodeId`.
    InvalidOpConversion,
    /// Error while trying to access an invalid/empty Stack location.
    InvalidStackPointer,
    /// Error while trying to access an invalid/empty Memory location.
    InvalidMemoryPointer,
    /// Error while trying to access an invalid/empty Storage key.
    InvalidStorageKey,
    /// Error when an EvmWord is too big to be converted into a
    /// `MemoryAddress`.
    WordToMemAddr,
    /// Signature parsing error.
    Signature(libsecp256k1::Error),
}

impl From<&Transaction> for TransactionRequest {
    fn from(tx: &Transaction) -> TransactionRequest {
        TransactionRequest {
            from: Some(tx.from),
            to: tx.to.map(NameOrAddress::Address),
            gas: Some(tx.gas_limit),
            gas_price: tx.gas_price,
            value: Some(tx.value),
            data: Some(tx.input.clone()),
            nonce: Some(tx.nonce),
            ..Default::default()
        }
    }
}

// impl From<&Transaction> for Eip1559TransactionRequest {
//     fn from(tx: &Transaction) -> Eip1559TransactionRequest {
//         Eip1559TransactionRequest {
//             from: Some(tx.from),
//             to: tx.to.map(NameOrAddress::Address),
//             gas: Some(tx.gas_limit),
//             value: Some(tx.value),
//             data: Some(tx.call_data.clone()),
//             nonce: Some(tx.nonce),
//             access_list: tx.access_list.clone(),
//             max_priority_fee_per_gas: tx.gas_fee_cap,
//             max_fee_per_gas: tx.gas_tip_cap,
//             chain_id: Some(tx.chain_id),
//             ..Default::default()
//         }
//     }
// }
