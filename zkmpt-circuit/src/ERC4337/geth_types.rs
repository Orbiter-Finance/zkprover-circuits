use ethers::{core::types::{
    Address, Bytes,
}, types::{transaction::eip2930::AccessList, U256}};

use serde::{Serialize, Serializer};

/// Ethereum Word (256 bits).
pub type Word = U256;

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Transaction {
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Transaction nonce
    pub nonce: Word,
    /// Gas Limit / Supplied gas
    pub gas_limit: Word,
    /// Transfered value
    pub value: Word,
    /// Gas Price
    pub gas_price: Word,
    /// Gas fee cap
    pub gas_fee_cap: Word,
    /// Gas tip cap
    pub gas_tip_cap: Word,
    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see
    /// Ethereum Contract ABI
    pub call_data: Bytes,
    /// Access list
    pub access_list: Option<AccessList>,

    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,
}
