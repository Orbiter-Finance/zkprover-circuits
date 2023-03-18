
// use ethers::abi::ethabi::{
//     Bytes, Hash, Uint, Address
// };

 use ethers::core::types::{
    transaction::{eip2930::AccessList},
    Address, Block, Bytes, H160, H256, U256, U64, TxHash, 
};

use num_bigint::BigUint;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};

use crate::operation::TraceError;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct BundlerRpcTxData {
   
    pub hash: TxHash,
    pub nonce: U256,
    pub block_hash: Option<TxHash>,
    pub block_number: Option<U256>,
    pub transaction_index: Option<U256>,
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    pub value: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub input: Bytes, 
    pub v: U64,
    pub r: U256,
    pub s: U256,
    pub r#type: U256,
    pub access_list: Option<AccessList>,
    pub max_priority_fee_per_gas: U256,
    pub chain_id: U256,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct BundlerRpcData {
    pub txs: Vec<BundlerRpcTxData>,
}


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

impl <'d> TryFrom <&'d BundlerRpcTxData> for Transaction {
    type Error = TraceError;
    
    fn try_from(value: &'d BundlerRpcTxData) -> Result<Self, Self::Error> {
        let tx = Self {
            from: value.from.clone(),
            to: value.to.clone(),
            nonce: value.nonce.clone(),
            gas_limit: value.gas.clone(),
            value: value.value.clone(),
            gas_price: value.gas_price.clone(),
            gas_fee_cap: value.max_priority_fee_per_gas.clone(),
            gas_tip_cap: value.max_priority_fee_per_gas.clone(),
            call_data: value.input.clone(),
            access_list: value.access_list.clone(),
            v: value.v.as_u64(),
            r: value.r,
            s: value.s,
        };
        Ok(tx)
    }
} 

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use super::{BundlerRpcData, Transaction};
    #[test]
    fn test_bundler_rpc_data() {
        let mut buffer = Vec::new();
        let mut f = File::open("src/ERC4337/rpc_data_test.json").unwrap();
        f.read_to_end(&mut buffer).unwrap();
        // println!("buffer {buffer:?}");

        let rpc_txs = serde_json::from_slice::<BundlerRpcData>(&buffer)
                                                                                .unwrap()
                                                                                .txs;
                                                                                    
        let txs: Vec<Transaction> = rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect();

    }
}