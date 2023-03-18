
use ethers::abi::ethabi::{
    Bytes, Hash
};

use num_bigint::BigUint;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct BundlerRpcTxData {
    pub hash: Bytes,
    pub nonce: Bytes,
    pub block_hash: Bytes,
    pub block_number: Bytes,
    pub transaction_index: Bytes,
    pub from: Bytes,
    pub to: Bytes,
    pub value: Bytes,
    pub gas_price: Bytes,
    pub gas: Bytes,
    pub input: Bytes,
    pub v: Bytes,
    pub r: Bytes,
    pub s: Bytes,
    pub r#type: Bytes,
    pub access_list: Vec<Bytes>,
    pub max_priority_fee_per_gas: Bytes,
    pub chain_id: Bytes,
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_bundler_rpc_data() {

    }
}