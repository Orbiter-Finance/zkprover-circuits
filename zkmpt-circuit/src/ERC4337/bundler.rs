// use ethers::abi::ethabi::{
//     Bytes, Hash, Uint, Address
// };

use ethers::{
    core::types::{
        transaction::eip1559::Eip1559TransactionRequest, transaction::eip2930::AccessList, Address,
        Block, Bytes, Signature, TxHash, H160, H256, U256, U64,
    },
    types::TransactionRequest,
    utils::keccak256,
};

use lazy_static::lazy_static;

use halo2_proofs::halo2curves::{
    secp256k1::{self, Secp256k1Affine},
    CurveAffine,
};
use num::Integer;
use num_bigint::BigUint;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};

use crate::{
    gadgets::{ToBigEndian, ToLittleEndian},
    serde::Hash,
    ERC4337::geth_types::Error as BundlerError,
};
use itertools::Itertools;
use snark_verifier::util::{
    arithmetic::PrimeField,
    hash::{Digest, Keccak256},
};
use subtle::CtOption;

use crate::{gadgets::sign_verify::SignData, operation::TraceError};

lazy_static! {
    /// Secp256k1 Curve Scalar.  Referece: Section 2.4.1 (parameter `n`) in "SEC 2: Recommended
    /// Elliptic Curve Domain Parameters" document at http://www.secg.org/sec2-v2.pdf
    pub static ref SECP256K1_Q: BigUint = BigUint::from_bytes_le(&(secp256k1::Fq::zero() - secp256k1::Fq::one()).to_repr()) + 1u64;
}

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
    pub gas_price: Option<U256>,
    pub gas: U256,
    pub input: Bytes,
    pub v: U64,
    pub r: U256,
    pub s: U256,
    pub r#type: U256,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub chain_id: U64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct BundlerRpcData {
    pub jsonrpc: String,
    pub result: BundlerRpcResult,
    pub id: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct BundlerRpcResult {
    pub batch_hash: TxHash,
    pub tx_list: Vec<BundlerRpcTxData>,
    pub status: u64,
}

/// Ethereum Word (256 bits).
pub type Word = U256;

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Transaction {
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Transaction nonce
    pub nonce: Word,
    /// Gas Limit / Supplied gas
    pub gas_limit: Word,
    /// Transfered value
    pub value: Word,
    /// Gas Price
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<Word>,
    /// Gas fee cap
    pub gas_fee_cap: Option<Word>,
    /// Gas tip cap
    pub gas_tip_cap: Option<Word>,
    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see
    /// Ethereum Contract ABI
    pub call_data: Bytes,
    /// Access list
    pub access_list: AccessList,

    pub chain_id: U64,

    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,
}

/// Helper function to convert a `CtOption` into an `Result`.  Similar to
/// `Option::ok_or`.
pub fn ct_option_ok_or<T, E>(v: CtOption<T>, err: E) -> Result<T, E> {
    Option::<T>::from(v).ok_or(err)
}

/// Return a copy of the serialized public key with swapped Endianness.
pub fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk)
        .map(|r| r.clone())
        .expect("pk.len() != 64");
    pk_swap[..32].reverse();
    pk_swap[32..].reverse();
    pk_swap
}

/// Recover the public key from a secp256k1 signature and the message hash.
pub fn recover_pk(
    add: Address,
    v: u8,
    r: &Word,
    s: &Word,
    msg_hash: &[u8; 32],
) -> Result<Secp256k1Affine, libsecp256k1::Error> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.to_be_bytes());
    sig_bytes[32..].copy_from_slice(&s.to_be_bytes());
    let signature = libsecp256k1::Signature::parse_standard(&sig_bytes)?;
    let msg_hash = libsecp256k1::Message::parse_slice(msg_hash.as_slice())?;
    let recovery_id = libsecp256k1::RecoveryId::parse(v)?;
    let pk = libsecp256k1::recover(&msg_hash, &signature, &recovery_id)?;
    let pk_be = pk.serialize();
    debug_assert_eq!(pk_be[0], 0x04);
    let pk_hash: [u8; 32] = Keccak256::digest(&pk_be[1..])
        .as_slice()
        .to_vec()
        .try_into()
        .expect("hash length isn't 32 bytes");
    let address = Address::from_slice(&pk_hash[12..]);

    // debug_assert_eq!(address, add);
    if ! address.eq(&add) {
        return Err(libsecp256k1::Error::InvalidSignature);
    }
    
    let pk_le = pk_bytes_swap_endianness(&pk_be[1..]);
    let x = ct_option_ok_or(
        secp256k1::Fp::from_bytes(pk_le[..32].try_into().unwrap()),
        libsecp256k1::Error::InvalidPublicKey,
    )?;
    let y = ct_option_ok_or(
        secp256k1::Fp::from_bytes(pk_le[32..].try_into().unwrap()),
        libsecp256k1::Error::InvalidPublicKey,
    )?;
    ct_option_ok_or(
        Secp256k1Affine::from_xy(x, y),
        libsecp256k1::Error::InvalidPublicKey,
    )
}

pub fn biguint_to_32bytes_le(v: BigUint) -> [u8; 32] {
    let mut res = [0u8; 32];
    let v_le = v.to_bytes_le();
    res[..v_le.len()].copy_from_slice(&v_le);
    res
}

impl Transaction {
    pub(crate) fn verify_sig(&self) -> Result<(), ()> {
        todo!()
    }
    pub(crate) fn sign_1559_data(&self) -> Result<SignData, BundlerError> {
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        let chain_id = self.chain_id.as_u64();
        let sig_r = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_r_le),
            BundlerError::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        let sig_s = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_s_le),
            BundlerError::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        // msg = rlp([nonce, gasPrice, gas, to, value, data, sig_v, r, s])
        let req: Eip1559TransactionRequest = self.into();
        println!("1559 REQ {:?}", &req);
        let msg = req.chain_id(chain_id).rlp();

        println!("RLP Code === {:?}", &msg);
        let msg_hash: [u8; 32] = Keccak256::digest(&msg)
            .as_slice()
            .to_vec()
            .try_into()
            .expect("hash length isn't 32 bytes");

        println!("RLP Hash ==== {:?}", hex::encode(&msg_hash));

        // let v = self
        //     .v
        //     .checked_sub(35 + chain_id * 2)
        //     .ok_or(BundlerError::Signature(
        //         libsecp256k1::Error::InvalidSignature,
        //     ))? as u8;
        let v = self.v as u8;
        let pk = recover_pk(self.from, v, &self.r, &self.s, &msg_hash).unwrap();
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(
            secp256k1::Fq::from_repr(msg_hash_le),
            libsecp256k1::Error::InvalidMessage,
        )
        .unwrap();
        Ok(SignData {
            signature: (sig_r, sig_s),
            pk,
            msg_hash,
        })
    }
    pub(crate) fn sign_data(&self) -> Result<SignData, BundlerError> {
        let chain_id = self.chain_id.as_u64();
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        let sig_r = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_r_le),
            BundlerError::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        let sig_s = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_s_le),
            BundlerError::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        // msg = rlp([nonce, gasPrice, gas, to, value, data, sig_v, r, s])
        let req: TransactionRequest = self.into();
        let msg = req.chain_id(chain_id).rlp();
        let msg_hash: [u8; 32] = Keccak256::digest(&msg)
            .as_slice()
            .to_vec()
            .try_into()
            .expect("hash length isn't 32 bytes");
        let v = self
            .v
            .checked_sub(35 + chain_id * 2)
            .ok_or(BundlerError::Signature(
                libsecp256k1::Error::InvalidSignature,
            ))? as u8;
        let pk = recover_pk(self.from, v, &self.r, &self.s, &msg_hash).unwrap();
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(
            secp256k1::Fq::from_repr(msg_hash_le),
            libsecp256k1::Error::InvalidMessage,
        )
        .unwrap();
        Ok(SignData {
            signature: (sig_r, sig_s),
            pk,
            msg_hash,
        })
    }
}

impl<'d> TryFrom<&'d BundlerRpcTxData> for Transaction {
    type Error = TraceError;

    fn try_from(value: &'d BundlerRpcTxData) -> Result<Self, Self::Error> {
        let tx = Transaction {
            from: value.from.clone(),
            to: value.to.clone(),
            nonce: value.nonce.clone(),
            gas_limit: value.gas.clone(),
            value: value.value.clone(),
            gas_price: value.gas_price.clone(),
            gas_fee_cap: value.max_fee_per_gas.clone(),
            gas_tip_cap: value.max_priority_fee_per_gas.clone(),
            call_data: value.input.clone(),
            access_list: value.access_list.clone(),
            v: value.v.as_u64().clone(),
            r: value.r.clone(),
            s: value.s.clone(),
            chain_id: value.chain_id.clone(),
        };
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::tracing::log::error;
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
            .result
            .tx_list;

        let txs: Vec<Transaction> = rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect();
        println!("txs ${:?}", txs);
        // txs.iter()
        //     .map(|tx| {
        //         tx.sign_1559_data(4337).map_err(|e| {
        //             error!("tx_to_sign_data error for tx {:?}", tx);
        //             e
        //         })
        //     })
        //     .try_collect()
        //     .unwrap();
    }
}
