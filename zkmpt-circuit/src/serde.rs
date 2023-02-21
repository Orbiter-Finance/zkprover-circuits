//! deserialize data for operations
use num_bigint::BigUint;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};

use std::fmt::{Debug, Display, Formatter};

impl<const LEN: usize> Serialize for HexBytes<LEN> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ret = format!("0x{:0>1$}", self.hex(), LEN * 2);
        serializer.serialize_str(&ret)
    }
}

impl<'de, const LEN: usize> Deserialize<'de> for HexBytes<LEN> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let de_str = <&'de str>::deserialize(deserializer)?;

        de_str.try_into().map_err(D::Error::custom)
    }
}

fn de_uint_bin<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let de_str = <&'de str>::deserialize(deserializer)?;
    BigUint::parse_bytes(de_str.as_bytes(), 2).ok_or_else(|| D::Error::custom(RowDeError::BigInt))
}

fn se_uint_hex<S>(bi: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ret = format!("0x{}", bi.to_str_radix(16));
    serializer.serialize_str(&ret)
}

fn se_uint_hex_fixed32<S>(bi: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ret = format!("0x{:0>64}", bi.to_str_radix(16));
    serializer.serialize_str(&ret)
}

fn de_uint_hex<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let de_str = <&'de str>::deserialize(deserializer)?;
    // handling "0x" prefix and a special case that only "0x" occur (i.e.: 0)
    let ret = if de_str.starts_with("0x") {
        if de_str.len() == 2 {
            return Ok(BigUint::default());
        }
        BigUint::parse_bytes(de_str.get(2..).unwrap().as_bytes(), 16)
    } else {
        BigUint::parse_bytes(de_str.as_bytes(), 16)
    };

    ret.ok_or_else(|| D::Error::custom(RowDeError::BigInt))
}

#[derive(Debug, thiserror::Error)]
/// Row type deserialization errors.
pub enum RowDeError {
    #[error(transparent)]
    /// hex decode error
    Hex(#[from] hex::FromHexError),
    #[error("cannot parse bigInt repr")]
    /// bigInt decode error
    BigInt,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// HexBytes struct encoding to "0x...."
pub struct HexBytes<const LEN: usize>(pub [u8; LEN]);

impl<const LEN: usize> HexBytes<LEN> {
    /// get hex representation
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// pick the inner cotent for read
    pub fn start_read(&self) -> &[u8] {
        &self.0[..]
    }

    /// cast bytes to another length, truncate or append 0 on the target
    pub fn cast<const LNEW: usize>(&self) -> [u8; LNEW] {
        let mut out = [0; LNEW];
        self.0
            .iter()
            .zip(out.as_mut_slice())
            .for_each(|(i, o): (&u8, &mut u8)| *o = *i);
        out
    }
}

impl<const LEN: usize> Default for HexBytes<LEN> {
    fn default() -> Self {
        Self([0; LEN])
    }
}

impl<const LEN: usize> Debug for HexBytes<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:0>1$}", self.hex(), LEN * 2)
    }
}

impl<const LEN: usize> Display for HexBytes<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:0>1$}", self.hex(), LEN * 2)
    }
}

impl<const LEN: usize> AsRef<[u8; LEN]> for HexBytes<LEN> {
    fn as_ref(&self) -> &[u8; LEN] {
        &self.0
    }
}

impl<const LEN: usize> AsMut<[u8; LEN]> for HexBytes<LEN> {
    fn as_mut(&mut self) -> &mut [u8; LEN] {
        &mut self.0
    }
}

impl<const LEN: usize> TryFrom<&str> for HexBytes<LEN> {
    type Error = hex::FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut bytes = Self::default();
        // handling "0x" prefix
        if value.starts_with("0x") {
            hex::decode_to_slice(value.get(2..).unwrap(), &mut bytes.0)?;
        } else {
            hex::decode_to_slice(value, &mut bytes.0)?;
        }

        Ok(bytes)
    }
}

/// Hash expressed by 256bit integer for a Fp repr
pub type Hash = HexBytes<32>;

/// Address expressed by 20bytes eth address
pub type Address = HexBytes<20>;

///
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct MptRootUpdate {
    pub old_root: Hash,
    pub new_root: Hash,
}

///
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct AccountState {
    pub nonce: u64,
    #[serde(deserialize_with = "de_uint_hex", serialize_with = "se_uint_hex")]
    pub gas_balance: BigUint,

    /// Recrusive hash of the account tx list hashes like: hash(n) = hash(txN,
    /// hash(n-1))
    pub tx_hash_history: Hash,
}

///
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct AccountUpdate {
    pub old_account_state: Option<AccountState>,
    pub new_account_state: Option<AccountState>,
}

///
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct MPTTransTrace {
    /// Address for the trace
    pub address: Address,

    /// key of account (hash of address)
    pub account_key: Hash,
    /// pub key of the account
    pub pub_key: Hash,

    /// hash of the use Tx
    pub tx_hash: Hash,

    pub tx_signature: Hash,

    pub mpt_root_update: Option<MptRootUpdate>,

    pub account_update: Option<AccountUpdate>,
}
