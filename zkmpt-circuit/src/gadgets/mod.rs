use ethers::types::U256;

pub mod account;
pub mod ecsdsa;
pub mod gas_ticket;
pub mod hash_poseidon;
pub mod hash_util;
pub mod hashes_sum;
pub mod table;
pub mod kv_util;
pub mod layer;
pub mod mpt;
pub mod padding;
pub mod poseidon_hash;
pub mod sign_verify;
pub mod sign_util;
pub mod table_util;

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}
