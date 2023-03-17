use std::{hash::Hash, cmp::Ordering};

use crate::gadgets::mpt::{SingleOp, MPTPath};

use super::serde;
use halo2_proofs::arithmetic::FieldExt;
pub use halo2_proofs::halo2curves::bn256::Fr;
use hash_circuit::{hash, Hashable};
use num_bigint::{BigInt, BigUint};
use num_traits::Num;

/// Represent an account operation in MPT
#[derive(Clone, Debug, Default)]
pub struct AccountOp<Fp: FieldExt> {
    /// the operation on the account trie (first layer)
    // pub acc_trie: SingleOp<Fp>,
    // /// the operation on the state trie (second layer)
    // pub state_trie: Option<SingleOp<Fp>>,
    /// the state before updating in account
    pub account_before: Account<Fp>,
    /// the state after updating in account
    pub account_after: Account<Fp>,
}

impl<Fp: FieldExt> AccountOp<Fp> {
    /// the root of account trie before operation
    pub fn account_root_before(&self) -> Fp {
        self.account_before.state_root
    }

    pub fn account_root_after(&self) -> Fp {
        self.account_after.state_root
    }

    /// indicate rows would take in the account trie part
    pub fn use_rows_trie_account(&self) -> usize {
        // TODO: should update SingleOp
        10
    }

}

impl<Fp: Hashable> AccountOp<Fp> {
    /// providing the padding record for hash table
    pub fn padding_hash() -> (Fp, Fp, Fp) {
        (
            Fp::zero(),
            Fp::zero(),
            Hashable::hash([Fp::zero(), Fp::zero()]),
        )
    }

    // pub fn hash_traces(&self) -> impl Iterator<Item = &(Fp, Fp, Fp)> + Clone {
    //     self.acc_trie
    //         .hash_traces()
    //         .chain(self.state_trie.iter().flat_map(|i| i.hash_traces()))
    //         .chain(
    //             self.account_before
    //                 .iter()
    //                 .flat_map(|i| i.hash_traces.iter()),
    //         )
    //         .chain(self.account_after.iter().flat_map(|i| i.hash_traces.iter()))
    //         .chain(Some(self.address_rep.hash_traces()))
    //         .chain(self.store_key.as_ref().map(|v| v.hash_traces()))
    //         .chain(self.store_before.as_ref().map(|v| v.hash_traces()))
    //         .chain(self.store_after.as_ref().map(|v| v.hash_traces()))
    // }
}
/// Represent for a zkProver account
#[derive(Clone, Debug, Default)]
pub struct Account<Fp> {
    ///address
    pub address: Fp,
    /// pub_key: Fp,
    pub pub_key: Fp,
    /// key of address
    pub account_key: Fp,
    /// the gasBalance of account
    pub gas_balance: Fp,
    /// the nonce of an account
    pub nonce: Fp,
    /// the 256-bit tx_hash require 2 field (first / last 128bit) to contain
    pub recrusive_tx_hash: Fp,
    /// the root of state trie
    pub state_root: Fp,

    pub tx_hash: Fp,
    pub pre_recrusive_tx_hash: Fp,

    /// cached traces
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
}

/// impl
impl<Fp: FieldExt> Account<Fp> {
    /// calculating all traces ad-hoc with hasher function
    pub(crate) fn trace(mut self, mut hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        let account_key = hasher(&self.address, &Fp::zero());
        // println!("account_key {account_key:?}");

        // assert_eq!(account_key, self.account_key);

        self.account_key = hasher(&self.address, &Fp::zero());
        self.recrusive_tx_hash = hasher(&self.pre_recrusive_tx_hash, &self.tx_hash);
        let h1 = hasher(&self.account_key, &self.pub_key);
        let h2 = hasher(&self.nonce, &self.gas_balance);
        let h3 = hasher(&self.recrusive_tx_hash, &self.state_root);
        let h4 = hasher(&h3, &h2);
        let h_final = hasher(&h4, &h1);

        self.hash_traces = vec![
            (self.address, Fp::zero(), self.account_key),
            (
                self.pre_recrusive_tx_hash,
                self.tx_hash,
                self.recrusive_tx_hash,
            ),
            (self.nonce, self.gas_balance, h2),
            (self.recrusive_tx_hash, self.state_root, h3),
            (h3, h2, h4),
            (h4, h1, h_final),
        ];

        self
    }
    /// complete
    pub(crate) fn complete(self, hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        if self.hash_traces.is_empty() {
            self.trace(hasher)
        } else {
            self
        }
    }

    /// access the cached traces for calculated all hashes required in obtain
    /// the account hash there is totally 4 of them and the last one
    /// calculate the final hash
    pub fn hash_traces(&self, i: usize) -> Fp {
        if self.hash_traces.is_empty() {
            Fp::zero()
        } else {
            self.hash_traces[i].2
        }
    }

    /// the hash of account, which act as leaf value in account trie
    pub fn account_hash(&self) -> Fp {
        if self.hash_traces.is_empty() {
            Fp::zero()
        } else {
            // assert_eq!(self.hash_traces.len(), 4);
            let len = self.hash_traces.len();
            self.hash_traces[len - 1].2
        }
    }
}

impl<Fp: Hashable> Account<Fp> {
    pub fn create(
        nonce: Fp,
        gas_balance: Fp,
        tx_hash: Fp,
        pre_recrusive_tx_hash: Fp,
        state_root: Fp,
    ) -> Self {
        let init = Self {
            nonce,
            gas_balance,
            tx_hash,
            pre_recrusive_tx_hash,
            state_root,
            ..Default::default()
        };
        init.trace(|a, b| <Fp as Hashable>::hash([*a, *b]))
    }
}

/// include error raised in deserialize or data verification
#[derive(Debug)]
pub enum TraceError {
    /// error in deserialize
    DeErr(std::io::Error),
    /// error for malform data
    DataErr(String),
}

fn bytes_to_fp<Fp: FieldExt>(mut bt: Vec<u8>) -> std::io::Result<Fp> {
    // let expected_size = Fp::NUM_BITS as usize / 8 + if Fp::NUM_BITS % 8 == 0 { 0
    // } else { 1 };
    bt.resize(64, 0u8);
    let arr: [u8; 64] = bt
        .as_slice()
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(Fp::from_bytes_wide(&arr))
}

/// Represent an account operation in MPT
#[derive(Debug, Default, Clone)]
pub struct FpStruct<Fp> {
    pub fp: Fp,
}

impl<'d, Fp: Hashable> From<&'d serde::Hash> for (Fp,) {
    fn from(data: &'d serde::Hash) -> Self {
        let hash_str = data.hex();
        let hash_int = BigInt::from_str_radix(&hash_str.trim_start_matches("0x"), 16)
            .unwrap()
            .to_string();
        // let hash_int = BigInt::from_str
        let hash_fp: Fp = Fp::from_str_vartime(&hash_int).unwrap();

        (hash_fp,)
    }
}

impl<'d, Fp: Hashable> From<&'d serde::Address> for (Fp,) {
    fn from(data: &'d serde::Address) -> Self {
        let hash_str = data.hex();
        let hash_int = BigInt::from_str_radix(&hash_str.trim_start_matches("0x"), 16)
            .unwrap()
            .to_string();
        // let hash_int = BigInt::from_str
        let hash_fp: Fp = Fp::from_str_vartime(&hash_int).unwrap();

        (hash_fp,)
    }
}

impl<'d, Fp: Hashable>
    TryFrom<(
        &'d serde::AccountStateData,
        &'d serde::Address,
        &'d serde::Hash,
        &'d serde::Hash,
    )> for Account<Fp>
{
    type Error = TraceError;

    fn try_from(
        acc_trace: (
            &'d serde::AccountStateData,
            &'d serde::Address,
            &'d serde::Hash,
            &'d serde::Hash,
        ),
    ) -> Result<Self, Self::Error> {
        let (account_data, address, account_key, pub_key) = acc_trace;
        let nonce = Fp::from(account_data.nonce);
        let gas_balance =
            bytes_to_fp(account_data.gas_balance.to_bytes_le()).map_err(TraceError::DeErr)?;
        let (pre_recrusive_tx_hash,) = <(Fp,)>::from(&account_data.pre_recrusive_tx_hash);
        let (address,) = <(Fp,)>::from(address);
        let (pub_key,) = <(Fp,)>::from(pub_key);
        let (account_key,) = <(Fp,)>::from(account_key);
        let (tx_hash,) = <(Fp,)>::from(&account_data.tx_hash);
        // let pre_recrusive_tx_hash = Fp::from_bytes_wide(&account_data.pre_recrusive_tx_hash.cast());
        // let address = Fp::from_bytes_wide(&address.cast());
        // let pub_key = Fp::from_bytes_wide(&pub_key.cast());
        // let account_key = Fp::from_bytes_wide(&account_key.cast());
        // let tx_hash = Fp::from_bytes_wide(&account_data.tx_hash.cast());
        let acc = Self {
            address,
            pub_key,
            account_key,
            nonce,
            gas_balance,
            tx_hash,
            pre_recrusive_tx_hash,
            recrusive_tx_hash: Fp::zero(),
            state_root: Fp::zero(),
            hash_traces: vec![],
        };
        Ok(acc.complete(|a, b| <Fp as Hashable>::hash([*a, *b])))
    }
}

/// parse Trace data into MPTPath and additional data (siblings and path)
/// MptPath Siblings Path
struct SMTPathParse<Fp: FieldExt>(MPTPath<Fp>, Vec<Fp>, Vec<Fp>);

impl<'d, Fp: Hashable> TryFrom<&'d serde::SMTPath> for SMTPathParse<Fp> {
    type Error = TraceError;
    fn try_from(path_trace: &'d serde::SMTPath) -> Result<Self, Self::Error> {
        let mut siblings: Vec<Fp> = Vec::new();
        for n in &path_trace.path {
            let s = Fp::from_bytes_wide(&n.sibling.cast());
            siblings.push(s);
        }

        let mut path_bits: Vec<bool> = Vec::new();
        let mut path: Vec<Fp> = Vec::new();

        for i in 0..siblings.len() {
            let bit = (BigUint::from(1u64) << i) & &path_trace.path_part != BigUint::from(0u64);
            path_bits.push(bit);
            path.push(if bit { Fp::one() } else { Fp::zero() });
        }

        let mut key = Fp::zero();
        let mut leaf = None;
        // notice when there is no leaf node, providing 0 key
        if let Some(leaf_node) = &path_trace.leaf {
            key = Fp::from_bytes_wide(&leaf_node.sibling.cast());
            leaf = Some(Fp::from_bytes_wide(&leaf_node.value.cast()));
        }

        let mpt_path = MPTPath::create(&path_bits, &siblings, key, leaf);
        // sanity check
        let root = Fp::from_bytes_wide(&path_trace.root.cast());
        assert_eq!(root, mpt_path.root());

        Ok(SMTPathParse(mpt_path, siblings, path))
    }
}

impl<'d, Fp: Hashable> TryFrom<(&'d serde::SMTPath, &'d serde::SMTPath, serde::Hash)>
    for SingleOp<Fp>
{
    type Error = TraceError;
    fn try_from(
        traces: (&'d serde::SMTPath, &'d serde::SMTPath, serde::Hash),
    ) -> Result<Self, Self::Error> {
        let (before, after, ref_key) = traces;

        let key = Fp::from_bytes_wide(&ref_key.cast());
        let before_parsed: SMTPathParse<Fp> = before.try_into()?;
        let after_parsed: SMTPathParse<Fp> = after.try_into()?;
        let mut old = before_parsed.0;
        let mut new = after_parsed.0;

        // sanity check
        for (a, b) in after_parsed.1.iter().zip(&before_parsed.1) {
            if a != b {
                println!("compare {a:?} {b:?}");
                return Err(TraceError::DataErr("unmatch siblings".to_string()));
            }
        }

        // update for inserting op
        let (siblings, path, key_immediate) = match old.depth().cmp(&new.depth()) {
            Ordering::Less => {
                assert_eq!(new.key(), Some(key));
                let ext_dist = new.depth() - old.depth();
                old = old.extend(ext_dist, key);
                (
                    after_parsed.1,
                    after_parsed.2,
                    new.key_immediate().expect("should be leaf node"),
                )
            }
            Ordering::Greater => {
                assert_eq!(old.key(), Some(key));
                let ext_dist = old.depth() - new.depth();
                new = new.extend(ext_dist, key);
                (
                    before_parsed.1,
                    before_parsed.2,
                    old.key_immediate().expect("should be leaf node"),
                )
            }
            Ordering::Equal => {
                if old.key() != Some(key) && new.key() != Some(key) {
                    assert_eq!(old.key(), new.key());
                    let mut siblings = before_parsed.1;
                    let mut path = before_parsed.2;

                    if let Some(another_key) = old.key() {
                        // we need to make full path extension for both side, manually
                        let invert_2 = Fp::one().double().invert().unwrap();
                        let mut k1 = another_key;
                        let mut k2 = key;
                        let mut common_prefix_depth: usize = 0;
                        let shiftr = |fp: Fp| {
                            if fp.is_odd().unwrap_u8() == 1 {
                                fp * invert_2 - invert_2
                            } else {
                                fp * invert_2
                            }
                        };
                        let mut k2_bit = k2.is_odd().unwrap_u8();
                        while k1.is_odd().unwrap_u8() == k2_bit {
                            k1 = shiftr(k1);
                            k2 = shiftr(k2);
                            common_prefix_depth += 1;
                            if common_prefix_depth > path.len() {
                                path.push(Fp::from(k2_bit as u64));
                                siblings.push(Fp::zero());
                            }
                            assert_ne!(k1, k2);
                            k2_bit = k2.is_odd().unwrap_u8();
                        }

                        assert!(common_prefix_depth >= old.depth());
                        let ext_dist = common_prefix_depth - old.depth() + 1;
                        let last_node_hash = old.hashes[old.hashes.len() - 2];
                        old = old.extend(ext_dist, key);
                        new = new.extend(ext_dist, key);

                        path.push(Fp::from(k2_bit as u64));
                        siblings.push(last_node_hash);
                    }

                    // and also insert the required key hash trace
                    let key_immediate = <Fp as Hashable>::hash([Fp::one(), key]);
                    old.hash_traces.push((Fp::one(), key, key_immediate));

                    (siblings, path, key_immediate)
                } else if old.key() == Some(key) {
                    (
                        before_parsed.1,
                        before_parsed.2,
                        old.key_immediate().expect("should be leaf node"),
                    )
                } else {
                    (
                        after_parsed.1,
                        after_parsed.2,
                        new.key_immediate().expect("should be leaf node"),
                    )
                }
            }
        };

        let mut key_i = BigUint::from_bytes_le(ref_key.start_read());
        key_i >>= siblings.len();

        Ok(Self {
            key,
            key_residual: bytes_to_fp(key_i.to_bytes_le()).map_err(TraceError::DeErr)?,
            key_immediate,
            path,
            siblings,
            old,
            new,
        })
    }
}

impl<'d, Fp: Hashable> TryFrom<&'d serde::MPTTransTrace> for AccountOp<Fp> {
    type Error = TraceError;

    fn try_from(trace: &'d serde::MPTTransTrace) -> Result<Self, Self::Error> {
        // let acc_trie: SingleOp<Fp> = (
        //    &trace.account_path_update.unwrap().old_account_state_path.unwrap(),
        //    &trace.account_path_update.unwrap().new_account_state_path.unwrap(),
        //    trace.account_key
        // ).try_into().unwrap();

        // let state_trie: Option<SingleOp<Fp>> =
        //     if trace.state_path[0].is_some() && trace.state_path[1].is_some() {
        //         Some(
        //             (
        //                 trace.state_path[0].as_ref().unwrap(),
        //                 trace.state_path[1].as_ref().unwrap(),
        //                 trace.state_key.unwrap(),
        //             )
        //                 .try_into()?,
        //         )
        //     } else {
        //         None
        //     };

        let account_update = trace.account_update.as_ref().expect("msg");
        let address = &trace.address;
        let account_key = &trace.account_key;
        let pub_key = &trace.pub_key;
        let account_before = {
            let account_data = account_update.old_account_state.as_ref().expect("msg");
            let account: Account<Fp> = (account_data, address, account_key, pub_key).try_into()?;
            account
        };

        let account_after = {
            let account_data = account_update.new_account_state.as_ref().expect("");
            let account: Account<Fp> = (account_data, address, account_key, pub_key).try_into()?;
            account
        };

        Ok(Self {
            account_before,
            account_after,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HashableField<Fp: FieldExt>(Fp);

impl<Fp: FieldExt> std::hash::Hash for HashableField<Fp> {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        state.write_u128(self.0.get_lower_128());
    }
}

impl<Fp: FieldExt> From<Fp> for HashableField<Fp> {
    fn from(v: Fp) -> Self {
        Self(v)
    }
}

#[derive(Clone)]
pub(crate) struct HashTracesSrc<T, Fp: FieldExt> {
    source: T,
    deduplicator: std::collections::HashSet<HashableField<Fp>>,
}

impl<T, Fp: FieldExt> From<T> for HashTracesSrc<T, Fp> {
    fn from(source: T) -> Self {
        Self {
            source,
            deduplicator: Default::default(),
        }
    }
}

impl<'d, T, Fp> Iterator for HashTracesSrc<T, Fp>
where
    T: Iterator<Item = &'d (Fp, Fp, Fp)>,
    Fp: FieldExt,
{
    type Item = &'d (Fp, Fp, Fp);

    fn next(&mut self) -> Option<Self::Item> {
        for i in self.source.by_ref() {
            let cp_i = HashableField::from(i.2);
            if self.deduplicator.get(&cp_i).is_none() {
                self.deduplicator.insert(cp_i);
                return Some(i);
            }
        }
        None
    }
}
/// test
#[cfg(test)]
mod tests {

    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use hash_circuit::{hash, poseidon::Hash, Hashable};
    use num_bigint::BigUint;
    use std::vec;

    use crate::{
        serde::HexBytes,
        test_utils::{hash_str_to_fp, Fp},
    };

    use super::{bytes_to_fp, Account, TraceError};

    #[test]
    fn atonomy_bytes_data() {
        let gas_balance: Fp = bytes_to_fp(
            BigUint::from_bytes_be(
                b"0x1ffffffffffffffffffffffffffffffffffffffffffd5a5fa703d6131f2c2e5",
            )
            .to_bytes_le(),
        )
        .unwrap();
        println!("gasbalance {gas_balance:?}");

        let a = Fp::from(1000u64);
        let b = Fp::from(10u64);
        let c = Fp::from(1001u64);
        assert_eq!(a.lt(&c), true);
        assert_eq!(b.lt(&a), true);
        println!("Fp a {a:?}");

        let str = "0x41527e5c9713e748e4d0d28d270071a7710acffa8a2221605f6162a185de3416";
        let hash_bytes = HexBytes::<32>::try_from(str).unwrap();
        let hash_bytes_hex = hash_bytes.hex();
        println!("hash_bytes {hash_bytes:?}");
        println!("hash_bytes_hex {hash_bytes_hex:?}");
    }

    /// test
    #[test]
    fn trace_account_data() {
        let tx_hash_vec = vec![
            hash_str_to_fp("0x26af0428e16c2e77b72b7ff2bfee86292f61c02dce0f25f8a8651a662245b818"),
            hash_str_to_fp("0x86073f5c72cad966e40b0bf3538a1c95e5cb93e34fa455951dfe760797a79016"),
            hash_str_to_fp("0x245f586b79e1efff0f3edf628b054cc4fa6cb62655d369f3675a6493ab9509a0"),
        ];
        let mut final_tx_hash: Fp = Fp::zero();
        for i in 0..tx_hash_vec.len() {
            final_tx_hash = Fp::hash([final_tx_hash, tx_hash_vec[i]]);
        }

        let account: Account<Fp> = Account {
            address: hash_str_to_fp("0xb364e75b1189dcbbf7f0c856456c1ba8e4d6481b"),
            pub_key: hash_str_to_fp(
                "0xfb8fc76b0dd70729afc7eb236fbcb772770e306acb145552c19c045f0211b75e",
            ),
            nonce: Fp::from(1u64),
            gas_balance: Fp::from(1000u64),
            tx_hash: hash_str_to_fp(
                "0xfb8fc76b0dd70729afc7eb236fbcb772770e306acb145552c19c045f0211b75e",
            ),
            recrusive_tx_hash: hash_str_to_fp(
                "0xd84ef25cb42fd625f0b37e2051b1265e7cb7d8f2c4e267222220cfa8d1a439a9",
            ),
            state_root: hash_str_to_fp(
                "0x7739c67431d2c13dbcfb87502eafa7c21d17680a64b699b250d42b6f09e9e6ba",
            ),
            ..Default::default()
        };

        let data = account.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));
        println!("data hash {:?}", data.account_hash());

        assert_eq!(
            data.account_hash(),
            hash_str_to_fp("0x10bfe617037389f321b8a42581d8366a9cc8ae353d8b7d54195c28016c6054e8")
        );
    }
}
