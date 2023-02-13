//! represent the data for a single operation on the MPT
//!
#![allow(clippy::derive_hash_xor_eq)]

use super::{eth, serde, HashType};
use crate::hash::Hashable;
use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;
use std::cmp::Ordering;
use std::convert::TryFrom;

/// Indicate the current status of an MPTPath
#[derive(Clone, Copy, Debug)]
pub enum MPTPathStatus<Fp: FieldExt> {
    /// Path has empty leaf node
    Empty,
    /// Path has leaf node and the (key, keyImmediate) is tracked
    Leaf((Fp, Fp)),
    /// Path is under extended status,
    /// the "pushed down" sibling's proof (key, keyImmediate, value) is tracked
    Extended(((Fp, Fp), (Fp, Fp, Fp))),
}

/// Represent a sequence of hashes in a path inside MPT, it can be full
/// (with leaf) or truncated and being padded to an "empty" leaf node,
/// according to the hash_type. It would be used for the layout of MPT
/// circuit
#[derive(Clone, Debug)]
pub struct MPTPath<Fp: FieldExt> {
    /// hash types from beginning of a path, start with HashType::Start
    pub hash_types: Vec<HashType>,
    /// hashes from beginning of path, from the root of MPT to leaf node
    pub hashes: Vec<Fp>,
    /// the cached traces for calculated all hashes required in verifing a MPT path,
    /// include the leaf hashing      
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
    /// the key of path, which is purposed to be known (though not need while constructing
    /// empty leaf node)
    pub status: MPTPathStatus<Fp>,
}

impl<Fp: FieldExt> Default for MPTPath<Fp> {
    fn default() -> Self {
        Self {
            hash_types: vec![HashType::Start, HashType::Empty],
            hashes: vec![Fp::zero(), Fp::zero()],
            hash_traces: Default::default(),
            status: MPTPathStatus::Empty,
        }
    }
}

impl<Fp: FieldExt> MPTPath<Fp> {
    /// the root of MPT
    pub fn root(&self) -> Fp {
        self.hashes[0]
    }

    /// the leaf value, for truncated path, give None
    pub fn leaf(&self) -> Option<Fp> {
        match *self.hash_types.last().unwrap() {
            HashType::Empty => None,
            _ => Some(*self.hashes.last().unwrap()),
        }
    }

    /// the key value (for leaf or sibling, depending on status)
    pub fn key(&self) -> Option<Fp> {
        match self.status {
            MPTPathStatus::Empty => None,
            MPTPathStatus::Leaf((fp, _)) => Some(fp),
            MPTPathStatus::Extended(((_, fp), _)) => Some(fp),
        }
    }

    /// the immediate value in key hashing (for leaf or sibling, depending on status)
    pub fn key_immediate(&self) -> Option<Fp> {
        match self.status {
            MPTPathStatus::Empty => None,
            MPTPathStatus::Leaf((_, fp)) => Some(fp),
            MPTPathStatus::Extended(((_, fp), _)) => Some(fp),
        }
    }

    /// shortcut entry for status
    pub fn is_extended(&self) -> bool {
        matches!(self.status, MPTPathStatus::Extended(_))
    }

    /// the proof (key, key_immediate, value) in extended, for the last sibling is a leaf
    pub fn extended_proof(&self) -> Option<(Fp, Fp, Fp)> {
        match self.status {
            MPTPathStatus::Extended((_, proof)) => Some(proof),
            _ => None,
        }
    }

    /// the depth of path, means how many bits would be attributed to path type
    pub fn depth(&self) -> usize {
        self.hashes.len() - 2
    }

    pub(crate) fn extend_with_hasher(
        self,
        l: usize,
        new_key: Fp,
        mut hasher: impl FnMut(&Fp, &Fp) -> Fp,
    ) -> Self {
        if l == 0 {
            return self;
        }

        assert!(self.hash_types.len() > 1, "can not extend empty path");
        let ins_pos = self.hash_types.len() - 1;
        // can only extend a path with leaf
        let new_key_immediate = hasher(&Fp::one(), &self.key().expect("can only extend leaf"));
        let status = match self.status {
            MPTPathStatus::Leaf((fp, fp_immediate)) => MPTPathStatus::Extended((
                (new_key, new_key_immediate),
                (fp, fp_immediate, self.hashes[ins_pos]),
            )),
            _ => panic!("can only extend leaf path"),
        };

        let mut hash_types = self.hash_types;
        let mut addi_types = vec![HashType::LeafExt; l - 1];
        addi_types.push(HashType::LeafExtFinal);

        hash_types[ins_pos] = HashType::Empty;
        drop(hash_types.splice(ins_pos..ins_pos, addi_types));

        let mut hashes = self.hashes;
        let mut addi_hashes = vec![hashes[ins_pos - 1]; l - 1]; //pick the hash of leaf

        // move the old value at last row to upper (row LeafExtFinal)
        addi_hashes.push(hashes[ins_pos]);
        hashes[ins_pos] = Fp::zero();
        drop(hashes.splice(ins_pos..ins_pos, addi_hashes));

        Self {
            hash_types,
            hashes,
            status,
            ..self
        }
    }

    pub(crate) fn create_with_hasher(
        path: &[bool],
        siblings: &[Fp],
        key: Fp,
        leaf: Option<Fp>,
        mut hasher: impl FnMut(&Fp, &Fp) -> Fp,
    ) -> Self {
        assert_eq!(path.len(), siblings.len());

        let (status, mut hashes, mut hash_types, mut hash_traces) = if let Some(fp) = leaf {
            let one = Fp::one();
            let key_immediate = hasher(&one, &key);

            let leaf_hash = hasher(&key_immediate, &fp);
            (
                MPTPathStatus::Leaf((key, key_immediate)),
                vec![fp, leaf_hash],
                vec![HashType::Leaf],
                vec![(one, key, key_immediate), (key_immediate, fp, leaf_hash)],
            )
        } else {
            (
                MPTPathStatus::Empty,
                vec![Fp::zero(), Fp::zero()],
                vec![HashType::Empty],
                Vec::new(),
            )
        };

        for (sibling, bit) in siblings.iter().rev().zip(path.iter().rev()) {
            let (l, r) = if *bit {
                (sibling, hashes.last().unwrap())
            } else {
                (hashes.last().unwrap(), sibling)
            };

            let h = hasher(l, r);
            hash_traces.push((*l, *r, h));
            hashes.push(h);
            hash_types.push(HashType::Middle);
        }

        hashes.reverse();
        hash_types.push(HashType::Start);
        hash_types.reverse();

        Self {
            status,
            hashes,
            hash_types,
            hash_traces,
        }
    }
}

impl<Fp: Hashable> MPTPath<Fp> {
    /// create a common path data layout (only contains middle and leaf type)
    /// with the help of siblings and path bits (false indicate zero)
    /// to calculate path ad-hoc by hasher function
    pub fn create(path: &[bool], siblings: &[Fp], key: Fp, leaf: Option<Fp>) -> Self {
        Self::create_with_hasher(path, siblings, key, leaf, |a, b| {
            <Fp as Hashable>::hash([*a, *b])
        })
    }

    /// extend a common path (contain only midle and leaf/empty) to under extended status,
    /// it require caller to calc how many level should be extended and what the new key is
    pub fn extend(self, l: usize, new_key: Fp) -> Self {
        self.extend_with_hasher(l, new_key, |a, b| <Fp as Hashable>::hash([*a, *b]))
    }
}

/// Represent for a single operation
#[derive(Clone, Debug, Default)]
pub struct SingleOp<Fp: FieldExt> {
    /// the key of operation
    pub key: Fp,
    /// the immediate in key hashing
    pub key_immediate: Fp,
    /// the residual part of key for leaf
    pub key_residual: Fp,
    /// the path of operation, from top to the leaf's resident
    pub path: Vec<Fp>,
    /// the siblings, with one zero padding in the end
    pub siblings: Vec<Fp>,
    /// the MPT path data before operation
    pub old: MPTPath<Fp>,
    /// the MPT path data after operation
    pub new: MPTPath<Fp>,
}

impl<Fp: FieldExt> SingleOp<Fp> {
    /// indicate rows would take in circuit layout
    pub fn use_rows(&self) -> usize {
        self.siblings.len() + 2
    }

    /// calculate the ctrl_type base on the two hash type of MPTPath
    pub fn ctrl_type(&self) -> Vec<HashType> {
        self.old
            .hash_types
            .iter()
            .copied()
            .zip(self.new.hash_types.clone())
            .map(|type_pair| match type_pair {
                (old, new) if old == new => old,
                (HashType::Middle, HashType::LeafExt) | (HashType::LeafExt, HashType::Middle) => {
                    HashType::LeafExt
                }
                (HashType::Middle, HashType::LeafExtFinal)
                | (HashType::LeafExtFinal, HashType::Middle) => HashType::LeafExtFinal,
                (HashType::Empty, HashType::Leaf) | (HashType::Leaf, HashType::Empty) => {
                    HashType::Leaf
                }
                _ => unreachable!(
                    "invalid hash type pair: {:?}, {:?}",
                    type_pair.0, type_pair.1
                ),
            })
            .collect()
    }

    /// the root of MPT before operation
    pub fn start_root(&self) -> Fp {
        self.old.root()
    }

    /// the root of MPT after operation
    pub fn new_root(&self) -> Fp {
        self.new.root()
    }
    /// data represent an update operation (only contains middle and leaf type)
    /// with the help of siblings and calculating path ad-hoc by hasher function
    pub(crate) fn create_update_op_with_hasher(
        layers: usize,
        siblings: &[Fp],
        key: Fp,
        leafs: (Fp, Fp),
        hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone,
    ) -> Self {
        let siblings = Vec::from(siblings);

        //decompose path
        let (path, key_residual): (Vec<bool>, Fp) = {
            assert!(
                (layers as u32) * 8 < Fp::NUM_BITS,
                "not able to decompose more than bits"
            );
            let mut ret = Vec::new();
            let mut tested_key = key;
            let invert_2 = Fp::one().double().invert().unwrap();
            for _ in 0..layers {
                if tested_key.is_odd().unwrap_u8() == 1 {
                    tested_key = tested_key * invert_2 - invert_2;
                    ret.push(true);
                } else {
                    tested_key *= invert_2;
                    ret.push(false);
                }
            }
            (ret, tested_key)
        };
        let (old_leaf, new_leaf) = leafs;

        let old = MPTPath::<Fp>::create_with_hasher(
            &path,
            &siblings,
            key,
            Some(old_leaf),
            hasher.clone(),
        );
        let new = MPTPath::<Fp>::create_with_hasher(&path, &siblings, key, Some(new_leaf), hasher);
        let key_immediate = old
            .key_immediate()
            .expect("must have immediate value for leaf node");
        let path: Vec<Fp> = path
            .into_iter()
            .map(|b| if b { Fp::one() } else { Fp::zero() })
            .collect();

        Self {
            key,
            key_immediate,
            key_residual,
            old,
            new,
            siblings,
            path,
        }
    }

    /// create another updating op base on a previous action
    pub(crate) fn update_next_with_hasher(
        self,
        new_leaf: Fp,
        hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone,
    ) -> Self {
        let path_bool: Vec<bool> = self.path.iter().map(|v| *v != Fp::zero()).collect();
        let new = MPTPath::<Fp>::create_with_hasher(
            &path_bool,
            &self.siblings,
            self.key,
            Some(new_leaf),
            hasher,
        );
        Self {
            old: self.new,
            new,
            ..self
        }
    }

    /// iterate all hash traces inside the op
    pub fn hash_traces(&self) -> impl Iterator<Item = &(Fp, Fp, Fp)> + Clone {
        self.old
            .hash_traces
            .iter()
            .chain(self.new.hash_traces.iter())
    }

    /// when op has extention, return the proof for last silbling
    /// (notice if both old/new has proof, they should be identical)
    pub fn extended_proof(&self) -> Option<(Fp, Fp, Fp)> {
        self.old
            .extended_proof()
            .or_else(|| self.new.extended_proof())
    }
}

impl<Fp: Hashable> SingleOp<Fp> {
    /// data represent an update operation (only contains middle and leaf type)
    /// with the help of siblings and calculating path ad-hoc by hasher function
    pub fn create_update_op(layers: usize, siblings: &[Fp], key: Fp, leafs: (Fp, Fp)) -> Self {
        Self::create_update_op_with_hasher(layers, siblings, key, leafs, |a, b| {
            <Fp as Hashable>::hash([*a, *b])
        })
    }

    /// create another updating op base on a previous action
    pub fn update_next(self, new_leaf: Fp) -> Self {
        self.update_next_with_hasher(new_leaf, |a, b| <Fp as Hashable>::hash([*a, *b]))
    }
}

fn bytes_to_fp<Fp: FieldExt>(mut bt: Vec<u8>) -> std::io::Result<Fp> {
    // let expected_size = Fp::NUM_BITS as usize / 8 + if Fp::NUM_BITS % 8 == 0 { 0 } else { 1 };
    bt.resize(64, 0u8);
    let arr: [u8; 64] = bt
        .as_slice()
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(Fp::from_bytes_wide(&arr))
}

/// Represent for a eth account
#[derive(Clone, Debug, Default)]
pub struct Account<Fp> {
    /// the balance of account, because it is the total amount of ethereum so field should be large enough
    pub balance: Fp,
    /// the nonce of an account
    pub nonce: Fp,
    /// the 256-bit codehash require 2 field (first / last 128bit) to contain
    pub codehash: (Fp, Fp),
    /// the root of state trie
    pub state_root: Fp,
    /// cached traces
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
}

impl<Fp: FieldExt> Account<Fp> {
    /// calculating all traces ad-hoc with hasher function
    pub(crate) fn trace(mut self, mut hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        let h1 = hasher(&self.codehash.0, &self.codehash.1);
        let h3 = hasher(&self.nonce, &self.balance);
        let h2 = hasher(&h1, &self.state_root);
        let h_final = hasher(&h3, &h2);

        self.hash_traces = vec![
            (self.codehash.0, self.codehash.1, h1),
            (h1, self.state_root, h2),
            (self.nonce, self.balance, h3),
            (h3, h2, h_final),
        ];

        self
    }

    pub(crate) fn complete(self, hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        if self.hash_traces.is_empty() {
            self.trace(hasher)
        } else {
            self
        }
    }

    /// access the cached traces for calculated all hashes required in obtain the account hash
    /// there is totally 4 of them and the last one calculate the final hash
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
            assert_eq!(self.hash_traces.len(), 4);
            self.hash_traces[3].2
        }
    }
}

impl<Fp: Hashable> Account<Fp> {
    /// create object and complete the fields by calculating all traces
    pub fn create(balance: Fp, nonce: Fp, codehash: (Fp, Fp), state_root: Fp) -> Self {
        let init = Self {
            balance,
            nonce,
            codehash,
            state_root,
            ..Default::default()
        };
        init.trace(|a, b| <Fp as Hashable>::hash([*a, *b]))
    }
}

/// 2 fields for representing 32 byte, used for storage key or value, the hash is also saved
#[derive(Clone, Debug, Default)]
pub struct KeyValue<Fp> {
    data: (Fp, Fp, Fp), // (the first 16 bytes, the second 16 bytes, hash value)
}

impl<Fp: FieldExt> KeyValue<Fp> {
    /// create object and omit the hash
    pub fn create_base(bytes32: (Fp, Fp)) -> Self {
        let (fst, snd) = bytes32;
        Self {
            data: (fst, snd, Fp::zero()),
        }
    }

    /// obtain the value pair
    pub fn val(&self) -> (Fp, Fp) {
        (self.data.0, self.data.1)
    }
    /// obtain the hash
    pub fn hash(&self) -> Fp {
        self.data.2
    }
    /// obtain the linear combination of two field
    pub fn lc(&self, randomness: Fp) -> Fp {
        self.data.0 + self.data.1 * randomness
    }
    /// obtain the linear combination of the value, in byte represent, which
    /// is common used in zkevm circuit
    /// the u256 is represented by le bytes and combined with randomness 1, o, o^2 ... o^31 on each
    /// and we calculate it from be represent
    pub fn u8_rlc(&self, randomness: Fp) -> Fp {
        let u128_hi = self.data.0.get_lower_128();
        let u128_lo = self.data.1.get_lower_128();
        u128_hi
            .to_be_bytes()
            .into_iter()
            .chain(u128_lo.to_be_bytes())
            .map(|bt| Fp::from(bt as u64))
            .reduce(|acc, f| acc * randomness + f)
            .expect("not empty")
    }
    /// obtain the first limb
    pub fn limb_0(&self) -> Fp {
        self.data.0
    }
    /// obtain the snd limb
    pub fn limb_1(&self) -> Fp {
        self.data.1
    }
}

impl<Fp: Hashable> KeyValue<Fp> {
    /// create object and also calc the hash
    pub fn create(bytes32: (Fp, Fp)) -> Self {
        let (fst, snd) = bytes32;
        let hash = <Fp as Hashable>::hash([fst, snd]);

        Self {
            data: (fst, snd, hash),
        }
    }

    /// return the triple group of hash
    pub fn hash_traces(&self) -> &(Fp, Fp, Fp) {
        &self.data
    }
}

/// Represent an operation in eth MPT, which update 2 layer of tries (state and account)
#[derive(Clone, Debug, Default)]
pub struct AccountOp<Fp: FieldExt> {
    /// the operation on the account trie (first layer)
    pub acc_trie: SingleOp<Fp>,
    /// the operation on the state trie (second layer)
    pub state_trie: Option<SingleOp<Fp>>,
    /// the state before updating in account
    pub account_before: Option<Account<Fp>>,
    /// the state after updating in account
    pub account_after: Option<Account<Fp>>,
    /// the stored value before being updated
    pub store_before: Option<KeyValue<Fp>>,
    /// the stored value after being updated
    pub store_after: Option<KeyValue<Fp>>,
    /// address (the preimage of acc_trie's key)
    pub address: Fp,
    /// address (the preimage of acc_trie's key, splitted by 2 fields)
    pub address_rep: KeyValue<Fp>,
    /// the key being store (preimage of state_trie's key)
    pub store_key: Option<KeyValue<Fp>>,
}

impl<Fp: FieldExt> AccountOp<Fp> {
    /// indicate rows would take for whole operation
    pub fn use_rows(&self) -> usize {
        self.use_rows_account()
            + self.use_rows_trie_state()
            + self.use_rows_trie_account()
            + self.use_rows_trie_kv()
    }

    /// indicate rows would take in the account trie part
    pub fn use_rows_trie_account(&self) -> usize {
        self.acc_trie.use_rows()
    }

    /// indicate rows would take in the state trie part
    pub fn use_rows_trie_state(&self) -> usize {
        if let Some(op) = &self.state_trie {
            op.use_rows()
        } else {
            0
        }
    }

    /// indicate rows would take in account part
    pub fn use_rows_account(&self) -> usize {
        if self.state_trie.is_some() {
            eth::CIRCUIT_ROW - 1
        } else {
            eth::CIRCUIT_ROW
        }
    }

    /// indicate rows would take in the state kv part
    pub fn use_rows_trie_kv(&self) -> usize {
        if self.state_trie.is_some() {
            1
        } else {
            0
        }
    }

    /// the root of account trie, which is global state
    pub fn account_root(&self) -> Fp {
        self.acc_trie.new_root()
    }

    /// the root of account trie before operation
    pub fn account_root_before(&self) -> Fp {
        self.acc_trie.start_root()
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

    /// iter all the hash traces inside an operation (may contain duplications)
    pub fn hash_traces(&self) -> impl Iterator<Item = &(Fp, Fp, Fp)> + Clone {
        self.acc_trie
            .hash_traces()
            .chain(self.state_trie.iter().flat_map(|i| i.hash_traces()))
            .chain(
                self.account_before
                    .iter()
                    .flat_map(|i| i.hash_traces.iter()),
            )
            .chain(self.account_after.iter().flat_map(|i| i.hash_traces.iter()))
            .chain(Some(self.address_rep.hash_traces()))
            .chain(self.store_key.as_ref().map(|v| v.hash_traces()))
            .chain(self.store_before.as_ref().map(|v| v.hash_traces()))
            .chain(self.store_after.as_ref().map(|v| v.hash_traces()))
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

// parse Trace data into MPTPath and additional data (siblings and path)
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

impl<'d, Fp: Hashable> TryFrom<(&'d serde::AccountData, Fp)> for Account<Fp> {
    type Error = TraceError;
    fn try_from(acc_trace: (&'d serde::AccountData, Fp)) -> Result<Self, Self::Error> {
        let (acc, state_root) = acc_trace;
        let nonce = Fp::from(acc.nonce);
        let balance = bytes_to_fp(acc.balance.to_bytes_le()).map_err(TraceError::DeErr)?;
        let buf = acc.code_hash.to_bytes_le();
        let codehash = if buf.len() < 16 {
            (bytes_to_fp(buf).map_err(TraceError::DeErr)?, Fp::zero())
        } else {
            (
                bytes_to_fp(Vec::from(&buf[16..])).map_err(TraceError::DeErr)?,
                bytes_to_fp(Vec::from(&buf[0..16])).map_err(TraceError::DeErr)?,
            )
        };

        let acc = Self {
            nonce,
            balance,
            codehash,
            state_root,
            ..Default::default()
        };
        Ok(acc.complete(|a, b| <Fp as Hashable>::hash([*a, *b])))
    }
}

// decode address, store kv in smttrace with big-endian presented (32 bytes)
impl<'d, Fp: Hashable> From<&'d serde::HexBytes<32>> for KeyValue<Fp> {
    fn from(byte32: &'d serde::HexBytes<32>) -> Self {
        let bytes = byte32.0;
        let first_16bytes: [u8; 16] = bytes[..16].try_into().expect("expect first 16 bytes");
        let last_16bytes: [u8; 16] = bytes[16..].try_into().expect("expect second 16 bytes");
        Self::create((
            Fp::from_u128(u128::from_be_bytes(first_16bytes)),
            Fp::from_u128(u128::from_be_bytes(last_16bytes)),
        ))
    }
}

impl<'d, Fp: Hashable> From<&'d serde::HexBytes<20>> for KeyValue<Fp> {
    fn from(byte20: &'d serde::HexBytes<20>) -> Self {
        let bytes = byte20.0;
        let first_16bytes: [u8; 16] = bytes[..16].try_into().expect("expect first 16 bytes");
        let last_4bytes: [u8; 4] = bytes[16..].try_into().expect("expect second 4 bytes");
        Self::create((
            Fp::from_u128(u128::from_be_bytes(first_16bytes)),
            Fp::from_u128(
                u32::from_be_bytes(last_4bytes) as u128 * 0x1000000000000000000000000u128,
            ),
        ))
    }
}

impl<'d, Fp: Hashable> TryFrom<&'d serde::SMTTrace> for AccountOp<Fp> {
    type Error = TraceError;
    fn try_from(trace: &'d serde::SMTTrace) -> Result<Self, Self::Error> {
        let acc_trie: SingleOp<Fp> = (
            &trace.account_path[0],
            &trace.account_path[1],
            trace.account_key,
        )
            .try_into()?;

        let state_trie: Option<SingleOp<Fp>> =
            if trace.state_path[0].is_some() && trace.state_path[1].is_some() {
                Some(
                    (
                        trace.state_path[0].as_ref().unwrap(),
                        trace.state_path[1].as_ref().unwrap(),
                        trace.state_key.unwrap(),
                    )
                        .try_into()?,
                )
            } else {
                None
            };

        let comm_state_root = match trace.common_state_root {
            Some(h) => Fp::from_bytes_wide(&h.cast()),
            None => Fp::zero(),
        };

        let account_before = if let Some(leaf) = acc_trie.old.leaf() {
            let account_data = trace.account_update[0]
                .as_ref()
                .expect("account should exist when there is leaf");
            let old_state_root = state_trie
                .as_ref()
                .map(|s| s.start_root())
                .unwrap_or(comm_state_root);
            let account: Account<Fp> = (account_data, old_state_root).try_into()?;
            // sanity check
            assert_eq!(account.account_hash(), leaf);

            Some(account)
        } else {
            None
        };

        let account_after = if let Some(leaf) = acc_trie.new.leaf() {
            let account_data = trace.account_update[1]
                .as_ref()
                .expect("account should exist when there is leaf");
            let new_state_root = state_trie
                .as_ref()
                .map(|s| s.new_root())
                .unwrap_or(comm_state_root);
            let account: Account<Fp> = (account_data, new_state_root).try_into()?;

            // sanity check
            assert_eq!(account.account_hash(), leaf);
            Some(account)
        } else {
            None
        };

        let address = {
            let bytes = trace.address.0;
            let first_16bytes: [u8; 16] = bytes[..16].try_into().expect("expect first 16 bytes");
            let last_4bytes: [u8; 4] = bytes[16..].try_into().expect("expect second 4 bytes");
            Fp::from_u128(u128::from_be_bytes(first_16bytes)) * Fp::from(0x100000000u64)
                + Fp::from(u32::from_be_bytes(last_4bytes) as u64)
        };
        let address_rep = KeyValue::from(&trace.address);

        let (store_key, store_before, store_after) = if state_trie.is_some() {
            let update_pair = trace.state_update.as_ref().expect("state trie has existed");
            (
                Some(KeyValue::from(
                    &update_pair[0]
                        .as_ref()
                        .or(update_pair[1].as_ref())
                        .expect("one of state update should not NONE")
                        .key,
                )),
                update_pair[0].as_ref().map(|st| KeyValue::from(&st.value)),
                update_pair[1].as_ref().map(|st| KeyValue::from(&st.value)),
            )
        } else {
            (None, None, None)
        };

        Ok(Self {
            acc_trie,
            state_trie,
            account_before,
            account_after,
            address,
            address_rep,
            store_key,
            store_before,
            store_after,
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

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use super::*;
    use crate::test_utils::{rand_bytes_array, rand_gen, Fp};
    use halo2_proofs::{halo2curves::group::ff::{Field, PrimeField}, plonk::Expression};

    impl<Fp: FieldExt> SingleOp<Fp> {
        /// create an fully random update operation with leafs customable
        pub fn create_rand_op(
            layers: usize,
            leafs: Option<(Fp, Fp)>,
            key: Option<Fp>,
            hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone,
        ) -> Self {
            let siblings: Vec<Fp> = (0..layers)
                .map(|_| Fp::random(rand_gen([101u8; 32])))
                .collect();
            let key = key.unwrap_or_else(|| Fp::random(rand_gen([99u8; 32])));
            let leafs = leafs.unwrap_or_else(|| {
                (
                    Fp::random(rand_gen([102u8; 32])),
                    Fp::random(rand_gen([103u8; 32])),
                )
            });
            Self::create_update_op_with_hasher(layers, &siblings, key, leafs, hasher)
        }
    }

    impl<Fp: FieldExt> KeyValue<Fp> {
        /// create an fully random k/v
        pub fn create_rand(mut hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone) -> Self {
            let a = Fp::from_u128(u128::from_be_bytes(rand_bytes_array::<16>()));
            let b = Fp::from_u128(u128::from_be_bytes(rand_bytes_array::<16>()));
            let h = hasher(&a, &b);

            Self { data: (a, b, h) }
        }
    }

    fn decompose<Fp: FieldExt>(inp: Fp, l: usize) -> (Vec<bool>, Fp) {
        let mut ret = Vec::new();
        let mut tested_key = inp;
        let invert_2 = Fp::one().double().invert().unwrap();
        for _ in 0..l {
            if tested_key.is_odd().unwrap_u8() == 1 {
                tested_key = tested_key * invert_2 - invert_2;
                ret.push(true);
            } else {
                tested_key *= invert_2;
                ret.push(false);
            }
        }
        (ret, tested_key)
    }

    fn recover<Fp: FieldExt>(path: &[bool], res: Fp) -> Fp {
        let mut mask = Fp::one();
        let mut ret = Fp::zero();

        for b in path {
            ret += if *b { mask } else { Fp::zero() };
            mask = mask.double();
        }

        ret + res * mask
    }

    #[test]
    fn path_decomposing() {
        let test1 = Fp::from(75u64);
        // 75(decimal) = 1001011(binary)
        let ret1 = decompose(test1, 4);
        assert_eq!(ret1.0, vec![true, true, false, true]);
        assert_eq!(ret1.1, Fp::from(4u64));

        let test2 = Fp::from(16203805u64);
        // 16203805(decimal) =  11,1101110100000000011101(binary)
        let ret2 = decompose(test2, 22);
        assert_eq!(ret2.0, vec![true,false,true,true,true,false,false,false,false,false,false,false,false,false,true,false,true,true,true,false,true,true]);
        assert_eq!(recover(&ret2.0, ret2.1), test2);

        for _ in 0..1000 {
            let test = Fp::random(rand_gen([101u8; 32]));
            let ret = decompose(test, 22);
            assert_eq!(recover(&ret.0, ret.1), test);
        }
    }

    #[test]
    fn trace_debug_convert() {
        let example = r#"{"address":"0xb36feaeaf76c2a33335b73bef9aef7a23d9af1e3","accountKey":"0xf59112e5670628682b1ec72767b1a6153096d47742e1d9455c175a955211e900","accountPath":[{"pathPart":"0xf5","root":"0xab4ef5db245d66748b2cbd6eb7f57ebd8fee61444130233546fcd196a0298706","path":[{"value":"0x26e297ed2c0265392eb4d55ca93464914535a3da6c1a70a5884bbf0048f2bc11","sibling":"0x8251455b38bef426b8c56ad1e5c4b2004d0a57cf8af0aa499329e502f3a5022b"},{"value":"0x08eaa42867286da95ec7cf88e17ee86fdbc158b6c631365eab3f00f20ac7a029","sibling":"0xe582f6c510f1bf05d68badf1284b17ab9b44408e12f7c46b09c9260dd572fa2e"},{"value":"0xfee9e393c454b03ebe8c59988ee4c4a7224fdd133d211f1057131253610aa91d","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x01198505cc61e6be5421ed71bb380cb85f7d77af957c30d9a79478f236c4802b","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0xd91419a365920d5a3bd771e9d354abd558d0f9ff429a37d002ebfd122833ea2c","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x6af55a02e1b2435ebbbc58bf8e9b83efc4b4fd10dad2c739ba6be95119781e00","sibling":"0x559653b52296e19fe878d6430dbc748ebcd3046b463aa32689eac16c29702607"},{"value":"0x34a4740b27bec9410f659ec6134d6f7c9c933f35143152c374b125e2bce7ac2a","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x7368c8ebabb8fd55758c492232e6302b66efe9ce03c3eb22e9b7540eb15c8a1c","sibling":"0x0498324f694fc9f300d1600f78e054657dcb9ce620358beba8c1e847a14dc203"}],"leaf":{"value":"0x33c5435c783d711eca3cb21179f8afaf6dd0be8ca0f066d0daace28b17fc281d","sibling":"0xf59112e5670628682b1ec72767b1a6153096d47742e1d9455c175a955211e900"}},{"pathPart":"0xf5","root":"0x04048d2ce5b611be0de990f0c5575a8b82ded0e33f2ba624a823736426ff5d05","path":[{"value":"0xc5f6457f340dd71b3f30227f969df9d219f85f0f85f615d97610e56e5dd3e911","sibling":"0x8251455b38bef426b8c56ad1e5c4b2004d0a57cf8af0aa499329e502f3a5022b"},{"value":"0x21ce60ff0a0d9626c284cbc3c03774d0e4e07c2a900a3e1f16716d120f8a741c","sibling":"0xe582f6c510f1bf05d68badf1284b17ab9b44408e12f7c46b09c9260dd572fa2e"},{"value":"0xd93364b73307c4e85309140e10b36b36dfcaba10d45c2c3b6108493ab1dea520","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0xc97d843eac19493e6e1b34e7c425d8943fb412cb71ba0a8344b435c04819ee08","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x5c1745a0c67b60a9d36e163e22afd69fe79d51d10c4e4a2f6a8376c55cbc2d27","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x23560d93412c108a1903015d54cb1239d4d6c9819347af5f735df983c3eb9b24","sibling":"0x559653b52296e19fe878d6430dbc748ebcd3046b463aa32689eac16c29702607"},{"value":"0x9dee92127fa400bfd4e158b546f343c75ca5eab55b8438900a4f35d8eaaa5020","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x2c05e2bb4aa93790418fb89c3bb0eb8030cf7dc178054de03fb225145db3c32e","sibling":"0x0498324f694fc9f300d1600f78e054657dcb9ce620358beba8c1e847a14dc203"}],"leaf":{"value":"0xdc1171e525a47eb17a5042b0d5fee68b08c8f7fe9377be7db8f3a06227ef3327","sibling":"0xf59112e5670628682b1ec72767b1a6153096d47742e1d9455c175a955211e900"}}],"accountUpdate":[{"nonce":1,"balance":"0x0","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"nonce":1,"balance":"0x0","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}],"stateKey":"0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820","statePath":[{"pathPart":"0x0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"pathPart":"0x0","root":"0x2b6a9e4dba68659fcc19b9b88240a96b06fa558578ff60317af9406e48621f09","leaf":{"value":"0xc37dd2b463aad7591be6403c921fdc58c12e28469ad81e28d08ad1582210d911","sibling":"0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820"}}],"stateUpdate":[null,{"key":"0x0000000000000000000000000000000000000000000000000000000000000000","value":"0x00000000000000000000000033b5ddf9b5e82bb958eb885f5f241e783a113f18"}]}"#;
        let trace: serde::SMTTrace = serde_json::from_str(example).unwrap();

        println!("{:?}", trace.state_path[0]);
        // let parse: SMTPathParse<Fp> = trace.state_path[0].as_ref().unwrap().try_into().unwrap();
        let parse: SMTPathParse<Fp> = trace.state_path[0].as_ref().unwrap().try_into().unwrap();
        println!("{:?}", parse.0);

        println!("{:?}", trace.state_path[1]);
        let parse: SMTPathParse<Fp> = trace.state_path[1].as_ref().unwrap().try_into().unwrap();
        println!("{:?}", parse.0);
    }

  
    #[test]
    fn trace_convert_insert_op() {
        let example = r#"{"address":"0xb36feaeaf76c2a33335b73bef9aef7a23d9af1e3","accountKey":"0xf59112e5670628682b1ec72767b1a6153096d47742e1d9455c175a955211e900","accountPath":[{"pathPart":"0x35","root":"0xebb00990cd20ab357e0e2115c0e301b8f4b0e0ee80b0500b3071e25c15770708","path":[{"value":"0x637a3f9434eddbed4a74ccf9472cf0e0d2806efe6100c42787fc9e19e1bf8028","sibling":"0x8251455b38bef426b8c56ad1e5c4b2004d0a57cf8af0aa499329e502f3a5022b"},{"value":"0xb1ca958b3030d92b8a07ea6b1733c2e015a11b80612b22bbf8be572b237ac308","sibling":"0xe582f6c510f1bf05d68badf1284b17ab9b44408e12f7c46b09c9260dd572fa2e"},{"value":"0x44947e33abac81c9d1cdbdc1eddf1646c042d5ba09a2096e38b280995a1fe805","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x706201d8f8e421382bc72b45f9f6bda4a4686ca7c8f83fd6cd548dc55d6cfd07","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x060d011c93edea04679826c4ca35f903e85f3d255b124cf327d331b9a256bf0e","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x0498324f694fc9f300d1600f78e054657dcb9ce620358beba8c1e847a14dc203","sibling":"0x559653b52296e19fe878d6430dbc748ebcd3046b463aa32689eac16c29702607"}],"leaf":{"value":"0xebda5e259838533294ae6548ea49d9ef6c13113fac4f311890821345d3cb3617","sibling":"0x7581e431a68d0fa641e14a7d29a6c2b150db6da1d13f59dee6f7f492a0bebd29"}},{"pathPart":"0xf5","root":"0xab4ef5db245d66748b2cbd6eb7f57ebd8fee61444130233546fcd196a0298706","path":[{"value":"0x26e297ed2c0265392eb4d55ca93464914535a3da6c1a70a5884bbf0048f2bc11","sibling":"0x8251455b38bef426b8c56ad1e5c4b2004d0a57cf8af0aa499329e502f3a5022b"},{"value":"0x08eaa42867286da95ec7cf88e17ee86fdbc158b6c631365eab3f00f20ac7a029","sibling":"0xe582f6c510f1bf05d68badf1284b17ab9b44408e12f7c46b09c9260dd572fa2e"},{"value":"0xfee9e393c454b03ebe8c59988ee4c4a7224fdd133d211f1057131253610aa91d","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x01198505cc61e6be5421ed71bb380cb85f7d77af957c30d9a79478f236c4802b","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0xd91419a365920d5a3bd771e9d354abd558d0f9ff429a37d002ebfd122833ea2c","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x6af55a02e1b2435ebbbc58bf8e9b83efc4b4fd10dad2c739ba6be95119781e00","sibling":"0x559653b52296e19fe878d6430dbc748ebcd3046b463aa32689eac16c29702607"},{"value":"0x34a4740b27bec9410f659ec6134d6f7c9c933f35143152c374b125e2bce7ac2a","sibling":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"value":"0x7368c8ebabb8fd55758c492232e6302b66efe9ce03c3eb22e9b7540eb15c8a1c","sibling":"0x0498324f694fc9f300d1600f78e054657dcb9ce620358beba8c1e847a14dc203"}],"leaf":{"value":"0x33c5435c783d711eca3cb21179f8afaf6dd0be8ca0f066d0daace28b17fc281d","sibling":"0xf59112e5670628682b1ec72767b1a6153096d47742e1d9455c175a955211e900"}}],"accountUpdate":[null,{"nonce":1,"balance":"0x0","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}],"commonStateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","statePath":[null,null],"stateUpdate":[null,null]}"#;
        let trace: serde::SMTTrace = serde_json::from_str(example).unwrap();

        let data: AccountOp<Fp> = (&trace).try_into().unwrap();
        println!("{:?}", data);
    }

     #[test]
    fn trace_account_data() {
        let data: Account<Fp> = Account {
            balance: Fp::from(0u64),
            nonce: Fp::from(1u64),
            codehash: (Fp::zero(), Fp::zero()),
            //0x20b24ebee7712fbbe84a15027eba4f1208e2e2df9f925de51b3382b86433e6a5
            state_root: Fp::from_str_vartime(
                "14789053415173694845992038966920525110567435779704439275440571405364058384037",
            )
            .unwrap(),
            ..Default::default()
        };

        let data = data.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));

        //0x227e285425906a1f84d43e6e821bd3d49225e39e8395e9aa680a1574ff5f1eb8
        assert_eq!(
            data.account_hash(),
            Fp::from_str_vartime(
                "15601537920438488782505741155807773419253320959345191889201535312143566446264"
            )
            .unwrap()
        );

        let code_hash_int = BigUint::parse_bytes(
            b"e653e6971d6128bd15b83aa8ebeefca96378c1e36ba7bedafc17f76f1e10f632",
            16,
        )
        .unwrap();

        let data: Account<Fp> = Account {
            balance: Fp::from(0u64),
            nonce: Fp::from(1u64),
            //0xe653e6971d6128bd15b83aa8ebeefca96378c1e36ba7bedafc17f76f1e10f632
            codehash: (
                bytes_to_fp(Vec::from(&code_hash_int.to_bytes_le()[16..])).unwrap(),
                bytes_to_fp(Vec::from(&code_hash_int.to_bytes_le()[0..16])).unwrap(),
            ),

            //0x0fb46c93fe32157d73bdaf9359e4ac1fa7514f7043014df64213c18bbd80c2e0
            state_root: Fp::from_str_vartime(
                "7103474578896643880912595670996880817578037370381571930047680755406072759008",
            )
            .unwrap(),
            ..Default::default()
        };

        let data = data.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));
        println!("{:?}", data);

        //0x282e0113717ea7f0d515b8db9adaf15741c4ace339965482b771062e1f969fb6
        assert_eq!(
            data.account_hash(),
            Fp::from_str_vartime(
                "18173796334248186903004954824637212553607820157797929507368343926106786013110"
            )
            .unwrap()
        );
    }

    #[test]
    fn fp_invert_test() {
        let four = Fp::from(10000u64);
        let four_invert = four.invert().unwrap();
        println!("four ========== {:?}", four);
        println!("four_invert==== {:?}", four_invert);
        println!("four_invert plus four ==== {:?}", four.mul(four_invert));
        assert_eq!(four.mul(four_invert), Fp::from(1u64));
    }
}
