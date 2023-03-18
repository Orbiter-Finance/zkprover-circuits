use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn, VirtualCells,
    },
    poly::Rotation,
};
use hash_circuit::Hashable;

use super::{table_util::MPTOpTables, hash_util::HashTable};


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


/// Indicate the operation type of a row in MPT circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashType {
    /// Marking the start of node
    Start = 0,
    /// Empty node
    Empty,
    /// middle node
    Middle,
    /// leaf node which is extended to middle in insert
    LeafExt,
    /// leaf node which is extended to middle in insert, which is the last node
    /// in new path
    LeafExtFinal,
    /// leaf node
    Leaf,
}

const HASH_TYPE_CNT: usize = 6;

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

// we lookup the transition of ctrl type from the preset table, and different kind of rules
// is specified here
enum CtrlTransitionKind {
    Mpt = 1,        // transition in MPT circuit
    Account,        // transition in account circuit
    Operation = 99, // transition of the old state to new state in MPT circuit
}


#[derive(Clone, Debug)]
struct PathChipConfig {
    s_path: Column<Advice>,
    hash_type: Column<Advice>,
    s_hash_type: [Column<Advice>; HASH_TYPE_CNT],
    s_match_ctrl_type: Column<Advice>,
    s_match_ctrl_aux: Column<Advice>,
    val: Column<Advice>,
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct PathChip<'d, F: FieldExt> {
    offset: usize,
    config: PathChipConfig,
    data: &'d MPTPath<F>,
    ref_ctrl_type: Option<&'d [HashType]>,
}

impl<Fp: FieldExt> Chip<Fp> for PathChip<'_, Fp> {
    type Config = PathChipConfig;
    type Loaded = MPTPath<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'d, Fp: FieldExt> PathChip<'d, Fp> {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        g_config: &MPTOpConfig,
        from_old: bool,
    ) -> <Self as Chip<Fp>>::Config {
        let s_path = g_config.s_path;
        let s_enable = g_config.s_enable;
        let s_hash_type = g_config.s_ctrl_type;
        let hash_type = if from_old {
            g_config.old_hash_type
        } else {
            g_config.new_hash_type
        };
        let s_match_ctrl_type = if from_old {
            g_config.s_hash_match_ctrl[0]
        } else {
            g_config.s_hash_match_ctrl[1]
        };
        let s_match_ctrl_aux = if from_old {
            g_config.s_hash_match_ctrl_aux[0]
        } else {
            g_config.s_hash_match_ctrl_aux[1]
        };
        let val = if from_old {
            g_config.old_val
        } else {
            g_config.new_val
        };
        //let key = g_config.acc_key;
        let ext_sibling_val = val;
        let key_immediate = g_config.key_aux;
        let hash_table = &g_config.hash_table;

        let s_row = g_config.s_row;
        let sibling = g_config.sibling;
        let path = g_config.path;
        let trans_table = &g_config.tables;

        // Only lookup for hash table should be
        // setuped here, no other gates required
        //
        // |-------|-------|-------|
        // |  val  |sibling|  path |
        // |-------|-------|-------|
        // |   a   |   b   |  bit  |
        // |   c   |   d   |  bit  |
        // |-------|-------|-------|
        // where:
        //     bit = 0  ==>  l = a, r = b
        //     bit = 1  ==>  l = b, r = a
        //     h = upper cell of val col
        //
        // and we lookup (l, r, h) for each row which IsFirst is zero
        // that is:
        // (
        //   bit * (b - a) + a,
        //   bit * (a - b) + b,
        //   a.Rotation(-1)
        // )
        //
        // from table formed by (left, right, hash)
        meta.lookup_any("mpt node hash", |meta| {
            let s_hash_type_not_match = Expression::Constant(Fp::one())
                - meta.query_advice(s_match_ctrl_type, Rotation::cur());
            let s_path = meta.query_advice(s_enable, Rotation::cur())
                * (meta.query_advice(s_hash_type[HashType::Middle as usize], Rotation::cur())
                    + s_hash_type_not_match.clone()
                        * meta.query_advice(
                            s_hash_type[HashType::LeafExt as usize],
                            Rotation::cur(),
                        )
                    + s_hash_type_not_match
                        * meta.query_advice(
                            s_hash_type[HashType::LeafExtFinal as usize],
                            Rotation::cur(),
                        )); //hash type is Middle: i.e ctrl type is Middle or (Ext and ExtFinal and not
                            // match)

            let path_bit = meta.query_advice(path, Rotation::cur());
            let val_col = meta.query_advice(val, Rotation::cur());
            let sibling_col = meta.query_advice(sibling, Rotation::cur());
            let node_hash = meta.query_advice(val, Rotation::prev());

            hash_table.build_lookup(
                meta,
                s_path,
                path_bit.clone() * (sibling_col.clone() - val_col.clone()) + val_col.clone(),
                path_bit * (val_col - sibling_col.clone()) + sibling_col,
                node_hash,
            )
        });

        // calculate part of the leaf hash: hash(key_immediate, val) = hash_of_key_node
        meta.lookup_any("mpt leaf hash", |meta| {
            let s_leaf = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(s_hash_type[HashType::Leaf as usize], Rotation::cur()); //(actually) Leaf

            let key_immediate = meta.query_advice(key_immediate, Rotation::cur());
            let leaf_val = meta.query_advice(val, Rotation::cur());
            let leaf_hash = meta.query_advice(val, Rotation::prev());
            hash_table.build_lookup(meta, s_leaf, key_immediate, leaf_val, leaf_hash)
        });

        //transition, notice the start status is ensured outside of the gadget
        meta.lookup("mpt type trans", |meta| {
            let s_not_begin = Expression::Constant(Fp::one())
                - meta.query_advice(s_hash_type[HashType::Start as usize], Rotation::cur()); //not Start

            let s_block_enable = meta.query_advice(s_enable, Rotation::cur()) * s_not_begin;

            trans_table.build_lookup(
                s_block_enable,
                meta.query_advice(hash_type, Rotation::prev()),
                meta.query_advice(hash_type, Rotation::cur()),
                CtrlTransitionKind::Mpt as u64,
            )
        });

        meta.create_gate("leaf extended", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_extended = meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(s_hash_type[HashType::LeafExt as usize], Rotation::cur()); //(actually) LeafExt
            let sibling = meta.query_advice(sibling, Rotation::cur());
            // + sibling must be 0 when hash_type is leaf extended, or malice
            //   advisor can make arbital sibling which would halt the process of L2
            // + value of val col in leaf-extended row must equal to the previous
            vec![
                enable.clone() * s_extended.clone() * sibling,
                enable
                    * s_extended
                    * (meta.query_advice(val, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        meta.create_gate("last leaf extended", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_last_extended = meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(
                    s_hash_type[HashType::LeafExtFinal as usize],
                    Rotation::cur(),
                ); //(actually) LeafExtFinal

            // + sibling must be previous value of val when hash_type is leaf extended final
            // (notice the value for leafExtendedFinal can be omitted)
            vec![
                enable
                    * s_last_extended
                    * (meta.query_advice(sibling, Rotation::cur())
                        - meta.query_advice(val, Rotation::prev())),
            ]
        });

        // prove the silbing is really a leaf when extended
        meta.lookup_any("extended sibling proof 1", |meta| {
            let s_last_extended = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(
                    s_hash_type[HashType::LeafExtFinal as usize],
                    Rotation::cur(),
                ); //(actually) LeafExtFinal
            let key_proof = meta.query_advice(sibling, Rotation::next()); //key is written here
            let key_proof_immediate = meta.query_advice(key_immediate, Rotation::cur());

            hash_table.build_lookup(
                meta,
                s_last_extended,
                Expression::Constant(Fp::one()),
                key_proof,
                key_proof_immediate,
            )
        });

        meta.lookup_any("extended sibling proof 2", |meta| {
            let s_last_extended = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_match_ctrl_type, Rotation::cur())
                * meta.query_advice(
                    s_hash_type[HashType::LeafExtFinal as usize],
                    Rotation::cur(),
                ); //(actually) LeafExtFinal
            let extended_sibling = meta.query_advice(sibling, Rotation::cur());
            let key_proof_immediate = meta.query_advice(key_immediate, Rotation::cur());
            let key_proof_value = meta.query_advice(ext_sibling_val, Rotation::cur());

            hash_table.build_lookup(
                meta,
                s_last_extended,
                key_proof_immediate,
                key_proof_value,
                extended_sibling,
            )
        });

        PathChipConfig {
            s_path,
            hash_type,
            s_hash_type,
            s_match_ctrl_type,
            s_match_ctrl_aux,
            val,
        }
    }
    fn construct(
        config: PathChipConfig,
        offset: usize,
        data: &'d <Self as Chip<Fp>>::Loaded,
        ref_ctrl_type: Option<&'d [HashType]>,
    )-> Self {
        Self {
            config,
            offset,
            data,
            ref_ctrl_type,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;
        let offset = self.offset;
        let vals = &self.data.hashes;
        let hash_types = &self.data.hash_types;
        assert_eq!(hash_types.len(), vals.len());

        for (index, (hash_type, val)) in hash_types.iter().copied().zip(vals.iter()).enumerate() {
            region.assign_advice(|| "val", config.val, offset + index, || Value::known(*val))?;
            region.assign_advice(
                || format!("hash_type {}", hash_type as u32),
                config.hash_type,
                offset + index,
                || Value::known(Fp::from(hash_type as u64)),
            )?;
            region.assign_advice(
                || format!("hash_type {}", hash_type as u32),
                config.hash_type,
                offset + index,
                || Value::known(Fp::from(hash_type as u64)),
            )?;
            region.assign_advice(
                || "sel",
                config.s_path,
                offset + index,
                || {
                    Value::known(match hash_type {
                        HashType::Start | HashType::Empty | HashType::Leaf => Fp::zero(),
                        _ => Fp::one(),
                    })
                },
            )?;
        }

        let ref_ctrl_type = self
            .ref_ctrl_type
            .unwrap_or(&self.data.hash_types)
            .iter()
            .copied();
        for (index, (hash_type, ref_type)) in
            hash_types.iter().copied().zip(ref_ctrl_type).enumerate()
        {
            region.assign_advice(
                || "hash_type match aux",
                config.s_match_ctrl_aux,
                offset + index,
                || {
                    Value::known(
                        Fp::from(ref_type as u64 - hash_type as u64)
                            .invert()
                            .unwrap_or_else(Fp::zero),
                    )
                },
            )?;
            region.assign_advice(
                || "hash_type match",
                config.s_match_ctrl_type,
                offset + index,
                || {
                    Value::known(if hash_type == ref_type {
                        Fp::one()
                    } else {
                        Fp::zero()
                    })
                },
            )?;
        }

        Ok(offset + hash_types.len())
    }
}

#[derive(Clone, Debug)]
struct OpChipConfig {
    ctrl_type: Column<Advice>,
    s_ctrl_type: [Column<Advice>; HASH_TYPE_CNT],
    sibling: Column<Advice>,
    path: Column<Advice>,
    depth: Column<Advice>,
    acc_key: Column<Advice>,
    key_aux: Column<Advice>,
}

impl<Fp: FieldExt> Chip<Fp> for OpChip<'_, Fp> {
    type Config = OpChipConfig;
    type Loaded = SingleOp<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'d, Fp: FieldExt> OpChip<'d, Fp> {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        g_config: &MPTOpConfig,
    ) -> <Self as Chip<Fp>>::Config {
        let path = g_config.path;
        let old_hash_type = g_config.old_hash_type;
        let new_hash_type = g_config.new_hash_type;
        let acc_key = g_config.acc_key;
        let sibling = g_config.sibling;
        let depth_aux = g_config.depth;
        let key_aux = g_config.key_aux;
        let ctrl_type = g_config.ctrl_type;
        let s_ctrl_type = g_config.s_ctrl_type;

        let s_row = g_config.s_row;
        let s_enable = g_config.s_enable;
        let s_path = g_config.s_path;

        let type_table = &g_config.tables;

        let hash_table = &g_config.hash_table;

        //old - new
        meta.lookup("op update trans", |meta| {
            type_table.build_lookup(
                meta.query_advice(s_enable, Rotation::cur()),
                meta.query_advice(old_hash_type, Rotation::cur()),
                meta.query_advice(new_hash_type, Rotation::cur()),
                CtrlTransitionKind::Operation as u64,
            )
        });

        meta.create_gate("s_path and path bit", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_path = meta.query_advice(s_path, Rotation::cur());
            let s_path_not_opened = Expression::Constant(Fp::one()) - s_path.clone();

            let path = meta.query_advice(path, Rotation::cur());
            let path_bit = (Expression::Constant(Fp::one()) - path.clone()) * path;

            let hash_type = meta.query_advice(old_hash_type, Rotation::cur());
            let not_path_type = (hash_type.clone()
                - Expression::Constant(Fp::from(HashType::Empty as u64)))
                * (hash_type.clone() - Expression::Constant(Fp::from(HashType::Leaf as u64)))
                * (hash_type - Expression::Constant(Fp::from(HashType::Start as u64)));

            // s_path ∈ {0, 1}
            // s_path is not open when hash_type is "start" / "leaf" / "empty"
            // when s_path is 1, path ∈ {0, 1}
            vec![
                enable.clone()
                    * (Expression::Constant(Fp::one()) - s_path.clone())
                    * s_path.clone(),
                enable.clone() * not_path_type * s_path_not_opened,
                enable * s_path * path_bit,
            ]
        });

        meta.create_gate("depth", |meta| {
            let enable = meta.query_selector(s_row) * meta.query_advice(s_enable, Rotation::cur());
            let s_begin = meta.query_advice(s_ctrl_type[HashType::Start as usize], Rotation::cur()); //Start
            let path = meta.query_advice(path, Rotation::cur());
            let depth_aux_start = meta.query_advice(depth_aux, Rotation::cur())
                - Expression::Constant(Fp::one().double().invert().unwrap());
            let depth_aux_common = meta.query_advice(depth_aux, Rotation::cur())
                - meta.query_advice(depth_aux, Rotation::prev())
                    * Expression::Constant(Fp::from(2u64));
            let key_acc = meta.query_advice(acc_key, Rotation::cur())
                - (meta.query_advice(acc_key, Rotation::prev())
                    + path * meta.query_advice(depth_aux, Rotation::cur()));

            // for any row which is not s_begin: depth_aux == depth_aux.prev * 2
            // for row at the beginning, depth_aux must be 1/2
            // for row at the beginning, acc_key must be 0
            // for row not beginning, acc_key is path * depth_aux + acc_key_prev
            vec![
                enable.clone() * s_begin.clone() * depth_aux_start,
                enable.clone()
                    * (Expression::Constant(Fp::one()) - s_begin.clone())
                    * depth_aux_common,
                enable.clone() * s_begin.clone() * meta.query_advice(acc_key, Rotation::cur()),
                enable * (Expression::Constant(Fp::one()) - s_begin) * key_acc,
            ]
        });

        meta.lookup_any("mpt key pre calc", |meta| {
            let s_leaf = meta.query_advice(s_enable, Rotation::cur())
                * meta.query_advice(s_ctrl_type[HashType::Leaf as usize], Rotation::cur()); //Leaf

            let key = meta.query_advice(acc_key, Rotation::cur());
            let key_immediate = meta.query_advice(key_aux, Rotation::cur());
            hash_table.build_lookup(
                meta,
                s_leaf,
                Expression::Constant(Fp::one()),
                key,
                key_immediate,
            )
        });

        OpChipConfig {
            ctrl_type,
            s_ctrl_type,
            path,
            sibling,
            depth: depth_aux,
            acc_key,
            key_aux,
        }
    }

    fn construct(
        config: OpChipConfig,
        offset: usize,
        data: &'d <Self as Chip<Fp>>::Loaded,
    ) -> Self {
        Self {
            config,
            offset,
            data,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;
        let paths = &self.data.path;
        let siblings = &self.data.siblings;
        assert_eq!(paths.len(), siblings.len());
        let ctrl_type = self.data.ctrl_type();
        let mut offset = self.offset;
        region.assign_advice(
            || "path padding",
            config.path,
            offset,
            || Value::known(Fp::zero()),
        )?;
        region.assign_advice(
            || "acckey padding",
            config.acc_key,
            offset,
            || Value::known(Fp::zero()),
        )?;
        region.assign_advice(
            || "depth padding",
            config.depth,
            offset,
            || Value::known(Fp::one().double().invert().unwrap()),
        )?;
        region.assign_advice(
            || "sibling padding",
            config.sibling,
            offset,
            || Value::known(Fp::zero()),
        )?;
        region.assign_advice(
            || "op type start",
            config.ctrl_type,
            offset,
            || Value::known(Fp::from(ctrl_type[0] as u64)),
        )?;
        region.assign_advice(
            || "enabling s_op",
            config.s_ctrl_type[ctrl_type[0] as usize],
            offset,
            || Value::known(Fp::one()),
        )?;

        region.assign_advice(
            || "sibling padding",
            config.sibling,
            offset,
            || Value::known(Fp::zero()),
        )?;

        offset += 1;

        let mut cur_depth = Fp::one();
        let mut acc_key = Fp::zero();

        let extend_proof = self.data.extended_proof();

        for (index, (path, sibling)) in paths.iter().zip(siblings.iter()).enumerate() {
            acc_key = *path * cur_depth + acc_key;

            region.assign_advice(|| "path", config.path, offset, || Value::known(*path))?;
            region.assign_advice(
                || "acckey",
                config.acc_key,
                offset,
                || Value::known(acc_key),
            )?;
            region.assign_advice(|| "depth", config.depth, offset, || Value::known(cur_depth))?;
            region.assign_advice(
                || "sibling",
                config.sibling,
                offset,
                || Value::known(*sibling),
            )?;
            // currently we simply fill key_aux col with extend_proof (if any)
            region.assign_advice(
                || "ext proof key immediate",
                config.key_aux,
                offset,
                || Value::known(extend_proof.map(|pf| pf.1).unwrap_or_default()),
            )?;
            region.assign_advice(
                || "ctrl type",
                config.ctrl_type,
                offset,
                || Value::known(Fp::from(ctrl_type[index + 1] as u64)),
            )?;
            region.assign_advice(
                || "enabling s_op",
                config.s_ctrl_type[ctrl_type[index + 1] as usize],
                offset,
                || Value::known(Fp::one()),
            )?;

            cur_depth = cur_depth.double();
            offset += 1;
        }

        // final line
        let ctrl_type = *ctrl_type.last().expect("always has at least 2 rows");
        region.assign_advice(
            || "op type",
            config.ctrl_type,
            offset,
            || Value::known(Fp::from(ctrl_type as u64)),
        )?;
        region.assign_advice(
            || "enabling s_op",
            config.s_ctrl_type[ctrl_type as usize],
            offset,
            || Value::known(Fp::one()),
        )?;
        region.assign_advice(
            || "path",
            config.path,
            offset,
            || Value::known(self.data.key_residual),
        )?;
        region.assign_advice(
            || "key final",
            config.acc_key,
            offset,
            || Value::known(self.data.key),
        )?;
        region.assign_advice(
            || "key hash aux: immediate",
            config.key_aux,
            offset,
            || Value::known(self.data.key_immediate),
        )?;
        region.assign_advice(|| "depth", config.depth, offset, || Value::known(cur_depth))?;
        region.assign_advice(
            || "sibling last (key for extended or padding)",
            config.sibling,
            offset,
            || Value::known(extend_proof.map(|pf| pf.0).unwrap_or_default()),
        )?;

        Ok(offset + 1)
    }
}

/// chip for verify mutiple merkle path in MPT
/// it do not need any auxiliary cols
struct OpChip<'d, F: FieldExt> {
    offset: usize,
    config: OpChipConfig,
    data: &'d SingleOp<F>,
}

#[derive(Clone, Debug)]
struct MPTOpConfig {
    s_row: Selector,
    s_enable: Column<Advice>,
    s_path: Column<Advice>,
    depth: Column<Advice>,
    ctrl_type: Column<Advice>,
    s_ctrl_type: [Column<Advice>; HASH_TYPE_CNT],
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    s_hash_match_ctrl: [Column<Advice>; 2], //[old, new]
    s_hash_match_ctrl_aux: [Column<Advice>; 2],
    sibling: Column<Advice>,
    acc_key: Column<Advice>,
    path: Column<Advice>,
    old_val: Column<Advice>,
    new_val: Column<Advice>,
    key_aux: Column<Advice>,

    hash_table: HashTable,
    tables: MPTOpTables,
}

#[derive(Clone, Debug)]
pub(crate) struct MPTOpGadget {
    op: OpChipConfig,
    old_path: PathChipConfig,
    new_path: PathChipConfig,
    s_enable: Column<Advice>,

    pub hash_table: HashTable,
    pub tables: MPTOpTables,
}

impl MPTOpGadget {
    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 4 (MUST by following sequence: layout_flag, s_enable,
    /// old_val, new_val) + s_op_flags * 6 (corresponding 6 ctrl_types)
    /// + free col * 8
    /// notice the gadget has bi-direction exporting (on top it exporting mpt
    /// root and bottom exporting leaf)
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
        free: &[Column<Advice>],
        root_index: Option<(Column<Advice>, Column<Advice>)>,
        tables: MPTOpTables,
        hash_tbl: HashTable,
    ) -> Self {
        assert!(free.len() >= 8, "require at least 8 free cols");

        let g_config = MPTOpConfig {
            tables,
            s_row: sel,
            s_path: free[0],
            depth: free[1],
            new_hash_type: free[2],
            old_hash_type: free[3],
            sibling: free[4],
            path: free[5],
            key_aux: free[6],
            s_hash_match_ctrl: [free[7], free[8]],
            s_hash_match_ctrl_aux: [free[9], free[10]],
            ctrl_type: exported[0],
            s_enable: exported[1],
            old_val: exported[2],
            new_val: exported[3],
            acc_key: exported[4],
            s_ctrl_type: s_ctrl_type[0..6].try_into().expect("same size"),
            hash_table: hash_tbl,
        };

        meta.create_gate("flag boolean", |meta| {
            let s_row = meta.query_selector(g_config.s_row);
            let s_enable = meta.query_advice(g_config.s_enable, Rotation::cur());
            // s_enable ∈ {0, 1}
            vec![s_row * (Expression::Constant(Fp::one()) - s_enable.clone()) * s_enable]
        });

        if let Some((old_root_index, new_root_index)) = root_index {
            meta.create_gate("root index", |meta| {
                let s_row = meta.query_selector(g_config.s_row);
                let s_enable = s_row
                    * meta.query_advice(g_config.s_enable, Rotation::cur())
                    * meta.query_advice(
                        g_config.s_ctrl_type[HashType::Start as usize],
                        Rotation::cur(),
                    );
                // constraint root index:
                // the old root in heading row (START) equal to the new_root_index_prev
                // the old root in heading row (START) also equal to the old_root_index_cur
                // the new root in heading row (START) equal must be equal to new_root_index_cur
                vec![
                    s_enable.clone()
                        * (meta.query_advice(g_config.old_val, Rotation::cur())
                            - meta.query_advice(new_root_index, Rotation::prev())),
                    s_enable.clone()
                        * (meta.query_advice(g_config.old_val, Rotation::cur())
                            - meta.query_advice(old_root_index, Rotation::cur())),
                    s_enable
                        * (meta.query_advice(g_config.new_val, Rotation::cur())
                            - meta.query_advice(new_root_index, Rotation::cur())),
                ]
            });
        }

        Self {
            s_enable: g_config.s_enable,
            op: OpChip::<Fp>::configure(meta, &g_config),
            old_path: PathChip::<Fp>::configure(meta, &g_config, true),
            new_path: PathChip::<Fp>::configure(meta, &g_config, false),
            hash_table: g_config.hash_table.clone(),
            tables: g_config.tables.clone(),
        }
    }
}
