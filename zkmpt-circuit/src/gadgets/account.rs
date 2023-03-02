use halo2_proofs::{
    circuit::{Chip, Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Selector, Error, Expression},
    poly::Rotation,
};

use crate::{operation::Account};

use super::{hash_util, table_util::CtrlTransitionKind, kv_util::KeyValue};
use super::table_util;

pub const CIRCUIT_ROW: usize = 4;
const LAST_ROW: usize = CIRCUIT_ROW - 1;
use lazy_static::lazy_static;

lazy_static! {
    static ref TRANSMAP: Vec<(u32, u32)> = {
        let mut ret: Vec<_> = (0..LAST_ROW).map(|s| (s as u32, (s + 1) as u32)).collect();
        ret.push((0, 0));
        ret
    };
}

#[derive(Clone, Debug)]
pub(crate) struct AccountGadget {
    old_state: AccountChipConfig,
    new_state: AccountChipConfig,

    s_enable: Column<Advice>,
    ctrl_type: Column<Advice>,
    s_ctrl_type: [Column<Advice>; 4],

    state_change_key: Column<Advice>,
    state_change_aux: [Column<Advice>; 2],

}

impl AccountGadget {
    pub fn min_free_cols() -> usize {
        6
    }

    pub fn min_ctrl_types() -> usize {
        4
    }

    pub fn transition_rules() -> impl Iterator<Item = ([u32; 3], u32)> + Clone {
        TRANSMAP
            .iter()
            .copied()
            .map(|(a, b)| ([a, b, 0], CtrlTransitionKind::Account as u32))
    }


    /// create gadget from assigned cols, we need:
    /// + circuit selector * 1
    /// + exported col * 8 (MUST by following sequence: layout_flag, s_enable, old_val, new_val, key_val and 3 ext field for old/new/key_val)
    /// + free col * 4
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
        free: &[Column<Advice>],
        address_index: Option<Column<Advice>>,
        tables: table_util::MPTOpTables,
        hash_tbl: hash_util::HashTable,
    ) -> Self {
        assert!(free.len() >= 4, "require at least 4 free cols");
        let s_enable = exported[1];
        let ctrl_type = exported[0];
        let data_old = exported[2];
        let data_new = exported[3];
        let data_key = exported[4]; //the mpt gadget above it use the col as 'data key'
        let state_change_key = data_key; //while we use it as 'state_change_key'
        let data_old_ext = exported[5];
        let data_new_ext = exported[6];
        let s_ctrl_type = s_ctrl_type[0..4].try_into().expect("same size");

        let old_state = AccountChip::configure(
            meta,
            sel,
            s_enable,
            s_ctrl_type,
            data_old,
            data_old_ext,
            &free[0..2],
            hash_tbl.clone(),
        );

        let new_state = AccountChip::configure(
            meta,
            sel,
            s_enable,
            s_ctrl_type,
            data_new,
            data_new_ext,
            &free[2..4],
            hash_tbl.clone(),
        );

        let state_change_aux: [Column<Advice>; 2] = free[4..6].try_into().expect("size specified");

        // transition
        meta.lookup("account row trans", |meta| {
            let s_enable = meta.query_advice(s_enable, Rotation::cur())
                * (Expression::Constant(Fp::one()))
                    - meta.query_advice(s_ctrl_type[0], Rotation::cur());
            tables.build_lookup(
                s_enable, 
                meta.query_advice(ctrl_type, Rotation::prev()), 
                meta.query_advice(ctrl_type, Rotation::cur()), 
                table_util::CtrlTransitionKind::Account as u64,
            )
        });

        // ???
        if let Some(address_index) = address_index {
            meta.create_gate("address constraint", |meta| {
                let s_enable =
                    meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
                let row0 = meta.query_advice(s_ctrl_type[0], Rotation::cur());
                let address_limb_0 = meta.query_advice(old_state.intermediate_1, Rotation::cur());
                let address_limb_1 = meta.query_advice(new_state.intermediate_1, Rotation::cur());

                vec![
                    s_enable
                        * row0
                        * (address_limb_0 * Expression::Constant(Fp::from(0x100000000u64))
                            + address_limb_1
                                * Expression::Constant(
                                    Fp::from_u128(0x1000000000000000000000000u128)
                                        .invert()
                                        .unwrap(),
                                )
                            - meta.query_advice(address_index, Rotation::cur())),
                ]
            });
            meta.lookup_any("address hash", |meta| {
                let s_enable = meta.query_advice(s_enable, Rotation::cur())
                    * meta.query_advice(s_ctrl_type[0], Rotation::cur());

                let address_limb_0 = meta.query_advice(old_state.intermediate_1, Rotation::cur());
                let address_limb_1 = meta.query_advice(new_state.intermediate_1, Rotation::cur());
                let addr_hash = meta.query_advice(data_key, Rotation::prev());

                hash_tbl.build_lookup(meta, s_enable, address_limb_0, address_limb_1, addr_hash)
            });
        }

        // this gate constraint each gadget handle at most one change in account data
        meta.create_gate("single update for account data", |meta| {
            let enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let data_diff = meta.query_advice(data_old, Rotation::cur())
                - meta.query_advice(data_new, Rotation::cur());
            let data_ext_diff = meta.query_advice(data_old_ext, Rotation::cur())
                - meta.query_advice(data_new_ext, Rotation::cur());

            let is_diff_boolean =
                data_diff.clone() * meta.query_advice(state_change_aux[0], Rotation::cur());
            let is_diff_ext_boolean =
                data_ext_diff.clone() * meta.query_advice(state_change_aux[1], Rotation::cur());

            let one = Expression::Constant(Fp::one());
            // switch A || B to ! (!A ^ !B)
            let has_diff = one.clone()
                - (one.clone() - is_diff_boolean.clone())
                    * (one.clone() - is_diff_ext_boolean.clone());
            let diff_acc = has_diff
                + meta.query_advice(s_enable, Rotation::prev())
                    * meta.query_advice(state_change_key, Rotation::prev());
            let state_change_key = meta.query_advice(state_change_key, Rotation::cur());

            vec![
                enable.clone() * data_diff * (one.clone() - is_diff_boolean),
                enable.clone() * data_ext_diff * (one.clone() - is_diff_ext_boolean),
                enable.clone() * (state_change_key.clone() - diff_acc),
                enable * state_change_key.clone() * (one - state_change_key),
            ]
        });

        // constrain new_nonce = old_nonce + 1
        meta.create_gate("nonce constraint", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let old_nonce = Expression::Constant(Fp::zero());
            let new_nonce = Expression::Constant(Fp::one());
            vec![
                s_enable.clone() 
                    * ((new_nonce.clone() - old_nonce.clone())) 
                    * (new_nonce - old_nonce - Expression::Constant(Fp::one()))
            ]
        });

        // constrain 

        // constraint padding row
        meta.create_gate("padding row", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let row3 = meta.query_advice(s_ctrl_type[3], Rotation::cur());
            let old_root = meta.query_advice(data_old, Rotation::cur());
            let new_root = meta.query_advice(data_new, Rotation::cur());

            vec![s_enable * row3 * (new_root - old_root)]
        });


        Self {
            s_enable,
            ctrl_type,
            s_ctrl_type,
            old_state,
            new_state,
            state_change_key,
            state_change_aux,
        }
    }

    /// assign data and enable flag for account circuit
    pub fn assign<'d, Fp:FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        data: (&'d Account<Fp>, &'d Account<Fp>),
        address: KeyValue<Fp>,
        apply_last_row: Option<bool>
    ) -> Result<usize, Error> {
        let old_acc_chip = AccountChip::<Fp> {
            offset,
            config: &self.old_state,
            data: data.0,
        };

        let new_acc_chip = AccountChip::<Fp> {
            offset,
            config: &self.new_state,
            data: data.1,
        };

        let apply_last_row = if let Some(apply) = apply_last_row {
            if apply {
                assert_eq!(data.0.state_root, data.1.state_root);
            }
            apply
        } else {
            data.0.state_root == data.1.state_root
        };

        let end_offset = offset + CIRCUIT_ROW - if apply_last_row {0} else {1};

        old_acc_chip.assign(region)?;
        new_acc_chip.assign(region)?;

         // overwrite the datalimb in first row for address
        for (col, val) in [
            (old_acc_chip.config.intermediate_1, address.limb_0()),
            (new_acc_chip.config.intermediate_1, address.limb_1()),
        ] {
            region.assign_advice(|| "address assignment", col, offset, || Value::known(val))?;
        }

        let mut has_data_delta = false;
        for (index, offset) in (offset..end_offset).enumerate() {
            region.assign_advice(
                || "enable account circuit",
                self.s_enable,
                offset,
                || Value::known(Fp::one()),
            )?;
            region.assign_advice(
                || "account circuit rows", 
                self.ctrl_type, offset, 
                || Value::known(Fp::from(index as u64))
            )?;
            region.assign_advice(
                ||"enable s_ctrl", 
                self.s_ctrl_type[index], 
                offset, 
                || Value::known(Fp::zero()),
            )?;
            if index == LAST_ROW {
                region.assign_advice(
                    || "padding last row", 
                    self.old_state.intermediate_2, 
                    offset, 
                    ||Value::known(Fp::zero()),
                )?;
                region.assign_advice(
                    || "padding last row",
                    self.new_state.intermediate_2,
                    offset,
                    || Value::known(Fp::zero()),
                )?;
            }
            let data_delta = match index {
                0 => [data.0.nonce - data.1.nonce, Fp::zero()],
                1 => [data.0.gas_balance - data.1.gas_balance, Fp::zero()],
                2 => [data.0.recrusive_tx_hash - data.1.recrusive_tx_hash, Fp::zero()],
                3 => [data.0.state_root - data.1.state_root, Fp::zero()],
                _ => unreachable!("no such row number"),
            };

            if !has_data_delta {
                has_data_delta =
                    !(bool::from(data_delta[0].is_zero()) && bool::from(data_delta[1].is_zero()));
            }

            for (col, val) in self.state_change_aux.iter().zip(data_delta) {
                region.assign_advice(
                    || "data delta",
                    *col,
                    offset,
                    || {
                        Value::known(if bool::from(val.is_zero()) {
                            Fp::zero()
                        } else {
                            val.invert().unwrap()
                        })
                    },
                )?;
            }

            region.assign_advice(
                || "is data delta",
                self.state_change_key,
                offset,
                || {
                    Value::known(if has_data_delta {
                        Fp::one()
                    } else {
                        Fp::zero()
                    })
                },
            )?;

        }

        Ok(end_offset)

    }
}

#[derive(Clone, Debug)]
struct AccountChipConfig {
    intermediate_1: Column<Advice>,
    intermediate_2: Column<Advice>,
    acc_data_fields: Column<Advice>,
    acc_data_fields_ext: Column<Advice>, // for accommodate codehash's low field
}

struct AccountChip<'d, F> {
    offset: usize,
    config: &'d AccountChipConfig,
    data: &'d Account<F>,
}

impl<Fp: FieldExt> Chip<Fp> for AccountChip<'_, Fp> {
    type Config = AccountChipConfig;
    type Loaded = Account<Fp>;

    fn config(&self) -> &Self::Config {
        self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

impl<'d, Fp: FieldExt> AccountChip<'d, Fp> {
    fn lagrange_polynomial_for_row() {}

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        sel: Selector,
        s_enable: Column<Advice>,
        s_ctrl_type: [Column<Advice>; 4],
        acc_data_fields: Column<Advice>,
        acc_data_fields_ext: Column<Advice>,
        free_cols: &[Column<Advice>],
        hash_table: hash_util::HashTable,
    ) -> <Self as Chip<Fp>>::Config {
        let intermediate_1 = free_cols[0];
        let intermediate_2 = free_cols[1];

        // first hash lookup (Poseidon(TxHash_firts, TxHash_second) = hash1)
        meta.lookup_any("account hash1 calc", |meta| {
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let enable_rows = meta.query_advice(s_ctrl_type[2], Rotation::cur());
            let enable = enable_rows * s_enable;
            let fst = meta.query_advice(acc_data_fields, Rotation::cur());
            let snd = meta.query_advice(acc_data_fields_ext, Rotation::cur());
            let hash = meta.query_advice(intermediate_1, Rotation::cur());

            hash_table.build_lookup(meta, enable, fst, snd, hash)
        });

        // second hash lookup Poseidon(hash1, Root) = Hash2, Poseidon(hash3, hash2) =
        // hash_final
        meta.lookup_any("account hash2 and hash_final calc", |meta| {
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let enable_rows = meta.query_advice(s_ctrl_type[1], Rotation::cur())
                + meta.query_advice(s_ctrl_type[2], Rotation::cur());
            let enable = enable_rows * s_enable;
            let fst = meta.query_advice(intermediate_1, Rotation::cur());
            let snd = meta.query_advice(intermediate_2, Rotation::cur());
            let hash = meta.query_advice(intermediate_2, Rotation::cur());
            hash_table.build_lookup(meta, enable, fst, snd, hash)
        });

        // third hash lookup (Poseidon(nonce, balance) = hash3)
        meta.lookup_any("account hash3 calc", |meta| {
            // only enable on row 1
            let s_enable = meta.query_advice(s_enable, Rotation::cur());
            let enable_rows = meta.query_advice(s_ctrl_type[1], Rotation::cur());
            let enable = enable_rows * s_enable;

            let fst = meta.query_advice(acc_data_fields, Rotation::prev());
            let snd = meta.query_advice(acc_data_fields, Rotation::cur());
            let hash = meta.query_advice(intermediate_1, Rotation::cur());

            hash_table.build_lookup(meta, enable, fst, snd, hash)
        });

        // equality constraint: hash_final and Root
        meta.create_gate("account calc equalities", |meta| {
            let s_enable = meta.query_selector(sel) * meta.query_advice(s_enable, Rotation::cur());
            let exported_equal1 = meta.query_advice(intermediate_2, Rotation::cur())
                - meta.query_advice(acc_data_fields, Rotation::prev());
            let exported_equal2 = meta.query_advice(intermediate_2, Rotation::cur())
                - meta.query_advice(acc_data_fields, Rotation::next());

            // equalities in the circuit
            vec![
                s_enable.clone()
                    * meta.query_advice(s_ctrl_type[0], Rotation::cur())
                    * exported_equal1, // equality of hash_final
                s_enable * meta.query_advice(s_ctrl_type[2], Rotation::cur()) * exported_equal2, // equality of state trie root
            ]
        });

        AccountChipConfig {
            acc_data_fields,
            acc_data_fields_ext,
            intermediate_1,
            intermediate_2,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = self.config();
        let data = self.loaded();
        // fill the connected circuit
        let offset = self.offset - 1;
        region.assign_advice(
            || "account hash final", 
            config.acc_data_fields, 
            offset, 
            || Value::known(data.account_hash()),
        )?;

        // fill the main block of chip
        for (col, vals, desc) in [
            (
                config.acc_data_fields,
                [data.nonce, data.gas_balance, data.tx_hash],
                "data field",
            ),
            (
                config.acc_data_fields_ext,
                [Fp::zero(), Fp::zero(), data.tx_hash],
                "data field ext",
            ),
            (
                config.intermediate_2,
                [data.account_hash(), data.hash_traces(1), data.state_root],
                "intermediate 2",
            ),
            (
                config.intermediate_1,
                [Fp::zero(), data.hash_traces(2), data.hash_traces(0)],
                "intermediate 1",
            )
        ] {
            for (i, val) in vals.iter().enumerate() {
                region.assign_advice(
                    || format!("{} row {} (offset {})", desc, i, self.offset),
                    col,
                    self.offset + i,
                    || Value::known(*val),
                )?;
            }
         }

        // row 4: notice this is not belong to account chip in general
        region.assign_advice(
            || "state root",
            config.acc_data_fields,
            self.offset + LAST_ROW,
            || Value::known(self.data.state_root),
        )?;

        region.assign_advice(
            || "state root padding",
            config.acc_data_fields_ext,
            self.offset + LAST_ROW,
            || Value::known(Fp::zero()),
        )?;

        Ok(self.offset + LAST_ROW)
    }
}


#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use halo2_proofs::circuit::{SimpleFloorPlanner, Layouter, Value};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{Circuit, Selector, Advice, Column, ConstraintSystem, Error};
    use hash_circuit::Hashable;

    use crate::gadgets::{table_util, hash_util};
    use crate::operation::Account;

    use crate::test_utils::{rand_fp, mock_hash, hash_str_to_fp};
    use crate::{test_utils::Fp};

    use super::{AccountGadget, CIRCUIT_ROW};

    #[derive(Clone, Debug)]
    struct AccountTestConfig {
        gadget: AccountGadget,
        sel: Selector,
        free_cols: [Column<Advice>; 14],
        s_ctrl_cols: [Column<Advice>; 4],
        op_tabl: table_util::MPTOpTables,
        hash_tabl: hash_util::HashTable,
    }

    // express for a single path block
    #[derive(Clone, Default)]
    struct AccountTestCircuit {
        data: (Account<Fp>, Account<Fp>),
    }

    impl Circuit<Fp> for AccountTestCircuit {
        type Config = AccountTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let sel = meta.selector();
            let free_cols = [(); 14].map(|_| meta.advice_column());
            let s_ctrl_cols = [(); 4].map(|_| meta.advice_column());
            let exported_cols = [
                free_cols[0],
                free_cols[1],
                free_cols[2],
                free_cols[3],
                free_cols[4],
                free_cols[5],
                free_cols[6],
                free_cols[7],
            ];
            let op_tabl = table_util::MPTOpTables::configure_create(meta);
            let hash_tabl = hash_util::HashTable::configure_create(meta);

            let gadget = AccountGadget::configure(
                meta,
                sel,
                exported_cols.as_slice(),
                s_ctrl_cols.as_slice(),
                &free_cols[8..],
                None,
                op_tabl.clone(),
                hash_tabl.clone(),
            );

            AccountTestConfig {
                gadget,
                sel,
                free_cols,
                s_ctrl_cols,
                op_tabl,
                hash_tabl,
            }
        }

        fn synthesize(
            &self, 
            config: Self::Config, 
            mut layouter: impl Layouter<Fp>
        ) -> Result<(), Error> {
            // initialize the op table
            config
                .op_tabl
                .fill_constant(&mut layouter, AccountGadget::transition_rules())?;

            config.hash_tabl.dev_fill(
                &mut layouter,
                self.data
                    .0
                    .hash_traces
                    .iter()
                    .chain(self.data.1.hash_traces.iter()),
            )?;

            layouter.assign_region(
                || "account",
                |mut region | {
                    for col in config.free_cols {
                        region.assign_advice(
                            || "flush top row",
                            col,
                            0,
                            || Value::known(Fp::zero()),
                        )?;
                    }

                    for offset in 1..=CIRCUIT_ROW {
                        for col in config.s_ctrl_cols {
                            region.assign_advice(
                                || "flush s_ctrl",
                                col,
                                offset,
                                || Value::known(Fp::zero()),
                            )?;
                        }
                    }

                    let till = config.gadget.assign(
                        &mut region,
                        1,
                        (&self.data.0, &self.data.1),
                        Default::default(),
                        None,
                    )?;
                    for offset in 1..till {
                        config.sel.enable(&mut region, offset)?;
                    }
                    for col in config.free_cols {
                        region.assign_advice(
                            || "flush last row",
                            col,
                            till,
                            || Value::known(Fp::zero()),
                        )?;
                    }
                    Ok(())
                },
            )
        }

        
    }

    #[test]
    fn test_single_account(){
        let acc_data = Account::<Fp> {
            gas_balance: Fp::from(100000u64),
            address: hash_str_to_fp("0x1c5a77d9fa7ef466951b2f01f724bca3a5820b63"),
            account_key: hash_str_to_fp("0x0178efc3d95dd411bac18637d49d8d2fd35f9f5f6e0dac461a8b5e31914f85a8"),
            nonce: Fp::from(42u64),
            state_root: rand_fp(),
            ..Default::default()
        };

        let old_acc_data = Account::<Fp> {
            nonce: Fp::from(41u64),
            ..acc_data.clone()
        };

        let acc_data = acc_data.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));
        let old_acc_data = old_acc_data.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));

        let circuit = AccountTestCircuit {
            data: (old_acc_data, acc_data),
        };

        let k = 5;
        #[cfg(feature = "print_layout")]
        print_layout!("layouts/accgadget_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}