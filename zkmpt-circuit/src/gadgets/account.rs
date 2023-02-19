use halo2_proofs::{
    circuit::{Chip, Region, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Selector, Error},
    poly::Rotation,
};

use crate::{operation::Account, state_trie::HashTable};

pub const CIRCUIT_ROW: usize = 4;
const LAST_ROW: usize = CIRCUIT_ROW - 1;

#[derive(Clone, Debug)]
pub(crate) struct AccountGadget {}

impl AccountGadget {}

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
        hash_table: HashTable,
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
                [data.nonce, data.gas_balance, data.tx_hash.0],
                "data field",
            ),
            (
                config.acc_data_fields_ext,
                [Fp::zero(), Fp::zero(), data.tx_hash.1],
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
