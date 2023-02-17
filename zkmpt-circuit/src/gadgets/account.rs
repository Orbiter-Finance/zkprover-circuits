use halo2_proofs::{
    circuit::Chip,
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Selector},
    poly::Rotation,
};

use crate::{operation::Account, state_trie::HashTable};

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

    fn assign() {}
}
