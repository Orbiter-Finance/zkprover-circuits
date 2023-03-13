use halo2_proofs::{plonk::{Selector, Advice, Column, ConstraintSystem, Expression, Error}, halo2curves::FieldExt, poly::Rotation, circuit::{Region, Value}};


#[derive(Clone, Debug)]
pub(crate) struct LayerGadget {
    sel: Selector,
    series: Column<Advice>,
    op_type: Column<Advice>,
    s_stepflags: Vec<Column<Advice>>,
    s_ctrl_type: Vec<Column<Advice>>,
    ctrl_type: Column<Advice>,
    data_0: Column<Advice>,
    data_1: Column<Advice>,
    data_2: Column<Advice>,
    data_0_ext: Column<Advice>,
    data_2_ext: Column<Advice>,
    data_1_ext: Column<Advice>,
    free_cols: Vec<Column<Advice>>,
    old_root_index: Column<Advice>,
    new_root_index: Column<Advice>,
    address_index: Column<Advice>,
    op_delta_aux: Column<Advice>,
    control_table: [halo2_proofs::plonk::TableColumn; 5],
}

impl LayerGadget {

    pub fn exported_cols(&self, step: u32) -> [Column<Advice>; 8] {
        [
            self.ctrl_type,
            self.s_stepflags[step as usize],
            self.data_0,
            self.data_1,
            self.data_2,
            self.data_0_ext,
            self.data_1_ext,
            self.data_2_ext,
        ]
    }

    // obtain the index col for address value
    pub fn get_address_index(&self) -> Column<Advice> {
        self.address_index
    }

    pub fn get_ctrl_type_flags(&self) -> &[Column<Advice>] {
        &self.s_ctrl_type
    }

    pub fn get_free_cols(&self) -> &[Column<Advice>] {
        &self.free_cols
    }

    pub fn public_sel(&self) -> Selector {
        self.sel
    }

    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
        steps: usize,
        required_cols: usize,
        minium_ctrl_types: usize,
    ) -> Self {

        let s_stepflags: Vec<_> = (0..steps).map(|_| meta.advice_column()).collect();
        let free_cols: Vec<_> = (0..required_cols).map(|_| meta.advice_column()).collect();
        let s_ctrl_type: Vec<_> = (0..minium_ctrl_types)
            .map(|_| meta.advice_column())
            .collect();

        let sel = meta.complex_selector();
        let series = meta.advice_column();
        let op_type = meta.advice_column();
        let ctrl_type = meta.advice_column();
        let data_0 = meta.advice_column();
        let data_1 = meta.advice_column();
        let data_2 = meta.advice_column();
        let data_0_ext = meta.advice_column();
        let data_1_ext = meta.advice_column();
        let data_2_ext = meta.advice_column();
        let old_root_index = meta.advice_column();
        let new_root_index = meta.advice_column();
        let address_index = meta.advice_column();
        let op_delta_aux = meta.advice_column();
        let control_table = [(); 5].map(|_| meta.lookup_table_column());

        // require permutation with constants
        meta.enable_equality(series);

        meta.create_gate("series", |meta| {
            let sel = meta.query_selector(sel);
            let series_delta = meta.query_advice(series, Rotation::cur())
                - meta.query_advice(series, Rotation::prev());
            // delta ∈ {0, 1}
            vec![sel * (Expression::Constant(Fp::one()) - series_delta.clone()) * series_delta]
        });

        meta.create_gate("op transition", |meta| {
            let sel = meta.query_selector(sel);
            let op_delta = meta.query_advice(op_type, Rotation::cur())
                - meta.query_advice(op_type, Rotation::prev());
            let op_delta_aux = meta.query_advice(op_delta_aux, Rotation::cur());
            // map op_delta_aux so we can obtain 1 while delta is not zero
            // when pace_op, the op_delta_aux = op_delta.invert()
            vec![
                sel * (Expression::Constant(Fp::one()) - op_delta_aux * op_delta.clone())
                    * op_delta,
            ]
        });

        meta.create_gate("s_ctrl flags", |meta| {
            // TODO: not finish
            let sel = meta.query_selector(sel);
            vec![sel * Expression::Constant(Fp::zero())]
        });

        meta.create_gate("index identical", |meta| {
            // TODO: not finish
            let sel = meta.query_selector(sel);
            vec![sel * Expression::Constant(Fp::zero())]
        });

        meta.create_gate("flag", |meta| {
            // TODO: not finish
            let sel = meta.query_selector(sel);
            vec![sel * Expression::Constant(Fp::zero())]
        });

          // the main lookup for constrainting row layout
        // lookup opened under 2 conditions:
        // 1. series has zero-delta and op_type has non-zero delta
        // 2. series has non-zero-delta
        // under these condition the transition of op_type and ctrl_type would be
        // lookup from control_table
        meta.lookup("layer intra-block border rule", |meta| {
            // condition 1 (intra-block transition) is only actived when series has not change
            vec![
                (Expression::Constant(Fp::zero()), control_table[0]),
            ]
        });

        meta.lookup("layer intra-block border rule", |meta| {
            // condition 1 (intra-block transition) is only actived when series has not change
            vec![
                (Expression::Constant(Fp::zero()), control_table[0]),
            ]
        });


        Self {
            sel,
            series,
            s_stepflags,
            s_ctrl_type,
            op_type,
            ctrl_type,
            data_0,
            data_1,
            data_2,
            data_0_ext,
            data_1_ext,
            data_2_ext,
            free_cols,
            old_root_index,
            new_root_index,
            address_index,
            op_delta_aux,
            control_table,
        }
    }

    
    // an unique transition (start_op_code, 0) -> (<op type>, <ctrl type>) would be put in inter-op-block table
    // automatically to specify how the circuit starts
    pub fn start_op_code(&self) -> u32 {
        self.s_stepflags.len() as u32
    }
    // LayerGadget must be first assigned, with other gadgets start from the offset it has returned
    pub fn assign<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        max_rows: usize,
        init_root: Fp
    ) -> Result<usize, Error> {
         // current we flush the first row, and start other circuits's assignation from row 1
         self.free_cols.iter().try_for_each(|col| {
            region
                .assign_advice(|| "flushing", *col, 0, || Value::known(Fp::zero()))
                .map(|_| ())
         })?;
         self.s_stepflags.iter().try_for_each(|col| {
            region
                .assign_advice(|| "flushing", *col, 0, || Value::known(Fp::zero()))
                .map(|_| ())
         })?;

        region.assign_advice_from_constant(|| "init series", self.series, 0, Fp::zero())?;
        region.assign_advice_from_constant(|| "init series", self.series, 1, Fp::one())?;

        region.assign_advice_from_constant(
            || "init op",
            self.op_type,
            0,
            Fp::from(self.start_op_code() as u64),
        )?;
        region.assign_advice_from_constant(|| "init ctrl", self.ctrl_type, 0, Fp::zero())?;
        region.assign_advice(
            || "start root",
            self.new_root_index,
            0,
            || Value::known(init_root),
        )?;
        for col in [self.old_root_index, self.address_index] {
            region.assign_advice(|| "index flush", col, 0, || Value::known(Fp::zero()))?;
        }

        for offset in 1..max_rows {
            self.sel.enable(region, offset)?;
        }

        // flush one more row
        self.free_cols.iter().try_for_each(|col| {
            region
                .assign_advice(
                    || "flushing last",
                    *col,
                    max_rows,
                    || Value::known(Fp::zero()),
                )
                .map(|_| ())
        })?;
        // begin padding and final flush for data_rows
        for col in [self.data_0, self.data_1, self.data_2] {
            region.assign_advice(|| "begin padding", col, 0, || Value::known(Fp::zero()))?;

            region.assign_advice(
                || "last row flushing",
                col,
                max_rows,
                || Value::known(Fp::zero()),
            )?;
        }
        region.assign_advice(
            || "terminalte series",
            self.series,
            max_rows,
            || Value::known(Fp::zero()),
        )?;

        Ok(1)
    }
    
}