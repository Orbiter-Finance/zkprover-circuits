use halo2_proofs::{plonk::{TableColumn, ConstraintSystem, Expression, Error}, arithmetic::Field, halo2curves::FieldExt, circuit::{Layouter, Value}};


// we lookup the transition of ctrl type from the preset table, and different kind of rules
// is specified here
pub(crate) enum CtrlTransitionKind {
    Mpt = 1,        // transition in MPT circuit
    Account,        // transition in account circuit
    Operation = 99, // transition of the old state to new state in MPT circuit
}


#[derive(Clone, Debug)]
pub(crate) struct MPTOpTables(
    TableColumn,      // op mark
    [TableColumn; 3], // op rules
);


impl MPTOpTables {
    pub fn configure_create<Fp: Field>(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self(
            meta.lookup_table_column(),
            [0; 3].map(|_| meta.lookup_table_column()),
        )
    }

    pub fn build_lookup_any<Fp: FieldExt>(
        &self,
        enable: Expression<Fp>,
        rules: impl IntoIterator<Item = Expression<Fp>>,
        mark: u64,
    ) -> Vec<(Expression<Fp>, TableColumn)> {
        let mut ret: Vec<_> = rules
            .into_iter()
            .map(|exp| enable.clone() * exp)
            .zip(self.1)
            .collect();
        ret.push((enable * Expression::Constant(Fp::from(mark)), self.0));
        ret
    }

    pub fn build_lookup<Fp: FieldExt>(
        &self,
        enable: Expression<Fp>,
        old: Expression<Fp>,
        new: Expression<Fp>,
        mark: u64,
    ) -> Vec<(Expression<Fp>, TableColumn)> {
        self.build_lookup_any(enable, [old, new], mark)
    }

    pub fn fill_constant<Fp: FieldExt>(
        &self,
        layouter: &mut impl Layouter<Fp>,
        rules: impl Iterator<Item = ([u32; 3], u32)> + Clone,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "op table",
            |mut table| {
                // default line
                table.assign_cell(|| "default mark", self.0, 0, || Value::known(Fp::zero()))?;
                for i in 0..3 {
                    table.assign_cell(
                        || "default rule",
                        self.1[i],
                        0,
                        || Value::known(Fp::zero()),
                    )?;
                }

                for (offset, (items, mark)) in rules.clone().enumerate() {
                    let offset = offset + 1;
                    for (rule, col) in items.into_iter().zip(self.1) {
                        table.assign_cell(
                            || "rule item",
                            col,
                            offset,
                            || Value::known(Fp::from(rule as u64)),
                        )?;
                    }

                    table.assign_cell(
                        || "mark",
                        self.0,
                        offset,
                        || Value::known(Fp::from(mark as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}