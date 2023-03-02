use halo2_proofs::{plonk::{Column, Advice, ConstraintSystem, Selector, Error}, halo2curves::FieldExt, circuit::{Region, Value}};

// padding gadget keep start and end root identical, it often act as the "terminal" circuit to fill the rest space
// in the region, it has only one ctrl type equal to 0,
#[derive(Clone, Debug)]
pub(crate) struct PaddingGadget {
    s_enable: Column<Advice>,
    ctrl_type: Column<Advice>,
    s_ctrl_type: Column<Advice>,
}

impl PaddingGadget {
    pub fn configure<Fp: FieldExt>(
        _meta: &mut ConstraintSystem<Fp>,
        _sel: Selector,
        exported: &[Column<Advice>],
        s_ctrl_type: &[Column<Advice>],
    ) -> Self {
        Self {
            ctrl_type: exported[0],
            s_enable: exported[1],
            s_ctrl_type: s_ctrl_type[0],
        }
    }

    pub fn padding<Fp: FieldExt>(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        rows: usize,
    ) -> Result<(), Error> {
        for offset in offset..(offset + rows) {
            region.assign_advice(
                || "ctrl type",
                self.ctrl_type,
                offset,
                || Value::known(Fp::zero()),
            )?;
            region.assign_advice(
                || "enable s_ctrl",
                self.s_ctrl_type,
                offset,
                || Value::known(Fp::one()),
            )?;
            region.assign_advice(
                || "enable padding",
                self.s_enable,
                offset,
                || Value::known(Fp::one()),
            )?;
        }
        Ok(())
    }
}
