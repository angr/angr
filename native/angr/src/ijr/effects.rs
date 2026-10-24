//! Side effects a Rust resolver has on the CFG, applied by the dispatcher when the resolver returns `Done` (which is
//! when a Python resolver would have made them).

use pyo3::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// `cfg._seg_list.occupy(addr, size, sort)`.
    SegOccupy { addr: u64, size: u64, sort: &'static str },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Effects(pub Vec<Effect>);

impl Effects {
    pub fn push(&mut self, e: Effect) {
        self.0.push(e);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn apply(&self, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        if self.0.is_empty() {
            return Ok(());
        }
        let py = cfg.py();
        for e in &self.0 {
            match e {
                Effect::SegOccupy { addr, size, sort } => {
                    cfg.getattr(pyo3::intern!(py, "_seg_list"))?
                        .call_method1(pyo3::intern!(py, "occupy"), (*addr, *size, *sort))?;
                }
            }
        }
        Ok(())
    }
}
