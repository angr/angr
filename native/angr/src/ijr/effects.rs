//! Side effects a Rust resolver has on the CFG, applied by the dispatcher when the resolver returns `Done` (which is
//! when a Python resolver would have made them).

use pyo3::prelude::*;

/// A `JumptableInfo`.
#[derive(Clone, Debug, PartialEq)]
pub struct JtInfo {
    pub addr: u64,
    pub size: u64,
    pub entry_size: u64,
    pub entries: Vec<u64>,
    pub primary: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// `cfg._seg_list.occupy(addr, size, sort)`.
    SegOccupy {
        addr: u64,
        size: u64,
        sort: &'static str,
    },
    /// JumpTableResolver's write to `cfg.indirect_jumps[addr]` for a resolved table.
    IjJumptable {
        addr: u64,
        jumptable: bool,
        resolved_targets: Vec<u64>,
        tables: Vec<JtInfo>,
    },
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
                Effect::IjJumptable {
                    addr,
                    jumptable,
                    resolved_targets,
                    tables,
                } => {
                    let ij = cfg
                        .getattr(pyo3::intern!(py, "indirect_jumps"))?
                        .call_method1(pyo3::intern!(py, "get"), (*addr,))?;
                    if ij.is_none() {
                        continue;
                    }
                    ij.setattr(pyo3::intern!(py, "jumptable"), *jumptable)?;
                    for t in tables {
                        let kw = pyo3::types::PyDict::new(py);
                        kw.set_item(pyo3::intern!(py, "is_primary"), t.primary)?;
                        ij.call_method(
                            pyo3::intern!(py, "add_jumptable"),
                            (t.addr, t.size, t.entry_size, t.entries.clone()),
                            Some(&kw),
                        )?;
                    }
                    let targets = pyo3::types::PySet::new(py, resolved_targets)?;
                    ij.setattr(pyo3::intern!(py, "resolved_targets"), targets)?;
                    if *jumptable {
                        // IndirectJumpType.Jumptable_AddressLoadedFromMemory
                        ij.setattr(pyo3::intern!(py, "type"), 0)?;
                    }
                }
            }
        }
        Ok(())
    }
}
