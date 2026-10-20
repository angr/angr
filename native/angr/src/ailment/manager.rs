//! Rust port of `angr.ailment.manager.Manager`.
//!
//! The manager hands out monotonically increasing atom indices and carries
//! the per-conversion scratch state (current instruction address, VEX
//! statement index, type environment, block address). Porting it to Rust
//! lets the VEX converter bump the atom counter natively (no Python call per
//! atom). The public Python API mirrors the original class exactly.

use pyo3::prelude::*;

#[pyclass(
    name = "Manager",
    module = "angr.rustylib.ailment",
    subclass,
    dict,
    get_all,
    set_all
)]
#[derive(Debug)]
pub struct Manager {
    /// Next atom index to hand out (the original used `itertools.count()`).
    pub atom_ctr: i64,
    pub _variable_map: Option<Py<PyAny>>,
    pub ins_addr: Option<i64>,
    pub vex_stmt_idx: Option<i64>,
    pub tyenv: Option<Py<PyAny>>,
    pub block_addr: Option<i64>,
}

#[pymethods]
impl Manager {
    #[new]
    fn new() -> Self {
        Self {
            atom_ctr: 0,
            _variable_map: None,
            ins_addr: None,
            vex_stmt_idx: None,
            tyenv: None,
            block_addr: None,
        }
    }

    #[getter]
    fn variable_map(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self._variable_map {
            Some(m) => Ok(m.clone()),
            None => {
                let vmap_module = PyModule::import(py, "angr.analyses.decompiler.variable_map")?;
                let vmap_cls = vmap_module.getattr("VariableMap")?;
                let vmap: Py<PyAny> = vmap_cls.call0()?.into();
                self._variable_map = Some(vmap.clone());
                Ok(vmap)
            }
        }
    }

    pub fn next_atom(&mut self) -> i64 {
        let v = self.atom_ctr;
        self.atom_ctr += 1;
        v
    }

    fn reset(&mut self) {
        self.atom_ctr = 0;
    }
}
