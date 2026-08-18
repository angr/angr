//! Rust port of `angr.ailment.manager.Manager`.
//!
//! The manager hands out monotonically increasing atom indices and carries
//! the per-conversion scratch state (current instruction address, VEX
//! statement index, type environment, block address). Porting it to Rust
//! lets the VEX converter bump the atom counter natively (no Python call per
//! atom). The public Python API mirrors the original class exactly.

use pyo3::prelude::*;

#[pyclass(name = "Manager", module = "angr.rustylib.ailment", subclass, dict)]
#[derive(Debug)]
pub struct Manager {
    #[pyo3(get, set)]
    pub name: Option<Py<PyAny>>,
    #[pyo3(get, set)]
    pub arch: Option<Py<PyAny>>,
    /// Next atom index to hand out (the original used `itertools.count()`).
    #[pyo3(get, set)]
    pub atom_ctr: i64,
    /// Attached by Clinic so that optimization passes, peephole optimizations,
    /// and region simplifiers can use VariableMap.
    #[pyo3(get, set)]
    pub variable_map: Option<Py<PyAny>>,
    #[pyo3(get, set)]
    pub ins_addr: Option<i64>,
    #[pyo3(get, set)]
    pub vex_stmt_idx: Option<i64>,
    #[pyo3(get, set)]
    pub tyenv: Option<Py<PyAny>>,
    #[pyo3(get, set)]
    pub block_addr: Option<i64>,
}

#[pymethods]
impl Manager {
    #[new]
    #[pyo3(signature = (name=None, arch=None))]
    fn new(name: Option<Py<PyAny>>, arch: Option<Py<PyAny>>) -> Self {
        Self {
            name,
            arch,
            atom_ctr: 0,
            variable_map: None,
            ins_addr: None,
            vex_stmt_idx: None,
            tyenv: None,
            block_addr: None,
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
