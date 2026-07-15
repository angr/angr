//! Rust port of `angr.ailment.manager.Manager`.
//!
//! The manager hands out monotonically increasing atom indices and carries
//! the per-conversion scratch state (current instruction address, VEX
//! statement index, type environment, block address). Porting it to Rust
//! lets the VEX converter bump the atom counter natively (no Python call per
//! atom). The public Python API mirrors the original class exactly.

use pyo3::prelude::*;
use pyo3::types::PyType;

#[pyclass(name = "Manager", module = "angr.rustylib.ailment", subclass, dict)]
#[derive(Debug)]
pub struct Manager {
    pub name: Option<Py<PyAny>>,
    pub arch: Option<Py<PyAny>>,
    /// Next atom index to hand out (the original used `itertools.count()`).
    pub atom_ctr: i64,
    /// Attached by Clinic so that optimization passes, peephole optimizations,
    /// and region simplifiers can use VariableMap.
    pub variable_map: Option<Py<PyAny>>,
    pub ins_addr: Option<i64>,
    pub vex_stmt_idx: Option<i64>,
    pub tyenv: Option<Py<PyAny>>,
    pub block_addr: Option<i64>,
}

impl Manager {
    /// Native atom allocation used by the in-Rust VEX converter.
    pub fn next_atom_native(&mut self) -> i64 {
        let v = self.atom_ctr;
        self.atom_ctr += 1;
        v
    }
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

    fn next_atom(&mut self) -> i64 {
        self.next_atom_native()
    }

    fn reset(&mut self) {
        self.atom_ctr = 0;
    }

    // --- attributes ------------------------------------------------------

    #[getter]
    fn name(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.name.as_ref().map(|v| v.clone_ref(py))
    }
    #[setter]
    fn set_name(&mut self, value: Option<Py<PyAny>>) {
        self.name = value;
    }

    #[getter]
    fn arch(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.arch.as_ref().map(|v| v.clone_ref(py))
    }
    #[setter]
    fn set_arch(&mut self, value: Option<Py<PyAny>>) {
        self.arch = value;
    }

    #[getter]
    fn variable_map(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.variable_map.as_ref().map(|v| v.clone_ref(py))
    }
    #[setter]
    fn set_variable_map(&mut self, value: Option<Py<PyAny>>) {
        self.variable_map = value;
    }

    #[getter]
    fn ins_addr(&self) -> Option<i64> {
        self.ins_addr
    }
    #[setter]
    fn set_ins_addr(&mut self, value: Option<i64>) {
        self.ins_addr = value;
    }

    #[getter]
    fn vex_stmt_idx(&self) -> Option<i64> {
        self.vex_stmt_idx
    }
    #[setter]
    fn set_vex_stmt_idx(&mut self, value: Option<i64>) {
        self.vex_stmt_idx = value;
    }

    #[getter]
    fn tyenv(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.tyenv.as_ref().map(|v| v.clone_ref(py))
    }
    #[setter]
    fn set_tyenv(&mut self, value: Option<Py<PyAny>>) {
        self.tyenv = value;
    }

    #[getter]
    fn block_addr(&self) -> Option<i64> {
        self.block_addr
    }
    #[setter]
    fn set_block_addr(&mut self, value: Option<i64>) {
        self.block_addr = value;
    }

    /// Exposed for parity/debugging; the original stored an `itertools.count`.
    #[getter]
    fn atom_ctr(&self) -> i64 {
        self.atom_ctr
    }
    #[setter]
    fn set_atom_ctr(&mut self, value: i64) {
        self.atom_ctr = value;
    }
}

/// Helper so other modules can read the type object if needed.
pub fn manager_type(py: Python<'_>) -> Bound<'_, PyType> {
    py.get_type::<Manager>()
}
