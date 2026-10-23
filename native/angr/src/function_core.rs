//! Core state of `Function`.
//!
//! Exposed as `angr.rustylib.function_core`:
//! - `FunctionCore`: the plain-data state of a function (address, names, flags, returning status, dirty
//!   bookkeeping, the `FunctionGraph`). The Python `Function` subclasses it and keeps the Python-object state
//!   (prototypes, calling convention, info, tags, back-references, CodeNode caches, networkx mirrors) in slots.
//!   The getters and setters use the names of the former Python slots, so `func._is_plt = v` still works.

use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

use crate::function_graph::FunctionGraph;

#[pyclass(subclass, module = "angr.rustylib.function_core")]
pub struct FunctionCore {
    #[pyo3(get, set)]
    pub addr: u64,
    #[pyo3(get, set, name = "_name")]
    pub name: String,
    #[pyo3(get, set)]
    pub is_default_name: bool,
    /// A Python list so that in-place changes (`func.previous_names.append(...)`) stick; created on demand.
    pub previous_names: Option<Py<PyList>>,
    #[pyo3(get, set)]
    pub binary_name: Option<String>,
    #[pyo3(get, set, name = "_from_signature")]
    pub from_signature: Option<String>,
    #[pyo3(get, set, name = "_prototype_libname")]
    pub prototype_libname: Option<String>,
    #[pyo3(get, set, name = "_is_syscall")]
    pub is_syscall: bool,
    #[pyo3(get, set, name = "_is_simprocedure")]
    pub is_simprocedure: bool,
    #[pyo3(get, set, name = "_is_plt")]
    pub is_plt: bool,
    #[pyo3(get, set, name = "_is_alignment")]
    pub is_alignment: bool,
    #[pyo3(get, set, name = "_returning")]
    pub returning: Option<bool>,
    #[pyo3(get, set)]
    pub normalized: bool,
    #[pyo3(get, set)]
    pub ran_cca: bool,
    #[pyo3(get, set)]
    pub bp_on_stack: bool,
    #[pyo3(get, set)]
    pub retaddr_on_stack: bool,
    #[pyo3(get, set, name = "_dirty")]
    pub dirty: bool,
    #[pyo3(get, set)]
    pub meta_only: bool,
    #[pyo3(get, set)]
    pub evicted: bool,
    #[pyo3(get, set, name = "_graph")]
    pub graph: Option<Py<FunctionGraph>>,
}

impl Default for FunctionCore {
    fn default() -> Self {
        FunctionCore {
            addr: 0,
            name: String::new(),
            is_default_name: false,
            previous_names: None,
            binary_name: None,
            from_signature: None,
            prototype_libname: None,
            is_syscall: false,
            is_simprocedure: false,
            is_plt: false,
            is_alignment: false,
            returning: None,
            normalized: false,
            ran_cca: false,
            bp_on_stack: false,
            retaddr_on_stack: false,
            dirty: true,
            meta_only: false,
            evicted: false,
            graph: None,
        }
    }
}

#[pymethods]
impl FunctionCore {
    /// Arguments are accepted and ignored so that subclass constructors keep their own signatures.
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(_args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>) -> Self {
        FunctionCore::default()
    }

    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        if let Some(g) = &self.graph {
            visit.call(g)?;
        }
        if let Some(l) = &self.previous_names {
            visit.call(l)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.graph = None;
        self.previous_names = None;
    }

    #[getter]
    fn previous_names<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyList> {
        self.previous_names
            .get_or_insert_with(|| PyList::empty(py).unbind())
            .bind(py)
            .clone()
    }

    /// Lists are kept as they are (aliased, like a plain attribute); other iterables are copied into a list.
    #[setter]
    fn set_previous_names(&mut self, names: &Bound<'_, PyAny>) -> PyResult<()> {
        let list = match names.cast::<PyList>() {
            Ok(l) => l.clone(),
            Err(_) => PyList::new(names.py(), names.try_iter()?.collect::<PyResult<Vec<_>>>()?)?,
        };
        self.previous_names = Some(list.unbind());
        Ok(())
    }

    /// Records `name` as a previous name unless it already is one.
    fn _add_previous_name(&mut self, py: Python<'_>, name: &Bound<'_, PyAny>) -> PyResult<()> {
        let list = self.previous_names(py);
        if !list.contains(name)? {
            list.append(name)?;
        }
        Ok(())
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn returning(&self) -> Option<bool> {
        self.returning
    }

    #[getter]
    fn from_signature(&self) -> Option<&str> {
        self.from_signature.as_deref()
    }

    #[getter]
    fn prototype_libname(&self) -> Option<&str> {
        self.prototype_libname.as_deref()
    }

    #[getter]
    fn dirty(&self) -> bool {
        self.dirty
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    #[getter]
    fn is_plt(&self) -> bool {
        self.is_plt
    }

    #[setter]
    fn set_is_plt(&mut self, v: bool) {
        if self.is_plt != v {
            self.is_plt = v;
            self.dirty = true;
        }
    }

    #[getter]
    fn is_simprocedure(&self) -> bool {
        self.is_simprocedure
    }

    #[setter]
    fn set_is_simprocedure(&mut self, v: bool) {
        if self.is_simprocedure != v {
            self.is_simprocedure = v;
            self.dirty = true;
        }
    }

    #[getter]
    fn is_syscall(&self) -> bool {
        self.is_syscall
    }

    #[setter]
    fn set_is_syscall(&mut self, v: bool) {
        if self.is_syscall != v {
            self.is_syscall = v;
            self.dirty = true;
        }
    }

    #[getter]
    fn is_alignment(&self) -> bool {
        self.is_alignment
    }

    #[setter]
    fn set_is_alignment(&mut self, v: bool) {
        if self.is_alignment != v {
            self.is_alignment = v;
            self.dirty = true;
        }
    }

    /// The core fields as a dict keyed by the former slot names (pickling).
    fn _core_state<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item(intern!(py, "addr"), self.addr)?;
        d.set_item(intern!(py, "_name"), &self.name)?;
        d.set_item(intern!(py, "is_default_name"), self.is_default_name)?;
        d.set_item(intern!(py, "previous_names"), self.previous_names(py))?;
        d.set_item(intern!(py, "binary_name"), &self.binary_name)?;
        d.set_item(intern!(py, "_from_signature"), &self.from_signature)?;
        d.set_item(intern!(py, "_prototype_libname"), &self.prototype_libname)?;
        d.set_item(intern!(py, "_is_syscall"), self.is_syscall)?;
        d.set_item(intern!(py, "_is_simprocedure"), self.is_simprocedure)?;
        d.set_item(intern!(py, "_is_plt"), self.is_plt)?;
        d.set_item(intern!(py, "_is_alignment"), self.is_alignment)?;
        d.set_item(intern!(py, "_returning"), self.returning)?;
        d.set_item(intern!(py, "normalized"), self.normalized)?;
        d.set_item(intern!(py, "ran_cca"), self.ran_cca)?;
        d.set_item(intern!(py, "bp_on_stack"), self.bp_on_stack)?;
        d.set_item(intern!(py, "retaddr_on_stack"), self.retaddr_on_stack)?;
        d.set_item(intern!(py, "_dirty"), self.dirty)?;
        d.set_item(intern!(py, "meta_only"), self.meta_only)?;
        d.set_item(intern!(py, "evicted"), self.evicted)?;
        d.set_item(intern!(py, "_graph"), &self.graph)?;
        Ok(d)
    }
}

pub fn function_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FunctionCore>()?;
    Ok(())
}
