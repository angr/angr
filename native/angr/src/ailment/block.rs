//! Block class.

use std::sync::atomic::Ordering;

use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

use crate::ailment::base::CachedHash;
use crate::ailment::hash::{AilHash, finish, hasher};
use crate::ailment::utils::deep_copy_obj;

#[pyclass(
    name = "Block",
    module = "angr.rustylib.ailment",
    subclass,
    from_py_object
)]
#[derive(Debug)]
pub struct Block {
    pub addr: i64,
    pub original_size: Option<i64>,
    pub statements: Py<PyList>,
    pub idx: Option<i64>,
    pub cached_hash: CachedHash,
}

impl Clone for Block {
    fn clone(&self) -> Self {
        Python::attach(|py| Self {
            addr: self.addr,
            original_size: self.original_size,
            statements: self.statements.clone_ref(py),
            idx: self.idx,
            cached_hash: self.cached_hash.clone(),
        })
    }
}

#[pymethods]
impl Block {
    #[new]
    #[pyo3(signature = (addr, original_size=None, statements=None, idx=None))]
    fn new(
        py: Python<'_>,
        addr: i64,
        original_size: Option<i64>,
        statements: Option<Bound<'_, PyAny>>,
        idx: Option<i64>,
    ) -> PyResult<Self> {
        let stmts_list = match statements {
            Some(s) if !s.is_none() => {
                if let Ok(l) = s.cast::<PyList>() {
                    l.to_owned()
                } else {
                    let l = PyList::empty(py);
                    for x in s.try_iter()? {
                        l.append(x?)?;
                    }
                    l
                }
            }
            _ => PyList::empty(py),
        };
        Ok(Self {
            addr,
            original_size,
            statements: stmts_list.unbind(),
            idx,
            cached_hash: CachedHash::new(),
        })
    }

    #[getter]
    fn addr(&self) -> i64 {
        self.addr
    }
    #[setter]
    fn set_addr(&mut self, value: i64) {
        self.addr = value;
        self.cached_hash.clear();
    }
    #[getter]
    fn original_size(&self) -> Option<i64> {
        self.original_size
    }
    #[setter]
    fn set_original_size(&mut self, value: Option<i64>) {
        self.original_size = value;
    }
    #[getter]
    fn statements<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        self.statements.bind(py).clone()
    }
    #[setter]
    fn set_statements(&mut self, value: Bound<'_, PyList>) {
        self.statements = value.unbind();
    }
    #[getter]
    fn idx(&self) -> Option<i64> {
        self.idx
    }
    #[setter]
    fn set_idx(&mut self, value: Option<i64>) {
        self.idx = value;
        self.cached_hash.clear();
    }

    #[pyo3(signature = (statements=None))]
    fn copy(&self, py: Python<'_>, statements: Option<Bound<'_, PyAny>>) -> PyResult<Self> {
        let stmts_list = match statements {
            Some(s) if !s.is_none() => {
                if let Ok(l) = s.cast::<PyList>() {
                    l.to_owned()
                } else {
                    let l = PyList::empty(py);
                    for x in s.try_iter()? {
                        l.append(x?)?;
                    }
                    l
                }
            }
            _ => {
                // Shallow copy of self.statements
                let l = PyList::empty(py);
                for x in self.statements.bind(py).iter() {
                    l.append(x)?;
                }
                l
            }
        };
        Ok(Self {
            addr: self.addr,
            original_size: self.original_size,
            statements: stmts_list.unbind(),
            idx: self.idx,
            cached_hash: CachedHash::new(),
        })
    }

    fn deep_copy(&self, py: Python<'_>, manager: &Bound<'_, PyAny>) -> PyResult<Self> {
        let new_list = PyList::empty(py);
        for stmt in self.statements.bind(py).iter() {
            new_list.append(deep_copy_obj(&stmt, manager)?)?;
        }
        Ok(Self {
            addr: self.addr,
            original_size: self.original_size,
            statements: new_list.unbind(),
            idx: self.idx,
            cached_hash: CachedHash::new(),
        })
    }

    #[getter]
    fn sort_key(&self) -> (i64, i64, i64) {
        let idx = self.idx;
        match idx {
            None => (self.addr, 0, 0),
            Some(i) => (self.addr, 1, i),
        }
    }

    fn __lt__(&self, other: &Self) -> bool {
        self.sort_key() < other.sort_key()
    }

    fn __repr__(self_: PyRef<'_, Self>) -> PyResult<String> {
        let py = self_.py();
        let n = self_.statements.bind(py).len();
        Ok(match self_.idx {
            None => format!("<AILBlock {:#x} of {} statements>", self_.addr, n),
            Some(i) => format!("<AILBlock {:#x}.{} of {} statements>", self_.addr, i, n),
        })
    }

    #[pyo3(signature = (indent=0))]
    fn dbg_repr(self_: PyRef<'_, Self>, indent: usize) -> PyResult<String> {
        let py = self_.py();
        let indent_str = " ".repeat(indent);
        let mut s = match self_.idx {
            None => format!("{indent_str}## Block {:x}\n", self_.addr),
            Some(i) => format!("{indent_str}## Block {:x}.{}\n", self_.addr, i),
        };
        let stmts = self_.statements.bind(py);
        let mut parts = Vec::with_capacity(stmts.len());
        for (i, stmt) in stmts.iter().enumerate() {
            let tags = stmt.getattr("tags")?;
            let ins_addr = tags
                .call_method1("get", ("ins_addr", 0))?
                .extract::<i64>()
                .unwrap_or(0);
            parts.push(format!(
                "{indent_str}{i:02} | {ins_addr:#x} | {}",
                stmt.str()?
            ));
        }
        s.push_str(&parts.join("\n"));
        s.push('\n');
        Ok(s)
    }

    fn pp(self_: PyRef<'_, Self>) -> PyResult<()> {
        let s = Self::dbg_repr(self_, 0)?;
        println!("{s}");
        Ok(())
    }

    fn __str__(self_: PyRef<'_, Self>) -> String {
        match self_.idx {
            None => format!("<AILBlock {:#x}>", self_.addr),
            Some(i) => format!("<AILBlock {:#x}.{}>", self_.addr, i),
        }
    }

    fn __eq__(slf: Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let py = slf.py();
        if slf.is(other) {
            return Ok(true);
        }
        if !py.get_type::<Block>().is(other.get_type()) {
            return Ok(false);
        }
        let s = slf.borrow();
        let o = other.cast::<Block>()?.borrow();
        if s.addr != o.addr || s.idx != o.idx {
            return Ok(false);
        }
        s.statements.bind(py).as_any().eq(o.statements.bind(py))
    }

    fn likes(slf: Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let py = slf.py();
        if !py.get_type::<Block>().is(other.get_type()) {
            return Ok(false);
        }
        let s = slf.borrow();
        let o = other.cast::<Block>()?.borrow();
        let sa = s.statements.bind(py);
        let ob = o.statements.bind(py);
        if sa.len() != ob.len() {
            return Ok(false);
        }
        for (xa, xb) in sa.iter().zip(ob.iter()) {
            if !xa.call_method1("likes", (&xb,))?.is_truthy()? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn clear_hash(&self) {
        self.cached_hash.clear();
    }

    fn __hash__(&self) -> i64 {
        if let Some(h) = self.cached_hash.get() {
            return h;
        }
        // hash((Block, self.addr, self.idx))
        let mut hh = hasher();
        hh.typename("Block");
        hh.int(self.addr as i128);
        hh.opt_int(self.idx.map(|i| i as i128));
        let h = finish(hh);
        self.cached_hash.set(h);
        // suppress the unused-import lint for Ordering when atomic isn't used directly
        let _ = Ordering::Relaxed;
        h
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, memo: Bound<'py, PyAny>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let helper = py
            .import("angr.ailment._reconstruct")?
            .getattr("deepcopy_via_deep_copy")?;
        Ok(helper.call1((slf, memo))?.unbind())
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        Ok(slf.call_method0("copy")?.unbind())
    }

    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Bound<'py, PyTuple>> {
        let py = slf.py();
        let cls = slf.get_type();
        let s = slf.borrow();
        let stmts = s.statements.bind(py);
        let args = PyTuple::new(
            py,
            [
                s.addr.into_bound_py_any(py)?,
                s.original_size
                    .map(|v| v.into_bound_py_any(py))
                    .unwrap_or_else(|| py.None().into_bound_py_any(py))?,
                stmts.clone().into_any().into_bound_py_any(py)?,
                s.idx
                    .map(|v| v.into_bound_py_any(py))
                    .unwrap_or_else(|| py.None().into_bound_py_any(py))?,
            ],
        )?;
        PyTuple::new(
            py,
            [cls.into_bound_py_any(py)?, args.into_bound_py_any(py)?],
        )
    }

    fn __getstate__<'py>(slf: PyRef<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("addr", slf.addr)?;
        d.set_item("original_size", slf.original_size)?;
        d.set_item("idx", slf.idx)?;
        d.set_item("statements", slf.statements.bind(py))?;
        Ok(d)
    }

    fn __setstate__(mut slf: PyRefMut<'_, Self>, state: Bound<'_, PyDict>) -> PyResult<()> {
        let py = slf.py();
        if let Some(v) = state.get_item("addr")? {
            slf.addr = v.extract()?;
        }
        slf.original_size = state
            .get_item("original_size")?
            .and_then(|v| if v.is_none() { None } else { v.extract().ok() });
        slf.idx = state
            .get_item("idx")?
            .and_then(|v| if v.is_none() { None } else { v.extract().ok() });
        if let Some(v) = state.get_item("statements")? {
            if v.is_none() {
                slf.statements = PyList::empty(py).unbind();
            } else if let Ok(l) = v.cast::<PyList>() {
                slf.statements = l.to_owned().unbind();
            } else {
                let l = PyList::empty(py);
                for x in v.try_iter()? {
                    l.append(x?)?;
                }
                slf.statements = l.unbind();
            }
        }
        slf.cached_hash.clear();
        Ok(())
    }

    /// Serialize this Block to bytes via postcard. See
    /// [`crate::ailment::serialize`] for the format.
    fn to_bytes<'py>(slf: Bound<'py, Self>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        let py = slf.py();
        let bytes = crate::ailment::serialize::dumps_to_bytes(py, slf.as_any())?;
        Ok(pyo3::types::PyBytes::new(py, &bytes))
    }

    /// Deserialize a Block from bytes.
    #[classmethod]
    fn from_bytes(
        _cls: &Bound<'_, pyo3::types::PyType>,
        py: Python<'_>,
        data: &[u8],
    ) -> PyResult<Py<PyAny>> {
        crate::ailment::serialize::loads_from_bytes(py, data)
    }
}
