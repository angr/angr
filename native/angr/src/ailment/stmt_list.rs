//! The list type of ``Block.statements``.

use std::sync::atomic::{AtomicU64, Ordering};

use pyo3::ffi;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt, PyList, PyTuple};

static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);

fn next_version() -> u64 {
    NEXT_VERSION.fetch_add(1, Ordering::Relaxed)
}

/// A ``list`` that knows when it changed. Every mutator gives it a new process-unique ``version``, and statements
/// are immutable, so one version names one sequence of statement contents: what is derived from a block's
/// statements (see ``ssa.rs``) stays valid for as long as the version does.
///
/// Reads and iteration are ``list``'s own. Mutating one behind its back (``list.append(stmts, x)``, the C API)
/// leaves the version stale.
#[pyclass(name = "StatementList", module = "angr.rustylib.ailment", extends = PyList, frozen)]
pub struct StatementList {
    version: AtomicU64,
}

impl StatementList {
    /// The statements list of a block: ``statements`` itself if it is a ``StatementList`` already (blocks may share
    /// one), else a new one with its items.
    pub fn of<'py>(statements: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        if statements.is_instance_of::<StatementList>() {
            return Ok(statements.clone().cast_into::<PyList>()?);
        }
        Self::with_version(statements, next_version())
    }

    /// The statements list that replaces ``current`` in a block. When it holds the very statements of ``current``,
    /// in order, it takes the version of ``current``: rebuilding a block's list without changing it is common, and
    /// what was derived from the statements stays valid.
    pub fn replacing<'py>(
        statements: &Bound<'py, PyAny>,
        current: &Bound<'py, PyList>,
    ) -> PyResult<Bound<'py, PyList>> {
        if statements.is_instance_of::<StatementList>() {
            return Ok(statements.clone().cast_into::<PyList>()?);
        }
        let new = Self::with_version(statements, next_version())?;
        if same_items(&new, current) {
            let version = Self::version_of(current);
            if version != 0 {
                new.cast::<StatementList>()?
                    .get()
                    .version
                    .store(version, Ordering::Relaxed);
            }
        }
        Ok(new)
    }

    /// A new list with the items and the version of ``statements``.
    pub fn copy_of<'py>(statements: &Bound<'py, PyList>) -> PyResult<Bound<'py, PyList>> {
        Self::with_version(statements.as_any(), Self::version_of(statements))
    }

    fn with_version<'py>(items: &Bound<'py, PyAny>, version: u64) -> PyResult<Bound<'py, PyList>> {
        let new = Bound::new(
            items.py(),
            StatementList {
                version: AtomicU64::new(version),
            },
        )?
        .into_any()
        .cast_into::<PyList>()?;
        splice(&new, 0, 0, Some(items))?;
        Ok(new)
    }

    /// The version of a block's statements list; 0 (never a real version) for any other list.
    pub fn version_of(statements: &Bound<'_, PyList>) -> u64 {
        match statements.cast::<StatementList>() {
            Ok(list) => list.get().version.load(Ordering::Relaxed),
            Err(_) => 0,
        }
    }

    fn touch(slf: &Bound<'_, Self>) {
        slf.get().version.store(next_version(), Ordering::Relaxed);
    }
}

/// Whether two lists hold the same objects in the same order.
fn same_items(a: &Bound<'_, PyList>, b: &Bound<'_, PyList>) -> bool {
    let len = a.len();
    if len != b.len() {
        return false;
    }
    // SAFETY: both are lists and every index is in range; the borrowed items are only compared by address.
    (0..len as isize).all(|i| unsafe {
        ffi::PyList_GetItem(a.as_ptr(), i) == ffi::PyList_GetItem(b.as_ptr(), i)
    })
}

fn check(py: Python<'_>, status: std::ffi::c_int) -> PyResult<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(PyErr::fetch(py))
    }
}

/// ``list[start:stop] = items`` (any iterable), or ``del list[start:stop]`` without items, through the C API.
fn splice(
    list: &Bound<'_, PyList>,
    start: isize,
    stop: isize,
    items: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    let items = items.map_or(std::ptr::null_mut(), |items| items.as_ptr());
    // SAFETY: `list` is a list and `items` is null or a live object; both are borrowed for the call.
    check(list.py(), unsafe {
        ffi::PyList_SetSlice(list.as_ptr(), start, stop, items)
    })
}

/// A list index as ``list`` reads it: an exact ``int``, negative counting from the end. None for anything else and
/// for an index out of range; the generic path then raises what ``list`` raises.
fn int_index(list: &Bound<'_, PyList>, key: &Bound<'_, PyAny>) -> Option<isize> {
    if !key.is_exact_instance_of::<PyInt>() {
        return None;
    }
    let len = list.len() as isize;
    let index = key.extract::<isize>().ok()?;
    let index = if index < 0 { index + len } else { index };
    (0..len).contains(&index).then_some(index)
}

/// ``list.<name>``, bound to ``slf``: the mutators without a C API fast path.
fn list_method<'py>(
    slf: &Bound<'py, StatementList>,
    name: &Bound<'py, pyo3::types::PyString>,
) -> PyResult<Bound<'py, PyAny>> {
    let py = slf.py();
    py.get_type::<PyList>()
        .getattr(name)?
        .call_method1(intern!(py, "__get__"), (slf,))
}

#[pymethods]
impl StatementList {
    #[new]
    #[pyo3(signature = (*_args))]
    fn new(_args: &Bound<'_, PyTuple>) -> Self {
        // list.__init__ fills the items in
        Self {
            version: AtomicU64::new(next_version()),
        }
    }

    fn append<'py>(slf: &Bound<'py, Self>, item: &Bound<'py, PyAny>) -> PyResult<()> {
        let result = slf.as_super().append(item);
        Self::touch(slf);
        result
    }

    fn extend<'py>(slf: &Bound<'py, Self>, items: &Bound<'py, PyAny>) -> PyResult<()> {
        let list = slf.as_super();
        let len = list.len() as isize;
        let result = splice(list, len, len, Some(items));
        Self::touch(slf);
        result
    }

    fn insert<'py>(slf: &Bound<'py, Self>, index: isize, item: &Bound<'py, PyAny>) -> PyResult<()> {
        // SAFETY: both objects are live and borrowed for the call. PyList_Insert clamps the index as list.insert does.
        let result = check(slf.py(), unsafe {
            ffi::PyList_Insert(slf.as_ptr(), index, item.as_ptr())
        });
        Self::touch(slf);
        result
    }

    #[pyo3(signature = (index=None))]
    fn pop<'py>(
        slf: &Bound<'py, Self>,
        index: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let list = slf.as_super();
        let last = PyInt::new(slf.py(), -1);
        let key = index.unwrap_or(last.as_any());
        let result = match int_index(list, key) {
            Some(index) => {
                let item = list.get_item(index as usize)?;
                splice(list, index, index + 1, None).map(|()| item)
            }
            None => list_method(slf, intern!(slf.py(), "pop"))?.call1((key,)),
        };
        Self::touch(slf);
        result
    }

    fn remove<'py>(slf: &Bound<'py, Self>, item: &Bound<'py, PyAny>) -> PyResult<()> {
        let result = list_method(slf, intern!(slf.py(), "remove"))?.call1((item,));
        Self::touch(slf);
        result.map(drop)
    }

    fn clear(slf: &Bound<'_, Self>) -> PyResult<()> {
        let list = slf.as_super();
        let result = splice(list, 0, list.len() as isize, None);
        Self::touch(slf);
        result
    }

    fn reverse(slf: &Bound<'_, Self>) -> PyResult<()> {
        let result = slf.as_super().reverse();
        Self::touch(slf);
        result
    }

    #[pyo3(signature = (*args, **kwargs))]
    fn sort<'py>(
        slf: &Bound<'py, Self>,
        args: &Bound<'py, PyTuple>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<()> {
        let result = list_method(slf, intern!(slf.py(), "sort"))?.call(args, kwargs);
        Self::touch(slf);
        result.map(drop)
    }

    fn __setitem__<'py>(
        slf: &Bound<'py, Self>,
        key: &Bound<'py, PyAny>,
        value: &Bound<'py, PyAny>,
    ) -> PyResult<()> {
        let list = slf.as_super();
        let result = match int_index(list, key) {
            Some(index) => {
                if list.get_item(index as usize)?.is(value) {
                    // writing back the statement that is there changes nothing
                    return Ok(());
                }
                list.set_item(index as usize, value)
            }
            None => list_method(slf, intern!(slf.py(), "__setitem__"))?
                .call1((key, value))
                .map(drop),
        };
        Self::touch(slf);
        result
    }

    fn __delitem__<'py>(slf: &Bound<'py, Self>, key: &Bound<'py, PyAny>) -> PyResult<()> {
        let list = slf.as_super();
        let result = match int_index(list, key) {
            Some(index) => splice(list, index, index + 1, None),
            None => list_method(slf, intern!(slf.py(), "__delitem__"))?
                .call1((key,))
                .map(drop),
        };
        Self::touch(slf);
        result
    }

    fn __iadd__<'py>(slf: &Bound<'py, Self>, items: &Bound<'py, PyAny>) -> PyResult<()> {
        Self::extend(slf, items)
    }

    fn __imul__<'py>(slf: &Bound<'py, Self>, count: &Bound<'py, PyAny>) -> PyResult<()> {
        let result = list_method(slf, intern!(slf.py(), "__imul__"))?.call1((count,));
        Self::touch(slf);
        result.map(drop)
    }

    /// Pickle and ``copy`` as a plain list: the version means nothing outside this process.
    fn __reduce__<'py>(
        slf: &Bound<'py, Self>,
    ) -> PyResult<(Bound<'py, PyAny>, (Bound<'py, PyList>,))> {
        let py = slf.py();
        let plain = PyList::new(py, slf.as_super().iter())?;
        Ok((py.get_type::<PyList>().into_any(), (plain,)))
    }
}
