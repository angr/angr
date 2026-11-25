//! The list type of ``Block.statements``.

use std::sync::atomic::{AtomicU64, Ordering};

use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyList, PyTuple};

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

    /// A new list with the items and the version of ``statements``.
    pub fn copy_of<'py>(statements: &Bound<'py, PyList>) -> PyResult<Bound<'py, PyList>> {
        Self::with_version(statements.as_any(), Self::version_of(statements))
    }

    fn with_version<'py>(items: &Bound<'py, PyAny>, version: u64) -> PyResult<Bound<'py, PyList>> {
        let py = items.py();
        let new = Bound::new(
            py,
            StatementList {
                version: AtomicU64::new(version),
            },
        )?;
        list_method(py, "extend")?.call1((&new, items))?;
        Ok(new.into_any().cast_into::<PyList>()?)
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

/// The unbound ``list`` method of that name.
fn list_method<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    static METHODS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    METHODS
        .get_or_try_init(py, || {
            PyResult::Ok(py.get_type::<PyList>().into_any().unbind())
        })?
        .bind(py)
        .getattr(name)
}

/// Run ``list.<name>(slf, *args)``, then mark the list changed.
fn mutate<'py>(
    slf: &Bound<'py, StatementList>,
    name: &str,
    args: impl pyo3::call::PyCallArgs<'py>,
) -> PyResult<Bound<'py, PyAny>> {
    let result = list_method(slf.py(), name)?.call1(args);
    StatementList::touch(slf);
    result
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
        mutate(slf, "append", (slf, item)).map(drop)
    }

    fn extend<'py>(slf: &Bound<'py, Self>, items: &Bound<'py, PyAny>) -> PyResult<()> {
        mutate(slf, "extend", (slf, items)).map(drop)
    }

    fn insert<'py>(
        slf: &Bound<'py, Self>,
        index: &Bound<'py, PyAny>,
        item: &Bound<'py, PyAny>,
    ) -> PyResult<()> {
        mutate(slf, "insert", (slf, index, item)).map(drop)
    }

    #[pyo3(signature = (*args))]
    fn pop<'py>(slf: &Bound<'py, Self>, args: &Bound<'py, PyTuple>) -> PyResult<Bound<'py, PyAny>> {
        let method = list_method(slf.py(), "pop")?;
        let result = method.call_method1("__get__", (slf,))?.call1(args);
        Self::touch(slf);
        result
    }

    fn remove<'py>(slf: &Bound<'py, Self>, item: &Bound<'py, PyAny>) -> PyResult<()> {
        mutate(slf, "remove", (slf, item)).map(drop)
    }

    fn clear(slf: &Bound<'_, Self>) -> PyResult<()> {
        mutate(slf, "clear", (slf,)).map(drop)
    }

    fn reverse(slf: &Bound<'_, Self>) -> PyResult<()> {
        mutate(slf, "reverse", (slf,)).map(drop)
    }

    #[pyo3(signature = (*args, **kwargs))]
    fn sort<'py>(
        slf: &Bound<'py, Self>,
        args: &Bound<'py, PyTuple>,
        kwargs: Option<&Bound<'py, pyo3::types::PyDict>>,
    ) -> PyResult<()> {
        let method = list_method(slf.py(), "sort")?;
        let result = method.call_method1("__get__", (slf,))?.call(args, kwargs);
        Self::touch(slf);
        result.map(drop)
    }

    fn __setitem__<'py>(
        slf: &Bound<'py, Self>,
        key: &Bound<'py, PyAny>,
        value: &Bound<'py, PyAny>,
    ) -> PyResult<()> {
        mutate(slf, "__setitem__", (slf, key, value)).map(drop)
    }

    fn __delitem__<'py>(slf: &Bound<'py, Self>, key: &Bound<'py, PyAny>) -> PyResult<()> {
        mutate(slf, "__delitem__", (slf, key)).map(drop)
    }

    fn __iadd__<'py>(slf: &Bound<'py, Self>, items: &Bound<'py, PyAny>) -> PyResult<()> {
        mutate(slf, "extend", (slf, items)).map(drop)
    }

    fn __imul__<'py>(slf: &Bound<'py, Self>, count: &Bound<'py, PyAny>) -> PyResult<()> {
        mutate(slf, "__imul__", (slf, count)).map(drop)
    }

    /// Pickle and ``copy`` as a plain list: the version means nothing outside this process.
    fn __reduce__<'py>(
        slf: &Bound<'py, Self>,
    ) -> PyResult<(Bound<'py, PyAny>, (Bound<'py, PyList>,))> {
        let py = slf.py();
        let plain = PyList::new(py, slf.as_any().try_iter()?.collect::<PyResult<Vec<_>>>()?)?;
        Ok((py.get_type::<PyList>().into_any(), (plain,)))
    }
}
