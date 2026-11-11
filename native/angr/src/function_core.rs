//! Core state of `Function` and the address index of `FunctionManager`.
//!
//! Exposed as `angr.rustylib.function_core`:
//! - `FunctionCore`: the plain-data state of a function (address, names, flags, returning status, dirty
//!   bookkeeping, the `FunctionGraph`). The Python `Function` subclasses it and keeps the Python-object state
//!   (prototypes, calling convention, info, tags, back-references, CodeNode caches, networkx mirrors) in slots.
//!   The getters and setters use the names of the former Python slots, so `func._is_plt = v` still works.
//! - Bulk construction (`FunctionCore._bulk_new`, `FunctionCore._bulk_from_store`, and `new_function_objects`
//!   for Rust callers): many function objects from records in one call, without `Function.__init__`.
//! - `FunctionIndex`: the ordered address set of a function map plus the address-keyed caches of
//!   `FunctionManager` (returning sets, block counts, names, signature sources, key functions, binary-name and
//!   PLT ranges).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound as RangeBound;

use indexmap::{IndexMap, IndexSet};
use pyo3::exceptions::PyValueError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList, PySet, PyTuple, PyType};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::function_graph::FunctionGraph;
use crate::recovery_functions::RecoveryFunctions;

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

/// The fields a bulk-created function gets; everything else keeps its default.
pub struct CoreRecord {
    pub addr: u64,
    pub name: String,
    pub is_default_name: bool,
    pub binary_name: Option<String>,
    pub is_syscall: bool,
    pub is_simprocedure: bool,
    pub is_plt: bool,
    pub is_alignment: bool,
    pub returning: Option<bool>,
    pub graph: Py<FunctionGraph>,
}

impl FunctionCore {
    fn apply(&mut self, rec: CoreRecord) {
        self.addr = rec.addr;
        self.name = rec.name;
        self.is_default_name = rec.is_default_name;
        self.binary_name = rec.binary_name;
        self.is_syscall = rec.is_syscall;
        self.is_simprocedure = rec.is_simprocedure;
        self.is_plt = rec.is_plt;
        self.is_alignment = rec.is_alignment;
        self.returning = rec.returning;
        self.graph = Some(rec.graph);
    }
}

/// Creates instances of `cls` (a `FunctionCore` subclass) from records, without running `cls.__init__`.
/// The Python-side state of the objects is left uninitialized; the caller initializes it.
pub fn new_function_objects<'py>(
    cls: &Bound<'py, PyType>,
    records: Vec<CoreRecord>,
) -> PyResult<Vec<Bound<'py, PyAny>>> {
    let py = cls.py();
    if !cls.is_subclass_of::<FunctionCore>()? {
        return Err(PyValueError::new_err(
            "cls must be a subclass of FunctionCore",
        ));
    }
    let new = cls.getattr(intern!(py, "__new__"))?;
    let args = PyTuple::new(py, [cls])?;
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        let obj = new.call1(&args)?;
        obj.cast::<FunctionCore>()?.borrow_mut().apply(rec);
        out.push(obj);
    }
    Ok(out)
}

/// `(functions, their info dicts)`
type BulkFunctions<'py> = (Vec<Bound<'py, PyAny>>, Vec<Bound<'py, PyDict>>);

type RecordTuple = (
    u64,
    String,
    bool,
    Option<String>,
    bool,
    bool,
    bool,
    bool,
    Option<bool>,
    Py<FunctionGraph>,
);

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

    #[getter(from_signature)]
    fn get_from_signature(&self) -> Option<&str> {
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

    /// Instances of `cls` from `(addr, name, is_default_name, binary_name, is_syscall, is_simprocedure, is_plt,
    /// is_alignment, returning, graph)` records. Only the core is initialized.
    #[classmethod]
    fn _bulk_new<'py>(
        cls: &Bound<'py, PyType>,
        records: Vec<RecordTuple>,
    ) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let recs = records
            .into_iter()
            .map(|r| CoreRecord {
                addr: r.0,
                name: r.1,
                is_default_name: r.2,
                binary_name: r.3,
                is_syscall: r.4,
                is_simprocedure: r.5,
                is_plt: r.6,
                is_alignment: r.7,
                returning: r.8,
                graph: r.9,
            })
            .collect();
        new_function_objects(cls, recs)
    }

    /// Instances of `cls` from the records of a RecoveryFunctions store (all of them, in address order, or the
    /// given addresses), and the info dict of each. Graphs are shared with the store.
    #[classmethod]
    #[pyo3(signature = (store, addrs=None))]
    fn _bulk_from_store<'py>(
        cls: &Bound<'py, PyType>,
        store: PyRef<'py, RecoveryFunctions>,
        addrs: Option<Vec<u64>>,
    ) -> PyResult<BulkFunctions<'py>> {
        let py = cls.py();
        let addrs = addrs.unwrap_or_else(|| store.funcs.keys().copied().collect());
        let mut recs = Vec::with_capacity(addrs.len());
        let mut extra = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let r = store
                .funcs
                .get(&addr)
                .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(addr))?;
            recs.push(CoreRecord {
                addr,
                name: r.name.clone(),
                is_default_name: r.is_default_name,
                binary_name: r.binary_name.clone(),
                is_syscall: r.is_syscall,
                is_simprocedure: r.is_simprocedure,
                is_plt: r.is_plt,
                is_alignment: r.is_alignment,
                returning: r.returning,
                graph: r.graph.clone_ref(py),
            });
            extra.push((r.previous_names.clone(), store.info_dict(py, addr)?));
        }
        let objs = new_function_objects(cls, recs)?;
        let mut infos = Vec::with_capacity(objs.len());
        for (obj, (previous_names, info)) in objs.iter().zip(extra) {
            if !previous_names.is_empty() {
                obj.cast::<FunctionCore>()?.borrow_mut().previous_names =
                    Some(PyList::new(py, previous_names)?.unbind());
            }
            infos.push(info);
        }
        Ok((objs, infos))
    }
}

/// An address-keyed map that iterates in insertion order like a Python dict (re-inserting a removed key moves it
/// to the end; updating a key keeps its place), with O(1) removal.
#[derive(Clone)]
struct SeqMap<V> {
    map: FxHashMap<u64, (u64, V)>,
    next: u64,
}

impl<V> Default for SeqMap<V> {
    fn default() -> Self {
        SeqMap {
            map: FxHashMap::default(),
            next: 0,
        }
    }
}

impl<V> SeqMap<V> {
    fn insert(&mut self, k: u64, v: V) {
        match self.map.get_mut(&k) {
            Some(e) => e.1 = v,
            None => {
                self.map.insert(k, (self.next, v));
                self.next += 1;
            }
        }
    }

    fn get(&self, k: u64) -> Option<&V> {
        self.map.get(&k).map(|e| &e.1)
    }

    fn remove(&mut self, k: u64) {
        self.map.remove(&k);
    }

    /// Entries in insertion order.
    fn ordered(&self) -> Vec<(u64, &V)> {
        let mut v: Vec<(u64, u64, &V)> =
            self.map.iter().map(|(&k, (seq, v))| (*seq, k, v)).collect();
        v.sort_unstable_by_key(|e| e.0);
        v.into_iter().map(|(_, k, v)| (k, v)).collect()
    }
}

/// The ordered address set of a function map and the address-keyed caches of its FunctionManager.
///
/// The caches follow the Python containers they replace: dict-like caches keep insertion order, and set results
/// are built in insertion order so that the returned Python sets iterate as before.
#[pyclass(module = "angr.rustylib.function_core")]
#[derive(Clone, Default)]
pub struct FunctionIndex {
    addrs: BTreeSet<u64>,
    nonreturning: FxHashSet<u64>,
    unknown_returning: FxHashSet<u64>,
    block_counts: SeqMap<usize>,
    names: FxHashMap<u64, String>,
    name_to_addrs: FxHashMap<String, IndexSet<u64>>,
    old_name_to_addrs: FxHashMap<String, IndexSet<u64>>,
    from_signature: SeqMap<Option<String>>,
    key_funcs: IndexMap<String, IndexSet<u64>>,
    /// min_addr -> (max_addr, binary basename) of objects whose binary name was looked up.
    binnames: BTreeMap<u64, (u64, Option<String>)>,
    /// min_addr -> max_addr of objects whose PLT stubs were collected, and the stubs.
    plt_ranges: BTreeMap<u64, u64>,
    plt_addrs: FxHashSet<u64>,
}

fn set_of<'py>(
    py: Python<'py>,
    items: impl IntoIterator<Item = u64>,
) -> PyResult<Bound<'py, PySet>> {
    let s = PySet::empty(py)?;
    for a in items {
        s.add(a)?;
    }
    Ok(s)
}

#[pymethods]
impl FunctionIndex {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    // --- ordered addresses ----------------------------------------------------------------------

    /// Returns True if the address is new.
    pub fn add(&mut self, addr: u64) -> bool {
        self.addrs.insert(addr)
    }

    /// Returns True if the address was present.
    pub fn discard(&mut self, addr: u64) -> bool {
        self.addrs.remove(&addr)
    }

    pub fn clear_addrs(&mut self) {
        self.addrs.clear();
    }

    pub fn __contains__(&self, addr: &Bound<'_, PyAny>) -> bool {
        match addr.extract::<u64>() {
            Ok(a) => self.addrs.contains(&a),
            Err(_) => false,
        }
    }

    pub fn __len__(&self) -> usize {
        self.addrs.len()
    }

    pub fn addrs(&self) -> Vec<u64> {
        self.addrs.iter().copied().collect()
    }

    /// The smallest address greater than `addr` (or the smallest address if `addr` is None). Iterating with it
    /// sees insertions after the current position and skips removed addresses.
    #[pyo3(signature = (addr=None))]
    pub fn next_addr(&self, addr: Option<u64>) -> Option<u64> {
        match addr {
            None => self.addrs.first().copied(),
            Some(a) => self
                .addrs
                .range((RangeBound::Excluded(a), RangeBound::Unbounded))
                .next()
                .copied(),
        }
    }

    pub fn floor(&self, addr: u64) -> Option<u64> {
        self.addrs.range(..=addr).next_back().copied()
    }

    pub fn ceiling(&self, addr: u64) -> Option<u64> {
        self.addrs.range(addr..).next().copied()
    }

    /// `SortedList.irange`
    #[pyo3(signature = (minimum=None, maximum=None, inclusive=(true, true), reverse=false))]
    pub fn irange(
        &self,
        minimum: Option<u64>,
        maximum: Option<u64>,
        inclusive: (bool, bool),
        reverse: bool,
    ) -> Vec<u64> {
        if let (Some(a), Some(b)) = (minimum, maximum)
            && (a > b || (a == b && !(inclusive.0 && inclusive.1)))
        {
            return Vec::new();
        }
        let lo = match (minimum, inclusive.0) {
            (None, _) => RangeBound::Unbounded,
            (Some(m), true) => RangeBound::Included(m),
            (Some(m), false) => RangeBound::Excluded(m),
        };
        let hi = match (maximum, inclusive.1) {
            (None, _) => RangeBound::Unbounded,
            (Some(m), true) => RangeBound::Included(m),
            (Some(m), false) => RangeBound::Excluded(m),
        };
        let it = self.addrs.range((lo, hi)).copied();
        if reverse {
            it.rev().collect()
        } else {
            it.collect()
        }
    }

    // --- returning status -----------------------------------------------------------------------

    pub fn set_returning(&mut self, addr: u64, v: Option<bool>) {
        match v {
            Some(false) => {
                self.nonreturning.insert(addr);
                self.unknown_returning.remove(&addr);
            }
            Some(true) => {
                self.nonreturning.remove(&addr);
                self.unknown_returning.remove(&addr);
            }
            None => {
                self.unknown_returning.insert(addr);
                self.nonreturning.remove(&addr);
            }
        }
    }

    pub fn is_nonreturning(&self, addr: u64) -> bool {
        self.nonreturning.contains(&addr)
    }

    pub fn is_returning_unknown(&self, addr: u64) -> bool {
        self.unknown_returning.contains(&addr)
    }

    pub fn nonreturning_addrs(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.nonreturning.iter().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn unknown_returning_addrs(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.unknown_returning.iter().copied().collect();
        v.sort_unstable();
        v
    }

    // --- block counts ---------------------------------------------------------------------------

    pub fn set_block_count(&mut self, addr: u64, count: usize) {
        self.block_counts.insert(addr, count);
    }

    pub fn block_count(&self, addr: u64) -> Option<usize> {
        self.block_counts.get(addr).copied()
    }

    /// The block counts as a dict, in insertion order.
    pub fn block_counts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (a, c) in self.block_counts.ordered() {
            d.set_item(a, *c)?;
        }
        Ok(d)
    }

    pub fn addrs_with_block_count<'py>(
        &self,
        py: Python<'py>,
        count: usize,
    ) -> PyResult<Bound<'py, PySet>> {
        set_of(
            py,
            self.block_counts
                .ordered()
                .into_iter()
                .filter(|&(_, &c)| c == count)
                .map(|(a, _)| a),
        )
    }

    // --- names ----------------------------------------------------------------------------------

    /// `FunctionManager.function_name_changed`
    #[pyo3(signature = (addr, old_name, new_name))]
    pub fn name_changed(&mut self, addr: u64, old_name: Option<&str>, new_name: &str) {
        if let Some(old) = old_name {
            if let Some(addrs) = self.name_to_addrs.get_mut(old) {
                addrs.shift_remove(&addr);
                if addrs.is_empty() {
                    self.name_to_addrs.remove(old);
                }
            }
            self.old_name_to_addrs
                .entry(old.to_owned())
                .or_default()
                .insert(addr);
        }
        self.name_to_addrs
            .entry(new_name.to_owned())
            .or_default()
            .insert(addr);
        self.names.insert(addr, new_name.to_owned());
    }

    /// Adds an address under a name without touching the address-to-name cache (bulk loading).
    pub fn add_name_addr(&mut self, name: &str, addr: u64) {
        self.name_to_addrs
            .entry(name.to_owned())
            .or_default()
            .insert(addr);
    }

    /// Adds an address under a previous name.
    pub fn add_old_name_addr(&mut self, name: &str, addr: u64) {
        self.old_name_to_addrs
            .entry(name.to_owned())
            .or_default()
            .insert(addr);
    }

    pub fn name(&self, addr: u64) -> Option<&str> {
        self.names.get(&addr).map(String::as_str)
    }

    /// Addresses of the functions named `name` (and, optionally, previously named `name`), in ascending order.
    #[pyo3(signature = (name, check_previous_names=false))]
    pub fn addrs_by_name(&self, name: &str, check_previous_names: bool) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .name_to_addrs
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .collect();
        if check_previous_names {
            out.extend(
                self.old_name_to_addrs
                    .get(name)
                    .into_iter()
                    .flatten()
                    .copied(),
            );
            out.sort_unstable();
            out.dedup();
        } else {
            out.sort_unstable();
        }
        out
    }

    /// The same addresses as a set: the current-name set or, with previous names, the previous-name set updated
    /// with the current-name set, each in insertion order.
    #[pyo3(signature = (name, check_previous_names=false))]
    pub fn addrs_by_name_set<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        check_previous_names: bool,
    ) -> PyResult<Bound<'py, PySet>> {
        let cur = self.name_to_addrs.get(name).into_iter().flatten().copied();
        if check_previous_names {
            set_of(
                py,
                self.old_name_to_addrs
                    .get(name)
                    .into_iter()
                    .flatten()
                    .copied()
                    .chain(cur),
            )
        } else {
            set_of(py, cur)
        }
    }

    // --- signature sources ----------------------------------------------------------------------

    #[pyo3(signature = (addr, from_signature))]
    pub fn set_from_signature(&mut self, addr: u64, from_signature: Option<String>) {
        self.from_signature.insert(addr, from_signature);
    }

    pub fn from_signature(&self, addr: u64) -> Option<&str> {
        self.from_signature.get(addr).and_then(|s| s.as_deref())
    }

    pub fn addrs_from_signature<'py>(
        &self,
        py: Python<'py>,
        from_signature: &str,
    ) -> PyResult<Bound<'py, PySet>> {
        set_of(
            py,
            self.from_signature
                .ordered()
                .into_iter()
                .filter(|(_, s)| s.as_deref() == Some(from_signature))
                .map(|(a, _)| a),
        )
    }

    // --- key functions --------------------------------------------------------------------------

    pub fn add_key_func(&mut self, func_type: &str, addr: u64) {
        self.key_funcs
            .entry(func_type.to_owned())
            .or_default()
            .insert(addr);
    }

    pub fn key_func_addrs<'py>(
        &self,
        py: Python<'py>,
        func_type: &str,
    ) -> PyResult<Bound<'py, PySet>> {
        set_of(
            py,
            self.key_funcs.get(func_type).into_iter().flatten().copied(),
        )
    }

    pub fn key_funcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (t, addrs) in &self.key_funcs {
            d.set_item(t, set_of(py, addrs.iter().copied())?)?;
        }
        Ok(d)
    }

    /// Indexes every `is_<type>` entry of an info dict whose value is True.
    pub fn index_info(&mut self, addr: u64, info: &Bound<'_, PyDict>) -> PyResult<()> {
        for (k, v) in info.iter() {
            let Ok(key) = k.extract::<&str>() else {
                continue;
            };
            if let Some(t) = key.strip_prefix("is_")
                && v.is_exact_instance_of::<PyBool>()
                && v.is_truthy()?
            {
                self.add_key_func(t, addr);
            }
        }
        Ok(())
    }

    // --- function addition and removal ----------------------------------------------------------

    /// `FunctionManager._function_added` for the cached parts: returning status, block count, signature source
    /// and name. Key functions are indexed separately (index_info).
    #[pyo3(signature = (addr, returning, block_count, from_signature, name))]
    pub fn function_added(
        &mut self,
        addr: u64,
        returning: Option<bool>,
        block_count: usize,
        from_signature: Option<String>,
        name: &str,
    ) {
        self.set_returning(addr, returning);
        self.block_counts.insert(addr, block_count);
        self.from_signature.insert(addr, from_signature);
        self.name_changed(addr, None, name);
    }

    /// The cache part of `FunctionManager.__delitem__`.
    pub fn function_removed(&mut self, addr: u64, previous_names: Vec<String>) {
        self.nonreturning.remove(&addr);
        self.unknown_returning.remove(&addr);
        self.block_counts.remove(addr);
        if let Some(name) = self.names.remove(&addr)
            && let Some(addrs) = self.name_to_addrs.get_mut(&name)
        {
            addrs.shift_remove(&addr);
            if addrs.is_empty() {
                self.name_to_addrs.remove(&name);
            }
        }
        self.from_signature.remove(addr);
        for old in previous_names {
            if let Some(s) = self.old_name_to_addrs.get_mut(&old) {
                s.shift_remove(&addr);
            }
        }
        for addrs in self.key_funcs.values_mut() {
            addrs.shift_remove(&addr);
        }
    }

    /// Drops every cache, keeping the addresses.
    pub fn clear_caches(&mut self) {
        let addrs = std::mem::take(&mut self.addrs);
        *self = Self::default();
        self.addrs = addrs;
    }

    // --- binary names and PLT stubs -------------------------------------------------------------

    /// `(True, name)` if `addr` is in a cached object range, else `(False, None)`.
    pub fn binary_name_cached(&self, addr: u64) -> (bool, Option<&str>) {
        match self.binnames.range(..=addr).next_back() {
            Some((_, (max_addr, name))) if addr < *max_addr => (true, name.as_deref()),
            _ => (false, None),
        }
    }

    #[pyo3(signature = (min_addr, max_addr, name))]
    pub fn cache_binary_name(&mut self, min_addr: u64, max_addr: u64, name: Option<String>) {
        self.binnames.insert(min_addr, (max_addr, name));
    }

    /// None if no cached object range contains `addr`; otherwise whether `addr` is a known PLT stub.
    pub fn plt_cached(&self, addr: u64) -> Option<bool> {
        match self.plt_ranges.range(..=addr).next_back() {
            Some((_, &max_addr)) if addr < max_addr => Some(self.plt_addrs.contains(&addr)),
            _ => None,
        }
    }

    pub fn is_plt_addr(&self, addr: u64) -> bool {
        self.plt_addrs.contains(&addr)
    }

    /// Caches an object range and, for objects with PLT information, its stubs.
    #[pyo3(signature = (min_addr, max_addr, plt_addrs=None))]
    pub fn cache_plt_range(&mut self, min_addr: u64, max_addr: u64, plt_addrs: Option<Vec<u64>>) {
        self.plt_ranges.entry(min_addr).or_insert(max_addr);
        if let Some(stubs) = plt_addrs {
            self.plt_addrs.extend(stubs);
        }
    }

    fn __repr__(&self) -> String {
        format!("<FunctionIndex: {} functions>", self.addrs.len())
    }
}

pub fn function_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FunctionCore>()?;
    m.add_class::<FunctionIndex>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_floor_ceiling_and_cursor() {
        let mut idx = FunctionIndex::new();
        for a in [0x30, 0x10, 0x20] {
            idx.add(a);
        }
        assert_eq!(idx.floor(0x1f), Some(0x10));
        assert_eq!(idx.floor(0x0f), None);
        assert_eq!(idx.ceiling(0x11), Some(0x20));
        assert_eq!(idx.ceiling(0x31), None);
        assert_eq!(idx.next_addr(None), Some(0x10));
        assert_eq!(idx.next_addr(Some(0x10)), Some(0x20));
        idx.discard(0x20);
        assert_eq!(idx.next_addr(Some(0x10)), Some(0x30));
        assert_eq!(
            idx.irange(Some(0x10), Some(0x30), (false, true), true),
            vec![0x30]
        );
    }

    #[test]
    fn name_changes_track_previous_names() {
        let mut idx = FunctionIndex::new();
        idx.name_changed(0x10, None, "a");
        idx.name_changed(0x10, Some("a"), "b");
        assert_eq!(idx.addrs_by_name("a", false), Vec::<u64>::new());
        assert_eq!(idx.addrs_by_name("a", true), vec![0x10]);
        assert_eq!(idx.name(0x10), Some("b"));
        idx.function_removed(0x10, vec!["a".into()]);
        assert!(idx.addrs_by_name("b", false).is_empty());
        assert_eq!(idx.addrs_by_name("a", true), Vec::<u64>::new());
    }
}
