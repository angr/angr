//! CFG memory data in Rust.
//!
//! `MemoryDataStore` (`angr.rustylib.memory_data.MemoryDataStore`) holds the `MemoryData` records of a `CFGModel`
//! keyed by address (addr, size, reference_size, sort, max_size, pointer_addr, content); Python `MemoryData`
//! objects are views over them.

use std::collections::BTreeMap;

use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use rustc_hash::FxHashMap;


/// Interned sorts; `MemoryDataSort` values in declaration order. Index 0 is `None` (`Unspecified`).
pub const SORT_UNSPECIFIED: u16 = 0;
pub const SORT_UNKNOWN: u16 = 1;
pub const SORT_INTEGER: u16 = 2;
pub const SORT_POINTER_ARRAY: u16 = 3;
pub const SORT_STRING: u16 = 4;
pub const SORT_UNICODE: u16 = 5;
pub const SORT_SEGMENT_BOUNDARY: u16 = 6;
pub const SORT_CODE_REFERENCE: u16 = 7;
pub const SORT_GOT_PLT_ENTRY: u16 = 8;
pub const SORT_ELF_HEADER: u16 = 9;

const BUILTIN_SORTS: [&str; 19] = [
    "unknown",
    "integer",
    "pointer-array",
    "string",
    "unicode",
    "segment-boundary",
    "code reference",
    "GOT PLT Entry",
    "elf-header",
    "fp",
    "alignment",
    "pe-import-directory",
    "pe-export-directory",
    "pe-delay-import-directory",
    "eh-funcinfo",
    "eh-unwindmapentry",
    "eh4-scopetable",
    "eh-tryblockmap",
    "eh-handlertype",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MdRec {
    pub size: Option<i128>,
    pub reference_size: Option<i128>,
    pub max_size: Option<i128>,
    pub pointer_addr: Option<u64>,
    pub sort: u16,
    pub content: Option<Vec<u8>>,
}

impl MdRec {
    /// `MemoryData(addr, size, sort)` with every other field unset.
    pub fn new(size: Option<i128>, sort: u16) -> MdRec {
        MdRec {
            size,
            sort,
            ..MdRec::default()
        }
    }
}

/// The interned sort strings of one store.
#[derive(Clone, Debug)]
pub struct Sorts {
    names: Vec<Option<String>>,
    index: FxHashMap<String, u16>,
}

impl Default for Sorts {
    fn default() -> Self {
        let mut s = Sorts {
            names: vec![None],
            index: FxHashMap::default(),
        };
        for name in BUILTIN_SORTS {
            s.intern(Some(name));
        }
        s
    }
}

impl Sorts {
    pub fn intern(&mut self, sort: Option<&str>) -> u16 {
        let Some(name) = sort else {
            return SORT_UNSPECIFIED;
        };
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        let i = u16::try_from(self.names.len()).expect("too many memory data sorts");
        self.names.push(Some(name.to_string()));
        self.index.insert(name.to_string(), i);
        i
    }

    pub fn lookup(&self, sort: Option<&str>) -> Option<u16> {
        match sort {
            None => Some(SORT_UNSPECIFIED),
            Some(name) => self.index.get(name).copied(),
        }
    }

    pub fn name(&self, sort: u16) -> Option<&str> {
        self.names[sort as usize].as_deref()
    }
}

/// The records, sorted by address.
#[derive(Clone, Debug, Default)]
pub struct MdStore {
    pub recs: BTreeMap<u64, MdRec>,
    pub sorts: Sorts,
}

impl MdStore {
    /// `CFGModel.add_memory_data`: True if a new record was added.
    pub fn add_memory_data(&mut self, addr: u64, sort: Option<u16>, size: Option<i128>) -> bool {
        if self.recs.contains_key(&addr) {
            return false;
        }
        let rec = match (sort, size) {
            (Some(sort), Some(size)) => MdRec {
                max_size: Some(size),
                ..MdRec::new(Some(size), sort)
            },
            _ => MdRec::new(Some(0), SORT_UNKNOWN),
        };
        self.recs.insert(addr, rec);
        true
    }

    /// The lowest address at or after `addr` that has a record.
    pub fn next_addr(&self, addr: u64) -> Option<u64> {
        self.recs.range(addr..).next().map(|(&a, _)| a)
    }
}

type FieldsTuple<'py> = (
    Option<i128>,
    Option<i128>,
    Option<Bound<'py, PyString>>,
    Option<i128>,
    Option<u64>,
    Option<Bound<'py, PyBytes>>,
);

type StateRow = (
    u64,
    Option<i128>,
    Option<i128>,
    Option<String>,
    Option<i128>,
    Option<u64>,
    Option<Vec<u8>>,
);

#[pyclass(module = "angr.rustylib.memory_data")]
#[derive(Default)]
pub struct MemoryDataStore {
    pub inner: MdStore,
    /// Python strings of the interned sorts, parallel to `inner.sorts`.
    sort_py: Vec<Option<Py<PyString>>>,
}

fn missing(addr: u64) -> PyErr {
    PyKeyError::new_err(addr)
}

impl MemoryDataStore {
    fn sort_obj<'py>(&mut self, py: Python<'py>, sort: u16) -> Option<Bound<'py, PyString>> {
        while self.sort_py.len() < self.inner.sorts.names.len() {
            let name = self.inner.sorts.names[self.sort_py.len()].as_deref();
            self.sort_py.push(name.map(|n| PyString::intern(py, n).unbind()));
        }
        self.sort_py[sort as usize].as_ref().map(|s| s.bind(py).clone())
    }

    fn rec(&self, addr: u64) -> PyResult<&MdRec> {
        self.inner.recs.get(&addr).ok_or_else(|| missing(addr))
    }

    fn rec_mut(&mut self, addr: u64) -> PyResult<&mut MdRec> {
        self.inner.recs.get_mut(&addr).ok_or_else(|| missing(addr))
    }
}

#[pymethods]
impl MemoryDataStore {
    #[new]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn __len__(&self) -> usize {
        self.inner.recs.len()
    }

    pub fn __contains__(&self, addr: u64) -> bool {
        self.inner.recs.contains_key(&addr)
    }

    pub fn copy(&self) -> Self {
        MemoryDataStore {
            inner: self.inner.clone(),
            sort_py: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.inner.recs.clear();
    }

    /// All addresses in ascending order.
    pub fn addrs(&self) -> Vec<u64> {
        self.inner.recs.keys().copied().collect()
    }

    /// `SortedDict.irange` over the addresses.
    #[pyo3(signature = (minimum=None, maximum=None, inclusive=(true, true), reverse=false))]
    pub fn irange(
        &self,
        minimum: Option<u64>,
        maximum: Option<u64>,
        inclusive: (bool, bool),
        reverse: bool,
    ) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .inner
            .recs
            .range(minimum.unwrap_or(0)..)
            .map(|(&a, _)| a)
            .filter(|&a| inclusive.0 || Some(a) != minimum)
            .take_while(|&a| match maximum {
                None => true,
                Some(m) => a < m || (inclusive.1 && a == m),
            })
            .collect();
        if reverse {
            out.reverse();
        }
        out
    }

    /// The lowest address at or after `addr` that has a record.
    pub fn next_addr(&self, addr: u64) -> Option<u64> {
        self.inner.next_addr(addr)
    }

    /// `(size, reference_size, sort, max_size, pointer_addr, content)`
    pub fn fields<'py>(&mut self, py: Python<'py>, addr: u64) -> PyResult<FieldsTuple<'py>> {
        let rec = self.rec(addr)?.clone();
        Ok((
            rec.size,
            rec.reference_size,
            self.sort_obj(py, rec.sort),
            rec.max_size,
            rec.pointer_addr,
            rec.content.as_deref().map(|c| PyBytes::new(py, c)),
        ))
    }

    /// Inserts or overwrites the record at `addr`.
    #[pyo3(signature = (addr, size, reference_size, sort, max_size, pointer_addr, content))]
    #[allow(clippy::too_many_arguments)]
    pub fn set(
        &mut self,
        addr: u64,
        size: Option<i128>,
        reference_size: Option<i128>,
        sort: Option<&str>,
        max_size: Option<i128>,
        pointer_addr: Option<u64>,
        content: Option<&[u8]>,
    ) {
        let sort = self.inner.sorts.intern(sort);
        self.inner.recs.insert(
            addr,
            MdRec {
                size,
                reference_size,
                max_size,
                pointer_addr,
                sort,
                content: content.map(<[u8]>::to_vec),
            },
        );
    }

    pub fn remove(&mut self, addr: u64) -> bool {
        self.inner.recs.remove(&addr).is_some()
    }

    #[pyo3(signature = (addr, sort, size=None))]
    pub fn add_memory_data(&mut self, addr: u64, sort: Option<&str>, size: Option<i128>) -> bool {
        if self.inner.recs.contains_key(&addr) {
            return false;
        }
        let sort = sort.map(|s| self.inner.sorts.intern(Some(s)));
        self.inner.add_memory_data(addr, sort, size)
    }

    pub fn size(&self, addr: u64) -> PyResult<Option<i128>> {
        Ok(self.rec(addr)?.size)
    }

    pub fn set_size(&mut self, addr: u64, value: Option<i128>) -> PyResult<()> {
        self.rec_mut(addr)?.size = value;
        Ok(())
    }

    pub fn reference_size(&self, addr: u64) -> PyResult<Option<i128>> {
        Ok(self.rec(addr)?.reference_size)
    }

    pub fn set_reference_size(&mut self, addr: u64, value: Option<i128>) -> PyResult<()> {
        self.rec_mut(addr)?.reference_size = value;
        Ok(())
    }

    pub fn sort<'py>(&mut self, py: Python<'py>, addr: u64) -> PyResult<Option<Bound<'py, PyString>>> {
        let sort = self.rec(addr)?.sort;
        Ok(self.sort_obj(py, sort))
    }

    pub fn set_sort(&mut self, addr: u64, value: Option<&str>) -> PyResult<()> {
        self.rec(addr)?;
        let sort = self.inner.sorts.intern(value);
        self.rec_mut(addr)?.sort = sort;
        Ok(())
    }

    pub fn max_size(&self, addr: u64) -> PyResult<Option<i128>> {
        Ok(self.rec(addr)?.max_size)
    }

    pub fn set_max_size(&mut self, addr: u64, value: Option<i128>) -> PyResult<()> {
        self.rec_mut(addr)?.max_size = value;
        Ok(())
    }

    pub fn pointer_addr(&self, addr: u64) -> PyResult<Option<u64>> {
        Ok(self.rec(addr)?.pointer_addr)
    }

    pub fn set_pointer_addr(&mut self, addr: u64, value: Option<u64>) -> PyResult<()> {
        self.rec_mut(addr)?.pointer_addr = value;
        Ok(())
    }

    pub fn content<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self
            .rec(addr)?
            .content
            .as_deref()
            .map(|c| PyBytes::new(py, c)))
    }

    pub fn set_content(&mut self, addr: u64, value: Option<&[u8]>) -> PyResult<()> {
        self.rec_mut(addr)?.content = value.map(<[u8]>::to_vec);
        Ok(())
    }

    /// `(addr, size, reference_size, sort, max_size, pointer_addr)` of every record, by address.
    #[allow(clippy::type_complexity)]
    pub fn records<'py>(
        &mut self,
        py: Python<'py>,
    ) -> Vec<(u64, Option<i128>, Option<i128>, Option<Bound<'py, PyString>>, Option<i128>, Option<u64>)> {
        let rows: Vec<(u64, MdRec)> = self
            .inner
            .recs
            .iter()
            .map(|(&a, r)| {
                (
                    a,
                    MdRec {
                        content: None,
                        ..r.clone()
                    },
                )
            })
            .collect();
        rows.into_iter()
            .map(|(a, r)| {
                (
                    a,
                    r.size,
                    r.reference_size,
                    self.sort_obj(py, r.sort),
                    r.max_size,
                    r.pointer_addr,
                )
            })
            .collect()
    }

    pub fn __getstate__(&self) -> Vec<StateRow> {
        self.inner
            .recs
            .iter()
            .map(|(&a, r)| {
                (
                    a,
                    r.size,
                    r.reference_size,
                    self.inner.sorts.name(r.sort).map(str::to_string),
                    r.max_size,
                    r.pointer_addr,
                    r.content.clone(),
                )
            })
            .collect()
    }

    pub fn __setstate__(&mut self, state: Vec<StateRow>) {
        self.inner = MdStore::default();
        self.sort_py.clear();
        for (a, size, reference_size, sort, max_size, pointer_addr, content) in state {
            let sort = self.inner.sorts.intern(sort.as_deref());
            self.inner.recs.insert(
                a,
                MdRec {
                    size,
                    reference_size,
                    max_size,
                    pointer_addr,
                    sort,
                    content,
                },
            );
        }
    }
}

pub fn memory_data(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MemoryDataStore>()?;
    Ok(())
}
