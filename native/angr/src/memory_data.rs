//! CFG memory data in Rust.
//!
//! `MemoryDataStore` (`angr.rustylib.memory_data.MemoryDataStore`) holds the `MemoryData` records of a `CFGModel`
//! keyed by address (addr, size, reference_size, sort, max_size, pointer_addr, content); Python `MemoryData`
//! objects are views over them. `tidy_data_references` and `merge_string_references` port
//! `CFGModel.tidy_data_references` (with `_guess_data_type`, `_fill_memory_data_gap` and the pointer-array
//! expansion) and `CFGFast._post_process_string_references` over a `LoaderSnapshot` and a `SegmentList`.
//! Every step mirrors the Python it replaces, quirks included, so that the recovered data stays byte-identical.

use std::collections::{BTreeMap, HashSet};

use pyo3::exceptions::{PyKeyError, PyOverflowError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use rustc_hash::FxHashMap;

use crate::cfg_scan::{LoaderSnapshot, PRINTABLE, Snapshot};
use crate::segmentlist::SegmentList;

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
            self.sort_py
                .push(name.map(|n| PyString::intern(py, n).unbind()));
        }
        self.sort_py[sort as usize]
            .as_ref()
            .map(|s| s.bind(py).clone())
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

    pub fn sort<'py>(
        &mut self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Option<Bound<'py, PyString>>> {
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

    pub fn content<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
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
    ) -> Vec<(
        u64,
        Option<i128>,
        Option<i128>,
        Option<Bound<'py, PyString>>,
        Option<i128>,
        Option<u64>,
    )> {
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

    /// `CFGFast._post_process_string_references`: concatenate the contents of adjacent non-null-terminated string
    /// records, unless that would touch `update_ratio` or more of all string records.
    #[pyo3(signature = (max_string_size=256, update_ratio=0.5))]
    pub fn merge_string_references(&mut self, max_string_size: usize, update_ratio: f64) -> usize {
        let recs: Vec<(&u64, &MdRec)> = self.inner.recs.iter().collect();
        let mut to_update: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut total_string_refs: usize = 0;
        for (i, &(&addr, md)) in recs.iter().enumerate() {
            if md.sort != SORT_STRING {
                continue;
            }
            total_string_refs += 1;
            let Some(content) = md.content.as_ref() else {
                continue;
            };
            let Some(size) = md.size.filter(|&s| s == content.len() as i128) else {
                // ending with a null byte
                continue;
            };
            let mut new_content = content.clone();
            let mut last_end_addr = addr as i128 + size;
            for &(&next_addr, next_md) in &recs[i + 1..] {
                match next_md.content.as_ref() {
                    Some(next_content)
                        if next_addr as i128 == last_end_addr && next_md.sort == SORT_STRING =>
                    {
                        new_content.extend_from_slice(next_content);
                        match next_md.size {
                            Some(s) if s == next_content.len() as i128 => {
                                last_end_addr = next_addr as i128 + s;
                            }
                            // ending with a null byte
                            _ => break,
                        }
                    }
                    _ => break,
                }
                if new_content.len() > max_string_size {
                    new_content.truncate(max_string_size);
                    break;
                }
            }
            if new_content.len() > content.len() {
                to_update.push((addr, new_content));
            }
        }
        let ratio = if total_string_refs == 0 {
            1.0
        } else {
            to_update.len() as f64 / total_string_refs as f64
        };
        if ratio >= update_ratio {
            return 0;
        }
        let n = to_update.len();
        for (addr, new_content) in to_update {
            let md = self.inner.recs.get_mut(&addr).expect("record exists");
            md.reference_size = Some(new_content.len() as i128);
            md.content = Some(new_content);
        }
        n
    }
}

// ---------------------------------------------------------------------------------------------------------------
// tidy_data_references
// ---------------------------------------------------------------------------------------------------------------

/// Python inputs of `CFGModel.tidy_data_references` that `_guess_data_type` reads.
struct Guesser<'a, 'py> {
    snap: &'a Snapshot,
    store: &'a Bound<'py, MemoryDataStore>,
    seg_list: Option<&'a Bound<'py, SegmentList>>,
    /// `xrefs is not None`
    has_xrefs: bool,
    /// `plt_xref(data_addr)`: some xref to `data_addr` comes from a PLT stub (None: not an ELF, no PLT)
    plt_xref: Option<&'a Bound<'py, PyAny>>,
    ptr_size: u64,
}

/// `(sort, size, content)`; sort None means "unknown".
type Guess = (Option<u16>, Option<i128>, Option<Vec<u8>>);
type GuessPy<'py> = (
    Option<Bound<'py, PyString>>,
    Option<i128>,
    Option<Bound<'py, PyBytes>>,
);

fn utf16le_decodes(data: &[u8], n: usize) -> bool {
    let s = &data[..data.len().min(n * 2)];
    if !s.len().is_multiple_of(2) {
        return false;
    }
    let units = s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c));
    char::decode_utf16(units).all(|c| c.is_ok())
}

fn is_printable(c: u8) -> bool {
    PRINTABLE[c as usize]
}

impl Guesser<'_, '_> {
    fn seg_occupied_by(&self, addr: u64) -> Option<Option<String>> {
        let seg = self.seg_list?.borrow();
        seg.is_occupied(addr).then(|| seg.occupied_by_sort(addr))
    }

    /// `CFGModel._guess_data_type`
    fn guess(
        &self,
        data_addr: u64,
        max_size: Option<i128>,
        fallback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Guess> {
        let snap = self.snap;
        let max_size = max_size.unwrap_or(0);

        // _guess_data_type_elfheader
        if let Some(oi) = snap.find_object_containing(data_addr, true)
            && data_addr == snap.objects[oi].min_addr
            && 4 < max_size
            && max_size < 1000
            && snap.load_bytes(data_addr, 4).as_deref() == Some(b"\x7fELF".as_slice())
        {
            return Ok((Some(SORT_ELF_HEADER), Some(max_size), None));
        }

        let ptr_size = self.ptr_size;

        if self.has_xrefs
            && self.seg_list.is_some()
            && let Some(plt_xref) = self.plt_xref
            && plt_xref.call1((data_addr,))?.extract::<bool>()?
        {
            return Ok((Some(SORT_GOT_PLT_ENTRY), Some(ptr_size as i128), None));
        }

        let Some(oi) = snap.find_object_containing(data_addr, true) else {
            return Ok((None, None, None));
        };
        let obj = &snap.objects[oi];
        if let Some(si) = obj.find_section_containing(data_addr)
            && obj.sections[si].only_uninit
        {
            return Ok((None, None, None));
        }

        // _guess_data_type_pointer_array
        let max_pointer_array_size = (512 * ptr_size as i128).min(max_size);
        let mut pointers_count: i128 = 0;
        let mut i: i128 = 0;
        while i < max_pointer_array_size {
            if let Some(ptr) = snap.load_word(data_addr.wrapping_add(i as u64), ptr_size as usize) {
                if snap.find_section_containing(ptr).is_some()
                    || snap.find_segment_containing(ptr).is_some()
                {
                    pointers_count += 1;
                } else {
                    break;
                }
            }
            i += ptr_size as i128;
        }
        if pointers_count > 0 {
            return Ok((
                Some(SORT_POINTER_ARRAY),
                Some(ptr_size as i128 * pointers_count),
                None,
            ));
        }

        let non_zero_max_size = if max_size == 0 { 1024 } else { max_size };
        let n = non_zero_max_size.min(1024);
        let data: Vec<u8> = if n > 0 {
            snap.load_bytes(data_addr, n as usize).unwrap_or_default()
        } else {
            Vec::new()
        };

        // UTF-16 string
        if data.len() >= 4 && data[1] == 0 && data[2] != 0 && data[3] == 0 && is_printable(data[0])
        {
            let can_decode = |n: usize| utf16le_decodes(&data, n);
            if can_decode(4) || can_decode(5) || can_decode(6) {
                let mut running_failures = 0;
                let mut last_success = 4usize;
                for i in 4..data.len() / 2 {
                    if can_decode(i) {
                        last_success = i;
                        running_failures = 0;
                        if data[i * 2 - 2] == 0 && data[i * 2 - 1] == 0 {
                            break;
                        }
                    } else {
                        running_failures += 1;
                        if running_failures > 3 {
                            break;
                        }
                    }
                }
                if last_success > 5 {
                    let mut string_data = data[..(last_success * 2).min(data.len())].to_vec();
                    if string_data.ends_with(b"\x00\x00") {
                        string_data.truncate(string_data.len() - 2);
                    }
                    return Ok((
                        Some(SORT_UNICODE),
                        Some(last_success as i128 * 2),
                        Some(string_data),
                    ));
                }
            }
        }

        // ASCII string
        if !data.is_empty() {
            let zero_pos = data.iter().position(|&c| c == 0);
            let prefix_printable =
                zero_pos.is_some_and(|z| z > 0 && data[..z].iter().all(|&c| is_printable(c)));
            if prefix_printable || data.iter().all(|&c| is_printable(c)) {
                let string_data = match zero_pos {
                    None => data.clone(),
                    Some(z) => data[..z].to_vec(),
                };
                let mut string_len = string_data.len() as i128;
                if zero_pos.is_some_and(|z| z != 0) {
                    string_len += 1;
                }
                return Ok((
                    Some(SORT_STRING),
                    Some(string_len.min(1024)),
                    Some(string_data),
                ));
            }
        }

        // code reference
        if self.has_xrefs
            && self.seg_list.is_some()
            && self
                .seg_occupied_by(data_addr)
                .is_some_and(|s| s.as_deref() == Some("code"))
        {
            return Ok((Some(SORT_CODE_REFERENCE), Some(0), None));
        }

        if let Some(fallback) = fallback {
            let r: Option<(String, Option<i128>)> =
                fallback.call1((data_addr, max_size))?.extract()?;
            if let Some((sort, size)) = r {
                let sort = self.store.borrow_mut().inner.sorts.intern(Some(&sort));
                return Ok((Some(sort), size, None));
            }
        }

        Ok((None, None, None))
    }
}

fn in_regions(regions: &[(u64, u64)], addr: u64) -> bool {
    regions
        .iter()
        .any(|&(start, end)| start <= addr && addr < end)
}

fn to_u64(v: i128) -> PyResult<u64> {
    u64::try_from(v)
        .map_err(|_| PyOverflowError::new_err("memory data address or size out of range"))
}

/// `CFGModel.tidy_data_references`. Returns `(new data found, new memory data addresses)`.
///
/// `copy_xrefs(old_addr, new_addr)` runs the xref copying of the Python version whenever a record is created from
/// another one; `guess_fallback(data_addr, max_size)` runs the user's `data_type_guessing_handlers` and returns
/// `(sort, size)` or None.
#[pyfunction]
#[pyo3(signature = (store, snapshot, memory_data_addrs=None, exec_mem_regions=None, seg_list=None,
                    has_xrefs=false, plt_xref=None, copy_xrefs=None, guess_fallback=None, fill_gaps=true))]
#[allow(clippy::too_many_arguments)]
pub fn tidy_data_references<'py>(
    store: &Bound<'py, MemoryDataStore>,
    snapshot: &Bound<'py, LoaderSnapshot>,
    memory_data_addrs: Option<Vec<u64>>,
    exec_mem_regions: Option<Vec<(u64, u64)>>,
    seg_list: Option<&Bound<'py, SegmentList>>,
    has_xrefs: bool,
    plt_xref: Option<&Bound<'py, PyAny>>,
    copy_xrefs: Option<&Bound<'py, PyAny>>,
    guess_fallback: Option<&Bound<'py, PyAny>>,
    fill_gaps: bool,
) -> PyResult<(bool, Vec<u64>)> {
    let snap_arc = snapshot.get().inner.clone();
    let snap: &Snapshot = &snap_arc;
    let ptr_size = snap.arch.bytes;
    let exec = exec_mem_regions.unwrap_or_default();
    let in_exec = |addr: u64| !exec.is_empty() && in_regions(&exec, addr);
    let g = Guesser {
        snap,
        store,
        seg_list,
        has_xrefs,
        plt_xref,
        ptr_size,
    };

    let keys: Vec<u64> = match memory_data_addrs {
        Some(mut k) => {
            k.sort_unstable();
            k
        }
        None => store.borrow().inner.recs.keys().copied().collect(),
    };

    // max sizes
    for (i, &data_addr) in keys.iter().enumerate() {
        if !store.borrow().inner.recs.contains_key(&data_addr) {
            return Err(missing(data_addr));
        }
        if in_exec(data_addr) {
            continue;
        }
        let next_data_addr = keys.get(i + 1).copied();
        let mut sec = snap.find_section_containing(data_addr);
        if sec.is_none() {
            sec = data_addr
                .checked_sub(1)
                .and_then(|a| snap.find_section_containing(a));
        }
        let mut next_sec_addr: Option<u64> = None;
        let last_addr: Option<i128> = match sec {
            Some((oi, si)) => {
                let s = &snap.objects[oi].sections[si];
                Some(s.vaddr as i128 + s.memsize as i128)
            }
            None => {
                if let Some((oi, si)) = snap.find_section_next_to(data_addr) {
                    next_sec_addr = Some(snap.objects[oi].sections[si].vaddr);
                }
                let mut seg = snap.find_segment_containing(data_addr);
                if seg.is_none() {
                    seg = data_addr
                        .checked_sub(1)
                        .and_then(|a| snap.find_segment_containing(a));
                }
                seg.map(|(oi, si)| {
                    let s = &snap.objects[oi].segments[si];
                    s.vaddr as i128 + s.memsize as i128
                })
            }
        };
        let mut boundary: Option<i128> = match (next_data_addr, last_addr) {
            (None, l) => l,
            (Some(n), None) => Some(n as i128),
            (Some(n), Some(l)) => Some(l.min(n as i128)),
        };
        if let (Some(b), Some(ns)) = (boundary, next_sec_addr) {
            boundary = Some(b.min(ns as i128));
        }
        let max_size = match boundary {
            Some(b) => b - data_addr as i128,
            None => 0,
        };
        store
            .borrow_mut()
            .inner
            .recs
            .get_mut(&data_addr)
            .expect("checked")
            .max_size = Some(max_size);
    }

    let mut new_data_found = false;
    let mut new_addrs: Vec<u64> = Vec::new();
    let empty_sorts: HashSet<Option<String>> = HashSet::new();

    // the gap record created while handling one entry is handled right after it (`keys.insert(i, new_addr)`)
    let mut pos = 0usize;
    let mut pending: Option<u64> = None;
    loop {
        let data_addr = match pending.take() {
            Some(a) => a,
            None if pos < keys.len() => {
                pos += 1;
                keys[pos - 1]
            }
            None => break,
        };
        let next_key = keys.get(pos).copied();

        let rec = store.borrow().rec(data_addr)?.clone();
        if rec.sort == SORT_SEGMENT_BOUNDARY {
            continue;
        }

        let guessed = rec.sort == SORT_UNKNOWN
            || rec.sort == SORT_UNSPECIFIED
            || (rec.sort == SORT_INTEGER
                && (rec.size == Some(0) || rec.size == Some(ptr_size as i128)));
        let (data_type, data_size, content) = if guessed {
            g.guess(data_addr, rec.max_size, guess_fallback)?
        } else {
            (Some(rec.sort), rec.size, None)
        };

        let mut size = rec.size;
        if let Some(data_type) = data_type {
            size = data_size;
            {
                let mut s = store.borrow_mut();
                let r = s.inner.recs.get_mut(&data_addr).expect("record exists");
                r.size = data_size;
                r.sort = data_type;
                if content.is_some() {
                    r.content = content;
                }
            }

            if fill_gaps
                && let (Some(max_size), Some(sz), Some(seg)) = (rec.max_size, data_size, seg_list)
                && 0 < sz
                && sz < max_size
            {
                // _fill_memory_data_gap
                let new_addr = to_u64(data_addr as i128 + sz)?;
                let next_free_pos = seg.borrow().next_free_pos(new_addr);
                let mut gap_addr = new_addr;
                let mut gap_max: i128 = max_size - sz;
                let next_obj_addr = store.borrow().inner.next_addr(new_addr);
                let mut fill = true;
                if let Some(next_obj_addr) = next_obj_addr {
                    let next_free_pos = next_free_pos
                        .ok_or_else(|| PyTypeError::new_err("SegmentList has no free position"))?;
                    if next_free_pos >= next_obj_addr {
                        fill = false;
                    } else {
                        gap_addr = next_free_pos;
                        gap_max = next_obj_addr as i128;
                    }
                }
                if fill {
                    gap_max = gap_max.min(data_addr as i128 + max_size - gap_addr as i128);
                    if let Some(next_key) = next_key {
                        gap_max = gap_max.min(next_key as i128 - gap_addr as i128);
                    }
                    if gap_max > 0 {
                        let rec = MdRec {
                            max_size: Some(gap_max),
                            ..MdRec::new(None, SORT_UNSPECIFIED)
                        };
                        store.borrow_mut().inner.recs.insert(gap_addr, rec);
                        if let Some(copy_xrefs) = copy_xrefs {
                            copy_xrefs.call1((data_addr, gap_addr))?;
                        }
                        pending = Some(gap_addr);
                    }
                }
            }

            if data_type == SORT_POINTER_ARRAY {
                let data_size = data_size.unwrap_or(0);
                let mut j: i128 = 0;
                while j < data_size {
                    let entry_addr = to_u64(data_addr as i128 + j)?;
                    j += ptr_size as i128;
                    let Some(ptr) = snap.load_word(entry_addr, ptr_size as usize) else {
                        // unmapped memory
                        break;
                    };
                    // is this pointer coming from the current binary?
                    match snap.find_object_containing(ptr, false) {
                        Some(oi) if snap.objects[oi].is_main => {}
                        _ => continue,
                    }

                    let mut ptr_guess: Guess = (Some(SORT_UNKNOWN), Some(0), None);
                    if seg_list.is_some() {
                        match g.seg_occupied_by(ptr) {
                            Some(sort) => {
                                if matches!(sort.as_deref(), Some("code") | Some("pointer-array")) {
                                    continue;
                                }
                            }
                            None => {
                                let next_data_addr =
                                    store.borrow().inner.next_addr(ptr.wrapping_add(1));
                                let max_data_size = match next_data_addr {
                                    None => 100,
                                    Some(n) => n as i128 - ptr as i128,
                                };
                                ptr_guess = g.guess(ptr, Some(max_data_size), None)?;
                            }
                        }
                    }

                    if store.borrow().inner.recs.contains_key(&ptr) {
                        continue;
                    }
                    let (ptr_sort, ptr_size_v, ptr_content) = ptr_guess;
                    store.borrow_mut().inner.recs.insert(
                        ptr,
                        MdRec {
                            pointer_addr: Some(entry_addr),
                            content: ptr_content,
                            ..MdRec::new(ptr_size_v, ptr_sort.unwrap_or(SORT_UNSPECIFIED))
                        },
                    );
                    if let (Some(ps), Some(pz), Some(seg)) = (ptr_sort, ptr_size_v, seg_list)
                        && pz > 0
                    {
                        let name = store.borrow().inner.sorts.name(ps).map(str::to_string);
                        seg.borrow_mut().occupy(ptr, to_u64(pz)?, name);
                    }
                    new_addrs.push(ptr);
                    if let Some(copy_xrefs) = copy_xrefs {
                        copy_xrefs.call1((data_addr, ptr))?;
                    }
                    new_data_found = true;
                }
            }
        } else if fill_gaps && !in_exec(data_addr) {
            // do not attempt to fill gaps in executable memory regions
            if let Some(max_size) = rec.max_size {
                let mut max_data_size = max_size;
                if let Some(seg) = seg_list
                    && let Some(next_occupied) =
                        seg.borrow()
                            .next_pos_with_sort_not_in(data_addr, empty_sorts.clone(), None)
                    && next_occupied > data_addr
                {
                    max_data_size = max_data_size.min(next_occupied as i128 - data_addr as i128);
                }
                size = Some(max_data_size);
                store
                    .borrow_mut()
                    .inner
                    .recs
                    .get_mut(&data_addr)
                    .expect("record exists")
                    .size = size;
            }
        }

        if let (Some(seg), Some(sz)) = (seg_list, size)
            && sz > 0
        {
            let s = store.borrow();
            let sort = s.inner.recs.get(&data_addr).expect("record exists").sort;
            let name = s.inner.sorts.name(sort).map(str::to_string);
            drop(s);
            seg.borrow_mut().occupy(data_addr, to_u64(sz)?, name);
        }
    }

    Ok((new_data_found, new_addrs))
}

/// `CFGModel._guess_data_type`: `(sort, size, content)`.
#[pyfunction]
#[pyo3(signature = (store, snapshot, data_addr, max_size, seg_list=None, has_xrefs=false, plt_xref=None,
                    guess_fallback=None))]
#[allow(clippy::too_many_arguments)]
pub fn guess_data_type<'py>(
    py: Python<'py>,
    store: &Bound<'py, MemoryDataStore>,
    snapshot: &Bound<'py, LoaderSnapshot>,
    data_addr: u64,
    max_size: Option<i128>,
    seg_list: Option<&Bound<'py, SegmentList>>,
    has_xrefs: bool,
    plt_xref: Option<&Bound<'py, PyAny>>,
    guess_fallback: Option<&Bound<'py, PyAny>>,
) -> PyResult<GuessPy<'py>> {
    let snap_arc = snapshot.get().inner.clone();
    let g = Guesser {
        snap: &snap_arc,
        store,
        seg_list,
        has_xrefs,
        plt_xref,
        ptr_size: snap_arc.arch.bytes,
    };
    let (sort, size, content) = g.guess(data_addr, max_size, guess_fallback)?;
    let sort = sort.and_then(|s| store.borrow_mut().sort_obj(py, s));
    Ok((sort, size, content.map(|c| PyBytes::new(py, &c))))
}

pub fn memory_data(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MemoryDataStore>()?;
    m.add_function(wrap_pyfunction!(tidy_data_references, m)?)?;
    m.add_function(wrap_pyfunction!(guess_data_type, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_prefix_validity() {
        let data = "ab\u{1F600}c"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();
        assert!(utf16le_decodes(&data, 2));
        // the prefix ends between the two halves of a surrogate pair
        assert!(!utf16le_decodes(&data, 3));
        assert!(utf16le_decodes(&data, 4));
        assert!(utf16le_decodes(&data, 100));
        // odd length
        assert!(!utf16le_decodes(&data[..3], 2));
    }

    #[test]
    fn string_merging_follows_the_ratio() {
        let mut s = MemoryDataStore::default();
        let mut add = |addr: u64, text: &[u8], size: i128| {
            s.inner.recs.insert(
                addr,
                MdRec {
                    content: Some(text.to_vec()),
                    ..MdRec::new(Some(size), SORT_STRING)
                },
            );
        };
        add(0x10, b"ab", 2);
        add(0x12, b"cd", 3);
        add(0x20, b"x", 2);
        add(0x30, b"y", 2);
        assert_eq!(s.merge_string_references(256, 0.5), 1);
        assert_eq!(
            s.inner.recs[&0x10].content.as_deref(),
            Some(b"abcd".as_slice())
        );
        assert_eq!(s.inner.recs[&0x10].reference_size, Some(4));
    }
}
