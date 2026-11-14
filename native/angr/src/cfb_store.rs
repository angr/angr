//! The interval store behind `CFBlanket` (`angr.rustylib.cfb.CfbStore`).
//!
//! Address-keyed records in a `BTreeMap`. Most records are native (an `Unknown` gap piece, a trimmed `Block`, a
//! `MemoryData` of the CFG model, a trim of a Python object) and are materialized by the Python façade on access;
//! `PYOBJ` records pin the object passed to `add_obj`. `add_obj`, `carve` and `mark_unknowns` are line-by-line ports
//! of the SortedDict implementation, quirks included (see `tests/analyses/cfg/cfb_reference.py`).
//!
//! The state sits behind a mutex taken with `lock_py_attached`, and no Python code runs while it is held: objects
//! are inspected before locking, results are built after unlocking, and dropped objects are released after
//! unlocking. A GUI thread may read while the CFG thread writes.

use std::collections::BTreeMap;
use std::ops::Bound as RangeBound;
use std::sync::{Mutex, MutexGuard};

use pyo3::exceptions::{PyKeyError, PyOverflowError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::MutexExt;
use pyo3::types::{PyBytes, PyDict, PyInt, PyList, PyString, PyTuple, PyType, PyWeakrefReference};
use rustc_hash::FxHashMap;

use crate::function_graph::FunctionGraph;
use crate::memory_data::MemoryDataStore;

pub const KIND_PYOBJ: u8 = 0;
pub const KIND_UNKNOWN: u8 = 1;
pub const KIND_BLOCK_TRIM: u8 = 2;
pub const KIND_MD: u8 = 3;
pub const KIND_TRIM: u8 = 4;
/// A block of a function: `factory.block(key, size=size)`.
pub const KIND_BLOCK: u8 = 5;
/// A block with user-supplied bytes (in the slot): `factory.block(key, size=size, byte_string=bytes)`.
pub const KIND_BLOCK_BYTES: u8 = 6;

pub const CLASS_OTHER: u8 = 0;
pub const CLASS_BLOCK: u8 = 1;
pub const CLASS_MD: u8 = 2;
pub const CLASS_UNKNOWN: u8 = 3;

const F_SIZED: u8 = 1;
const F_THUMB: u8 = 2;
const CLASS_SHIFT: u8 = 2;
const CLASS_MASK: u8 = 3 << CLASS_SHIFT;

const MD_CODE_REFERENCE: &str = "code reference";

#[derive(Clone, Copy, Debug)]
struct Rec {
    size: i64,
    /// PYOBJ/TRIM: slot index; UNKNOWN: region id.
    payload: u32,
    /// Unique per write, so that events and cached objects can tell whether a record is still the current one.
    generation: u32,
    /// Interned MemoryData sort (0 = None).
    sort: u16,
    kind: u8,
    flags: u8,
}

impl Rec {
    fn new(kind: u8, class: u8, size: Option<i64>) -> Rec {
        Rec {
            size: size.unwrap_or(0),
            payload: 0,
            generation: 0,
            sort: 0,
            kind,
            flags: (class << CLASS_SHIFT) | if size.is_some() { F_SIZED } else { 0 },
        }
    }

    fn sized(&self) -> bool {
        self.flags & F_SIZED != 0
    }

    fn size_opt(&self) -> Option<i64> {
        self.sized().then_some(self.size)
    }

    fn class(&self) -> u8 {
        (self.flags & CLASS_MASK) >> CLASS_SHIFT
    }

    /// `max(size or 1, 1)`: the span an object covers when something else carves it.
    fn span(&self) -> u128 {
        if self.sized() && self.size > 0 {
            self.size as u128
        } else {
            1
        }
    }

    fn uses_slot(&self) -> bool {
        matches!(self.kind, KIND_PYOBJ | KIND_TRIM | KIND_BLOCK_BYTES)
    }
}

/// The Python object of a PYOBJ record, or the source of a TRIM record.
enum Src {
    Obj(Py<PyAny>),
    /// A MemoryData record of the CFG model, by address.
    Md(u64),
}

impl Src {
    fn clone_ref(&self, py: Python<'_>) -> Src {
        match self {
            Src::Obj(o) => Src::Obj(o.clone_ref(py)),
            Src::Md(a) => Src::Md(*a),
        }
    }
}

struct Ev {
    key: u64,
    rec: Rec,
    src: Option<Src>,
}

#[derive(Default)]
struct Inner {
    /// The project's architecture is ARM (Block forces Thumb on odd addresses).
    arm: bool,
    map: BTreeMap<u64, Rec>,
    slots: Vec<Option<Src>>,
    free: Vec<u32>,
    next_gen: u32,
    /// Weak references to the objects materialized for native records: (generation, weakref).
    cache: FxHashMap<u64, (u32, Py<PyWeakrefReference>)>,
    purge_at: usize,
    events: Vec<Ev>,
    sort_names: Vec<Option<String>>,
    sort_index: FxHashMap<String, u16>,
    scratch: Vec<u64>,
}

/// An object to add, inspected before the lock is taken.
struct NewObj {
    key: u64,
    rec: Rec,
    sort: Option<String>,
    obj: Py<PyAny>,
}

fn to_key(v: i128) -> PyResult<u64> {
    u64::try_from(v)
        .map_err(|_| PyOverflowError::new_err("CFBlanket addresses must fit in 64 bits"))
}

impl Inner {
    fn intern_sort(&mut self, sort: Option<&str>) -> u16 {
        if self.sort_names.is_empty() {
            self.sort_names.push(None);
        }
        let Some(name) = sort else { return 0 };
        if let Some(&i) = self.sort_index.get(name) {
            return i;
        }
        let i = u16::try_from(self.sort_names.len()).expect("too many memory data sorts");
        self.sort_names.push(Some(name.to_string()));
        self.sort_index.insert(name.to_string(), i);
        i
    }

    fn alloc_slot(&mut self, src: Src) -> u32 {
        if let Some(i) = self.free.pop() {
            self.slots[i as usize] = Some(src);
            i
        } else {
            self.slots.push(Some(src));
            u32::try_from(self.slots.len() - 1).expect("too many CFBlanket objects")
        }
    }

    fn release(&mut self, rec: &Rec, grave: &mut Vec<Src>) {
        if rec.uses_slot() {
            if let Some(src) = self.slots[rec.payload as usize].take() {
                grave.push(src);
            }
            self.free.push(rec.payload);
        }
    }

    fn slot(&self, rec: &Rec) -> Option<&Src> {
        if rec.uses_slot() {
            self.slots[rec.payload as usize].as_ref()
        } else {
            None
        }
    }

    fn put(
        &mut self,
        py: Python<'_>,
        key: u64,
        mut rec: Rec,
        src: Option<Src>,
        want: bool,
        grave: &mut Vec<Src>,
    ) {
        if let Some(src) = src {
            rec.payload = self.alloc_slot(src);
        }
        rec.generation = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        if let Some(old) = self.map.insert(key, rec) {
            self.release(&old, grave);
        }
        if !self.cache.is_empty() {
            self.cache.remove(&key);
        }
        if want {
            let src = self.slot(&rec).map(|s| s.clone_ref(py));
            self.events.push(Ev { key, rec, src });
        }
    }

    fn remove(&mut self, key: u64, grave: &mut Vec<Src>) -> Option<Rec> {
        let rec = self.map.remove(&key)?;
        self.release(&rec, grave);
        if !self.cache.is_empty() {
            self.cache.remove(&key);
        }
        Some(rec)
    }

    /// `CFBlanket._trim`: the record (and its slot) of `rec` at `key` trimmed to `new_size` bytes, or None if the
    /// object cannot be trimmed.
    fn trim(
        &self,
        py: Python<'_>,
        key: u64,
        rec: &Rec,
        new_size: u128,
    ) -> Option<(Rec, Option<Src>)> {
        if new_size == 0 {
            return None;
        }
        let size = Some(i64::try_from(new_size).ok()?);
        let class = rec.class();
        let mut out = match (rec.kind, class) {
            (KIND_UNKNOWN, _) => {
                let mut r = Rec::new(KIND_UNKNOWN, CLASS_UNKNOWN, size);
                r.payload = rec.payload;
                (r, None)
            }
            (KIND_BLOCK_TRIM | KIND_BLOCK | KIND_BLOCK_BYTES, _) | (KIND_PYOBJ, CLASS_BLOCK) => {
                let mut r = Rec::new(KIND_BLOCK_TRIM, CLASS_BLOCK, size);
                // the materialized Block is Thumb if asked to be or (on ARM) if its address is odd
                let thumb = match rec.kind {
                    KIND_PYOBJ => rec.flags & F_THUMB != 0,
                    _ => self.arm && (rec.flags & F_THUMB != 0 || key & 1 == 1),
                };
                if thumb {
                    r.flags |= F_THUMB;
                }
                (r, None)
            }
            (KIND_MD, _) => (Rec::new(KIND_TRIM, CLASS_MD, size), Some(Src::Md(key))),
            // a trim of a trim equals the same trim of the source
            (KIND_TRIM, _) => (
                Rec::new(KIND_TRIM, class, size),
                self.slot(rec).map(|s| s.clone_ref(py)),
            ),
            (KIND_PYOBJ, CLASS_MD | CLASS_UNKNOWN) => (
                Rec::new(KIND_TRIM, class, size),
                self.slot(rec).map(|s| s.clone_ref(py)),
            ),
            _ => return None,
        };
        out.0.sort = rec.sort;
        Some(out)
    }

    /// `CFBlanket._carve`: remove or trim the records that overlap [start, end), except that a record at `start` is
    /// left for the caller to overwrite.
    fn carve(&mut self, py: Python<'_>, start: u64, end: u128, want: bool, grave: &mut Vec<Src>) {
        let mut keys = std::mem::take(&mut self.scratch);
        keys.clear();
        if let Some((&k, r)) = self.map.range(..start).next_back()
            && k as u128 + r.span() > start as u128
        {
            keys.push(k);
        }
        let upper = if end > u64::MAX as u128 {
            RangeBound::Unbounded
        } else {
            RangeBound::Excluded(end as u64)
        };
        keys.extend(
            self.map
                .range((RangeBound::Included(start), upper))
                .map(|(&k, _)| k),
        );

        for &key in &keys {
            let rec = self.map[&key];
            let obj_end = key as u128 + rec.span();
            let left = if key < start {
                self.trim(py, key, &rec, (start - key) as u128)
            } else {
                None
            };
            let right = if obj_end > end {
                self.trim(py, key, &rec, obj_end - end)
            } else {
                None
            };
            if let Some((r, src)) = left {
                // overwriting keeps the key in place
                self.put(py, key, r, src, want, grave);
            } else if key != start {
                self.remove(key, grave);
            }
            if let Some((r, src)) = right
                && let Ok(end) = u64::try_from(end)
            {
                self.put(py, end, r, src, want, grave);
            }
        }
        self.scratch = keys;
    }

    /// `CFBlanket.add_obj`.
    fn add(
        &mut self,
        py: Python<'_>,
        key: u64,
        rec: Rec,
        src: Option<Src>,
        want: bool,
        grave: &mut Vec<Src>,
    ) {
        if rec.sized() && rec.size > 0 {
            self.carve(py, key, key as u128 + rec.size as u128, want, grave);
        }
        self.put(py, key, rec, src, want, grave);
    }

    fn floor_key(&self, addr: u64) -> Option<u64> {
        self.map.range(..=addr).next_back().map(|(&k, _)| k)
    }

    fn ceiling_key(&self, addr: u64) -> Option<u64> {
        self.map.range(addr..).next().map(|(&k, _)| k)
    }

    fn unknown(region: u32, size: u128) -> Rec {
        let mut r = Rec::new(KIND_UNKNOWN, CLASS_UNKNOWN, Some(size as i64));
        r.payload = region;
        r
    }

    /// `CFBlanket._mark_unknowns_core` for the region [min_addr, max_addr).
    #[allow(clippy::too_many_arguments)]
    fn mark_unknowns(
        &mut self,
        py: Python<'_>,
        min_addr: u64,
        max_addr: u128,
        region: u32,
        want: bool,
        grave: &mut Vec<Src>,
    ) -> PyResult<()> {
        if !self.floor_key(min_addr).is_some_and(|k| k >= min_addr) {
            let next_addr = match self.ceiling_key(min_addr) {
                Some(k) if (k as u128) < max_addr => k as u128,
                _ => max_addr,
            };
            let rec = Self::unknown(region, next_addr - min_addr as u128);
            self.add(py, min_addr, rec, None, want, grave);
        }

        let mut addr = min_addr as u128;
        while addr < max_addr {
            // addr is always a key: see the Python implementation
            let Some(&rec) = self.map.get(&(addr as u64)) else {
                return Err(PyKeyError::new_err(addr));
            };
            let size: i128 = if !rec.sized() || rec.size == 0 {
                1
            } else {
                rec.size as i128
            };
            let end_addr = addr as i128 + size;
            if end_addr < max_addr as i128 {
                let next_key = self.ceiling_key(end_addr.max(0) as u64);
                let next_addr = next_key.map_or(max_addr, |k| k as u128);
                if next_addr as i128 > end_addr {
                    let rec = Self::unknown(region, (next_addr as i128 - end_addr) as u128);
                    self.add(py, end_addr as u64, rec, None, want, grave);
                }
                addr = next_addr;
            } else {
                addr = max_addr;
            }
        }
        Ok(())
    }

    fn purge_cache(&mut self, py: Python<'_>, grave: &mut Vec<Py<PyWeakrefReference>>) {
        if self.cache.len() <= self.purge_at {
            return;
        }
        let dead: Vec<u64> = self
            .cache
            .iter()
            .filter(|(_, (_, w))| w.bind(py).upgrade().is_none())
            .map(|(&k, _)| k)
            .collect();
        for k in dead {
            if let Some((_, w)) = self.cache.remove(&k) {
                grave.push(w);
            }
        }
        self.purge_at = (self.cache.len() * 2).max(4096);
    }

    /// The cached live object of the current record at `key`, if any.
    fn cached<'py>(&self, py: Python<'py>, key: u64, rec: &Rec) -> Option<Bound<'py, PyAny>> {
        let (generation, w) = self.cache.get(&key)?;
        if *generation != rec.generation {
            return None;
        }
        w.bind(py).upgrade()
    }

    /// What the façade needs to hand out the record: the object if it exists, else a description to materialize.
    fn desc(&self, py: Python<'_>, key: u64, rec: &Rec, src: Option<&Src>, current: bool) -> Desc {
        if rec.kind == KIND_PYOBJ
            && let Some(Src::Obj(o)) = src
        {
            return Desc::Obj(o.clone_ref(py));
        }
        if current && let Some(o) = self.cached(py, key, rec) {
            return Desc::Obj(o.unbind());
        }
        Desc::Spec(key, *rec, src.map(|s| s.clone_ref(py)))
    }

    fn lookup_desc(&self, py: Python<'_>, key: u64) -> Option<Desc> {
        let rec = self.map.get(&key)?;
        Some(self.desc(py, key, rec, self.slot(rec), true))
    }
}

enum Desc {
    Obj(Py<PyAny>),
    Spec(u64, Rec, Option<Src>),
}

type SpecTuple<'py> = (
    usize,
    u64,
    u8,
    Option<i64>,
    u8,
    u32,
    u32,
    u16,
    Option<Bound<'py, PyAny>>,
);

fn spec_tuple<'py>(
    py: Python<'py>,
    idx: usize,
    key: u64,
    rec: &Rec,
    src: Option<Src>,
) -> PyResult<SpecTuple<'py>> {
    let src = match src {
        Some(Src::Obj(o)) => Some(o.into_bound(py)),
        Some(Src::Md(a)) => Some(a.into_pyobject(py)?.into_any()),
        None => None,
    };
    Ok((
        idx,
        key,
        rec.kind,
        rec.size_opt(),
        rec.flags,
        rec.payload,
        rec.generation,
        rec.sort,
        src,
    ))
}

/// (pairs, specs): `pairs` holds (key, obj) with obj None where `specs` has an entry
/// (index, key, kind, size, flags, payload, generation, sort, src) to materialize.
fn descs_to_py<'py>(
    py: Python<'py>,
    descs: Vec<(u64, Desc)>,
) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
    let pairs = PyList::empty(py);
    let specs = PyList::empty(py);
    for (idx, (key, d)) in descs.into_iter().enumerate() {
        match d {
            Desc::Obj(o) => pairs.append((key, o))?,
            Desc::Spec(k, rec, src) => {
                pairs.append((key, py.None()))?;
                specs.append(spec_tuple(py, idx, k, &rec, src)?)?;
            }
        }
    }
    Ok((pairs, specs))
}

/// The interval store of a `CFBlanket`.
#[pyclass(module = "angr.rustylib.cfb", frozen)]
pub struct CfbStore {
    inner: Mutex<Inner>,
    block_type: Py<PyType>,
    md_type: Py<PyType>,
    unknown_type: Py<PyType>,
}

impl CfbStore {
    fn lock(&self, py: Python<'_>) -> PyResult<MutexGuard<'_, Inner>> {
        self.inner
            .lock_py_attached(py)
            .map_err(|_| PyRuntimeError::new_err("CfbStore mutex poisoned"))
    }

    /// Inspect `obj` for `add_obj`: `CFBlanket._obj_size`, and what `_trim` would do with it.
    fn new_obj(&self, py: Python<'_>, key: u64, obj: Bound<'_, PyAny>) -> PyResult<NewObj> {
        let size = match obj.getattr_opt(pyo3::intern!(py, "size"))? {
            Some(s) if s.is_instance_of::<PyInt>() => Some(s.extract::<i64>()?),
            _ => None,
        };
        let mut sort = None;
        let class = if obj.is_instance(self.block_type.bind(py))? {
            CLASS_BLOCK
        } else if obj.is_instance(self.md_type.bind(py))? {
            sort = obj
                .getattr(pyo3::intern!(py, "sort"))?
                .extract::<Option<String>>()?;
            CLASS_MD
        } else if obj.is_instance(self.unknown_type.bind(py))? {
            CLASS_UNKNOWN
        } else {
            CLASS_OTHER
        };
        let mut rec = Rec::new(KIND_PYOBJ, class, size);
        if class == CLASS_BLOCK
            && obj
                .getattr_opt(pyo3::intern!(py, "thumb"))?
                .is_some_and(|t| t.is_truthy().unwrap_or(false))
        {
            rec.flags |= F_THUMB;
        }
        Ok(NewObj {
            key,
            rec,
            sort,
            obj: obj.unbind(),
        })
    }

    /// The Blocks of a CFG scan: (lift address, size) in creation order, keyed by the real address (`addr & ~1` on
    /// ARM, where an odd lift address is Thumb), lifted with options `profile` (see `KIND_BLOCK`).
    pub fn add_scan_blocks(
        &self,
        py: Python<'_>,
        blocks: &[(u64, u32)],
        profile: u32,
        want: bool,
    ) -> PyResult<()> {
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            let arm = s.arm;
            for &(addr, size) in blocks {
                let key = if arm { addr & !1 } else { addr };
                s.add(
                    py,
                    key,
                    Self::scan_rec(arm, addr, size, profile),
                    None,
                    want,
                    &mut grave,
                );
            }
        }
        drop(grave);
        Ok(())
    }

    fn scan_rec(arm: bool, lift_addr: u64, size: u32, profile: u32) -> Rec {
        let mut rec = Rec::new(KIND_BLOCK, CLASS_BLOCK, Some(size as i64));
        rec.payload = profile;
        if arm && lift_addr & 1 == 1 {
            rec.flags |= F_THUMB;
        }
        rec
    }

    fn add_new(&self, py: Python<'_>, objs: Vec<NewObj>, want: bool) -> PyResult<()> {
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            for o in objs {
                let mut rec = o.rec;
                rec.sort = s.intern_sort(o.sort.as_deref());
                s.add(py, o.key, rec, Some(Src::Obj(o.obj)), want, &mut grave);
            }
        }
        drop(grave);
        Ok(())
    }
}

#[pymethods]
impl CfbStore {
    #[new]
    fn new(
        block_type: Py<PyType>,
        md_type: Py<PyType>,
        unknown_type: Py<PyType>,
        arm: bool,
    ) -> Self {
        let mut inner = Inner {
            arm,
            ..Inner::default()
        };
        inner.intern_sort(None);
        inner.purge_at = 4096;
        CfbStore {
            inner: Mutex::new(inner),
            block_type,
            md_type,
            unknown_type,
        }
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.lock(py)?.map.len())
    }

    fn __contains__(&self, py: Python<'_>, key: i128) -> PyResult<bool> {
        let Ok(key) = u64::try_from(key) else {
            return Ok(false);
        };
        Ok(self.lock(py)?.map.contains_key(&key))
    }

    /// `add_obj(addr, obj)`; with `want_events`, its events are queued for `take_events`.
    fn add_obj(
        &self,
        py: Python<'_>,
        addr: i128,
        obj: Bound<'_, PyAny>,
        want_events: bool,
    ) -> PyResult<()> {
        let o = self.new_obj(py, to_key(addr)?, obj)?;
        self.add_new(py, vec![o], want_events)
    }

    /// `add_obj` for each (addr, obj) in order.
    fn add_objs(
        &self,
        py: Python<'_>,
        items: Bound<'_, PyList>,
        want_events: bool,
    ) -> PyResult<()> {
        let mut objs = Vec::with_capacity(items.len());
        for item in items.iter() {
            let t = item.cast_into::<PyTuple>()?;
            let addr: i128 = t.get_item(0)?.extract()?;
            objs.push(self.new_obj(py, to_key(addr)?, t.get_item(1)?)?);
        }
        self.add_new(py, objs, want_events)
    }

    /// `add_obj(addr, factory.block(addr, size=size, byte_string=bytes))` for every local block of each source, in
    /// order, without creating Blocks. A source is (FunctionGraph, {node id: user bytes} or None), (serialized graph,
    /// function address), or (list of (addr, size, bytes or None), None).
    fn add_function_blocks(
        &self,
        py: Python<'_>,
        sources: Vec<(Bound<'_, PyAny>, Bound<'_, PyAny>)>,
        want_events: bool,
    ) -> PyResult<()> {
        let mut blocks: Vec<(u64, u32, Option<Py<PyAny>>)> = Vec::new();
        for (src, extra) in sources {
            if let Ok(graph) = src.cast::<FunctionGraph>() {
                let graph = graph.borrow();
                let overrides = extra.cast::<PyDict>().ok();
                for (addr, idx) in graph.local_items() {
                    let bytes = match &overrides {
                        Some(d) => d.get_item(idx)?.map(Bound::unbind),
                        None => None,
                    };
                    blocks.push((addr, graph.node_size(idx)?, bytes));
                }
            } else if let Ok(data) = src.cast::<PyBytes>() {
                let graph = FunctionGraph::decode(data.as_bytes())?;
                let ea: u64 = extra.extract()?;
                if graph.func_addr() != ea {
                    return Err(PyValueError::new_err(format!(
                        "Function graph of {:#x} stored under {ea:#x}",
                        graph.func_addr()
                    )));
                }
                for (addr, idx) in graph.local_items() {
                    blocks.push((addr, graph.node_size(idx)?, None));
                }
            } else {
                for spec in src.cast::<PyList>()?.iter() {
                    let (addr, size, bytes): (u64, u32, Option<Bound<'_, PyAny>>) =
                        spec.extract()?;
                    blocks.push((addr, size, bytes.map(Bound::unbind)));
                }
            }
        }
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            for (addr, size, bytes) in blocks {
                let kind = if bytes.is_some() {
                    KIND_BLOCK_BYTES
                } else {
                    KIND_BLOCK
                };
                let rec = Rec::new(kind, CLASS_BLOCK, Some(size as i64));
                s.add(py, addr, rec, bytes.map(Src::Obj), want_events, &mut grave);
            }
        }
        drop(grave);
        Ok(())
    }

    /// Store each (addr, obj) without carving or events (states pickled from the SortedDict implementation).
    fn put_objs(&self, py: Python<'_>, items: Vec<(i128, Bound<'_, PyAny>)>) -> PyResult<()> {
        let mut objs = Vec::with_capacity(items.len());
        for (addr, obj) in items {
            objs.push(self.new_obj(py, to_key(addr)?, obj)?);
        }
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            for o in objs {
                let mut rec = o.rec;
                rec.sort = s.intern_sort(o.sort.as_deref());
                s.put(py, o.key, rec, Some(Src::Obj(o.obj)), false, &mut grave);
            }
        }
        drop(grave);
        Ok(())
    }

    /// Store an Unknown of region `region` at `addr` without carving (remove_obj's filler).
    fn set_unknown(
        &self,
        py: Python<'_>,
        addr: i128,
        size: i64,
        region: u32,
        want_events: bool,
    ) -> PyResult<()> {
        let key = to_key(addr)?;
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            let mut rec = Rec::new(KIND_UNKNOWN, CLASS_UNKNOWN, Some(size));
            rec.payload = region;
            s.put(py, key, rec, None, want_events, &mut grave);
        }
        drop(grave);
        Ok(())
    }

    /// Remove the record at `addr`: None, or (obj, spec) of the removed record (see `get`).
    fn pop<'py>(
        &self,
        py: Python<'py>,
        addr: i128,
    ) -> PyResult<Option<(Py<PyAny>, Option<SpecTuple<'py>>)>> {
        let Ok(key) = u64::try_from(addr) else {
            return Ok(None);
        };
        let mut grave = Vec::new();
        let desc = {
            let mut s = self.lock(py)?;
            let Some(d) = s.lookup_desc(py, key) else {
                return Ok(None);
            };
            s.remove(key, &mut grave);
            d
        };
        drop(grave);
        Ok(Some(match desc {
            Desc::Obj(o) => (o, None),
            Desc::Spec(k, rec, src) => (py.None(), Some(spec_tuple(py, 0, k, &rec, src)?)),
        }))
    }

    /// `CFBlanket._mark_unknowns_core` over (min_addr, max_addr, region) triples, in order.
    fn mark_unknowns(
        &self,
        py: Python<'_>,
        regions: Vec<(i128, i128, u32)>,
        want_events: bool,
    ) -> PyResult<()> {
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            for (lo, hi, region) in regions {
                let hi = u128::try_from(hi).unwrap_or(0);
                s.mark_unknowns(py, to_key(lo)?, hi, region, want_events, &mut grave)?;
            }
        }
        drop(grave);
        Ok(())
    }

    /// `CFBlanket._mark_memory_data`: add every record of `md` except code references, in address order.
    fn mark_memory_data(
        &self,
        py: Python<'_>,
        md: Bound<'_, MemoryDataStore>,
        want_events: bool,
    ) -> PyResult<()> {
        let recs: Vec<(u64, Option<i64>, Option<String>)> = {
            let md = md.borrow();
            md.inner
                .recs
                .iter()
                .filter_map(|(&a, r)| {
                    let sort = md.inner.sorts.name(r.sort);
                    if sort == Some(MD_CODE_REFERENCE) {
                        return None;
                    }
                    Some((
                        a,
                        r.size.and_then(|s| i64::try_from(s).ok()),
                        sort.map(str::to_string),
                    ))
                })
                .collect()
        };
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            for (addr, size, sort) in recs {
                let mut rec = Rec::new(KIND_MD, CLASS_MD, size);
                rec.sort = s.intern_sort(sort.as_deref());
                s.add(py, addr, rec, None, want_events, &mut grave);
            }
        }
        drop(grave);
        Ok(())
    }

    /// One scan Block (see `add_scan_blocks`) stored at `key`.
    fn add_scan_block(
        &self,
        py: Python<'_>,
        key: i128,
        lift_addr: u64,
        size: u32,
        profile: u32,
        want_events: bool,
    ) -> PyResult<()> {
        let key = to_key(key)?;
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            let rec = Self::scan_rec(s.arm, lift_addr, size, profile);
            s.add(py, key, rec, None, want_events, &mut grave);
        }
        drop(grave);
        Ok(())
    }

    /// The queued events as a CfbEvents batch, or None if there are none.
    fn take_event_batch(slf: &Bound<'_, Self>) -> PyResult<Option<CfbEvents>> {
        let py = slf.py();
        let evs = std::mem::take(&mut slf.get().lock(py)?.events);
        Ok((!evs.is_empty()).then(|| CfbEvents {
            store: slf.clone().unbind(),
            evs,
        }))
    }

    /// The queued events as (pairs, specs); see `scan`.
    fn take_events<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
        let descs: Vec<(u64, Desc)> = {
            let mut s = self.lock(py)?;
            let events = std::mem::take(&mut s.events);
            events
                .into_iter()
                .map(|ev| {
                    let current = s
                        .map
                        .get(&ev.key)
                        .is_some_and(|r| r.generation == ev.rec.generation);
                    (
                        ev.key,
                        s.desc(py, ev.key, &ev.rec, ev.src.as_ref(), current),
                    )
                })
                .collect()
        };
        descs_to_py(py, descs)
    }

    /// Remember the materialized objects (key, generation, obj) of current native records, weakly.
    fn cache_put(
        &self,
        py: Python<'_>,
        entries: Vec<(u64, u32, Bound<'_, PyAny>)>,
    ) -> PyResult<()> {
        let mut refs = Vec::with_capacity(entries.len());
        for (key, generation, obj) in entries {
            // objects that do not support weak references (MemoryData views) are not cached
            if let Ok(w) = PyWeakrefReference::new(&obj) {
                refs.push((key, generation, w.unbind()));
            }
        }
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            for (key, generation, w) in refs {
                if s.map
                    .get(&key)
                    .is_some_and(|r| r.generation == generation && r.kind != KIND_PYOBJ)
                    && let Some((_, old)) = s.cache.insert(key, (generation, w))
                {
                    grave.push(old);
                }
            }
            s.purge_cache(py, &mut grave);
        }
        drop(grave);
        Ok(())
    }

    /// (obj, spec) of the record at `addr`: obj is the object, or None with spec
    /// (0, key, kind, size, flags, payload, generation, sort, src) to materialize. KeyError if missing.
    fn get<'py>(
        &self,
        py: Python<'py>,
        addr: i128,
    ) -> PyResult<(Py<PyAny>, Option<SpecTuple<'py>>)> {
        let desc = match u64::try_from(addr) {
            Ok(key) => self.lock(py)?.lookup_desc(py, key),
            Err(_) => None,
        };
        match desc {
            None => Err(PyKeyError::new_err(addr)),
            Some(Desc::Obj(o)) => Ok((o, None)),
            Some(Desc::Spec(k, rec, src)) => {
                Ok((py.None(), Some(spec_tuple(py, 0, k, &rec, src)?)))
            }
        }
    }

    /// The greatest key <= addr.
    fn floor_key(&self, py: Python<'_>, addr: i128) -> PyResult<Option<u64>> {
        if addr < 0 {
            return Ok(None);
        }
        let s = self.lock(py)?;
        Ok(match u64::try_from(addr) {
            Ok(a) => s.floor_key(a),
            Err(_) => s.map.keys().next_back().copied(),
        })
    }

    /// The smallest key >= addr.
    fn ceiling_key(&self, py: Python<'_>, addr: i128) -> PyResult<Option<u64>> {
        let Ok(a) = u64::try_from(addr.max(0)) else {
            return Ok(None);
        };
        Ok(self.lock(py)?.ceiling_key(a))
    }

    /// All keys, ascending.
    fn keys(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        Ok(self.lock(py)?.map.keys().copied().collect())
    }

    /// Keys in [minimum, maximum] (either bound optional; `inclusive` per bound), ascending or descending.
    #[pyo3(signature = (minimum=None, maximum=None, inclusive=(true, true), reverse=false))]
    fn irange(
        &self,
        py: Python<'_>,
        minimum: Option<i128>,
        maximum: Option<i128>,
        inclusive: (bool, bool),
        reverse: bool,
    ) -> PyResult<Vec<u64>> {
        let Some((lo, hi)) = bounds(minimum, maximum, inclusive) else {
            return Ok(Vec::new());
        };
        let s = self.lock(py)?;
        let it = s.map.range((lo, hi)).map(|(&k, _)| k);
        Ok(if reverse {
            it.rev().collect()
        } else {
            it.collect()
        })
    }

    /// Up to `limit` records with keys in [minimum, maximum] (inclusive, optional), ascending or descending, as
    /// (pairs, specs): `pairs` holds (key, obj) with obj None where `specs` has an entry
    /// (index into pairs, key, kind, size, flags, payload, generation, sort, src) to materialize.
    #[pyo3(signature = (minimum, maximum, reverse, limit=None))]
    fn scan<'py>(
        &self,
        py: Python<'py>,
        minimum: Option<i128>,
        maximum: Option<i128>,
        reverse: bool,
        limit: Option<usize>,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
        let Some((lo, hi)) = bounds(minimum, maximum, (true, true)) else {
            return descs_to_py(py, Vec::new());
        };
        let limit = limit.unwrap_or(usize::MAX);
        let descs: Vec<(u64, Desc)> = {
            let s = self.lock(py)?;
            let mk = |(&k, r): (&u64, &Rec)| (k, s.desc(py, k, r, s.slot(r), true));
            let range = s.map.range((lo, hi));
            if reverse {
                range.rev().take(limit).map(mk).collect()
            } else {
                range.take(limit).map(mk).collect()
            }
        };
        descs_to_py(py, descs)
    }

    /// (addr, size, class, sort) of each record with a key in [minimum, maximum] (inclusive, optional), ascending.
    /// class is one of CLASS_*: the class of the object the record materializes to; sort is the MemoryData sort.
    #[pyo3(signature = (minimum=None, maximum=None))]
    fn intervals<'py>(
        &self,
        py: Python<'py>,
        minimum: Option<i128>,
        maximum: Option<i128>,
    ) -> PyResult<Bound<'py, PyList>> {
        let Some((lo, hi)) = bounds(minimum, maximum, (true, true)) else {
            return Ok(PyList::empty(py));
        };
        let (rows, names): (Vec<IntervalRow>, Vec<Option<String>>) = {
            let s = self.lock(py)?;
            (
                s.map
                    .range((lo, hi))
                    .map(|(&k, r)| (k, r.size_opt(), r.class(), r.sort))
                    .collect(),
                s.sort_names.clone(),
            )
        };
        let names: Vec<Option<Bound<'py, PyString>>> = names
            .iter()
            .map(|n| n.as_deref().map(|n| PyString::intern(py, n)))
            .collect();
        let out = PyList::empty(py);
        for (k, size, class, sort) in rows {
            out.append((k, size, class, names[sort as usize].clone()))?;
        }
        Ok(out)
    }

    /// Name of an interned sort.
    fn sort_name(&self, py: Python<'_>, sort: u16) -> PyResult<Option<String>> {
        let s = self.lock(py)?;
        Ok(s.sort_names.get(sort as usize).cloned().flatten())
    }

    /// Empty the store.
    fn clear(&self, py: Python<'_>) -> PyResult<()> {
        let old = {
            let mut s = self.lock(py)?;
            let fresh = Inner {
                arm: s.arm,
                purge_at: 4096,
                ..Inner::default()
            };
            std::mem::replace(&mut *s, fresh)
        };
        drop(old);
        let mut s = self.lock(py)?;
        s.intern_sort(None);
        Ok(())
    }

    /// (records, sort names) with records (key, kind, flags, size, payload, sort, src): src is the PYOBJ object, or
    /// the source object or MemoryData address of a TRIM record.
    fn state<'py>(&self, py: Python<'py>) -> PyResult<(Bound<'py, PyList>, Vec<Option<String>>)> {
        type Row = (u64, Rec, Option<Src>);
        let (rows, names): (Vec<Row>, Vec<Option<String>>) = {
            let s = self.lock(py)?;
            (
                s.map
                    .iter()
                    .map(|(&k, r)| (k, *r, s.slot(r).map(|x| x.clone_ref(py))))
                    .collect(),
                s.sort_names.clone(),
            )
        };
        let out = PyList::empty(py);
        for (k, r, src) in rows {
            let src: Option<Bound<'py, PyAny>> = match src {
                Some(Src::Obj(o)) => Some(o.into_bound(py)),
                Some(Src::Md(a)) => Some(a.into_pyobject(py)?.into_any()),
                None => None,
            };
            out.append((k, r.kind, r.flags, r.size, r.payload, r.sort, src))?;
        }
        Ok((out, names))
    }

    /// Restore `state()` output into an empty store.
    #[allow(clippy::type_complexity)]
    fn load_state(
        &self,
        py: Python<'_>,
        records: Vec<(u64, u8, u8, i64, u32, u16, Option<Bound<'_, PyAny>>)>,
        sort_names: Vec<Option<String>>,
    ) -> PyResult<()> {
        let mut srcs = Vec::with_capacity(records.len());
        for (k, kind, flags, size, payload, sort, src) in records {
            let src = match (kind, src) {
                (KIND_TRIM, Some(o)) if o.is_instance_of::<PyInt>() => Some(Src::Md(o.extract()?)),
                (KIND_PYOBJ | KIND_TRIM | KIND_BLOCK_BYTES, Some(o)) => Some(Src::Obj(o.unbind())),
                (KIND_PYOBJ, None) => Some(Src::Obj(py.None())),
                _ => None,
            };
            let rec = Rec {
                size,
                payload,
                generation: 0,
                sort,
                kind,
                flags,
            };
            srcs.push((k, rec, src));
        }
        let mut grave = Vec::new();
        {
            let mut s = self.lock(py)?;
            s.sort_index = sort_names
                .iter()
                .enumerate()
                .filter_map(|(i, n)| Some((n.clone()?, i as u16)))
                .collect();
            s.sort_names = sort_names;
            for (k, rec, src) in srcs {
                s.put(py, k, rec, src, false, &mut grave);
            }
        }
        drop(grave);
        Ok(())
    }
}

/// (addr, size, class, sort id)
type IntervalRow = (u64, Option<i64>, u8, u16);

type KeyBounds = (RangeBound<u64>, RangeBound<u64>);

/// Range bounds over u64 keys for Python-int bounds; None if the range is empty.
fn bounds(
    minimum: Option<i128>,
    maximum: Option<i128>,
    inclusive: (bool, bool),
) -> Option<KeyBounds> {
    let lo = match minimum {
        None => RangeBound::Unbounded,
        Some(m) if m < 0 => RangeBound::Unbounded,
        Some(m) => {
            let m = u64::try_from(m).ok()?;
            if inclusive.0 {
                RangeBound::Included(m)
            } else {
                RangeBound::Excluded(m)
            }
        }
    };
    let hi = match maximum {
        None => RangeBound::Unbounded,
        Some(m) if m < 0 => return None,
        Some(m) => match u64::try_from(m) {
            Ok(m) if inclusive.1 => RangeBound::Included(m),
            Ok(m) => RangeBound::Excluded(m),
            Err(_) => RangeBound::Unbounded,
        },
    };
    // BTreeMap::range panics on inverted or empty-excluded ranges
    let ok = match (lo, hi) {
        (RangeBound::Included(a), RangeBound::Included(b)) => a <= b,
        (RangeBound::Included(a), RangeBound::Excluded(b))
        | (RangeBound::Excluded(a), RangeBound::Included(b)) => a < b,
        (RangeBound::Excluded(a), RangeBound::Excluded(b)) => a < b && !(a + 1 == b),
        _ => true,
    };
    ok.then_some((lo, hi))
}

/// Events taken from a CfbStore, materialized on access: an event whose record is still current gives the stored
/// object, any other a copy of what was added.
#[pyclass(module = "angr.rustylib.cfb", frozen)]
pub struct CfbEvents {
    store: Py<CfbStore>,
    evs: Vec<Ev>,
}

#[pymethods]
impl CfbEvents {
    fn __len__(&self) -> usize {
        self.evs.len()
    }

    /// (pairs, specs) of events [start, stop), as `CfbStore.scan` gives them.
    fn descs<'py>(
        &self,
        py: Python<'py>,
        start: usize,
        stop: usize,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
        let stop = stop.min(self.evs.len());
        let start = start.min(stop);
        let descs: Vec<(u64, Desc)> = {
            let s = self.store.get().lock(py)?;
            self.evs[start..stop]
                .iter()
                .map(|ev| {
                    let current = s
                        .map
                        .get(&ev.key)
                        .is_some_and(|r| r.generation == ev.rec.generation);
                    (
                        ev.key,
                        s.desc(py, ev.key, &ev.rec, ev.src.as_ref(), current),
                    )
                })
                .collect()
        };
        descs_to_py(py, descs)
    }

    /// (addr, size, class, sort) of each event, as `CfbStore.intervals` gives them.
    fn intervals<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let names = self.store.get().lock(py)?.sort_names.clone();
        let names: Vec<Option<Bound<'py, PyString>>> = names
            .iter()
            .map(|n| n.as_deref().map(|n| PyString::intern(py, n)))
            .collect();
        let out = PyList::empty(py);
        for ev in &self.evs {
            out.append((
                ev.key,
                ev.rec.size_opt(),
                ev.rec.class(),
                names[ev.rec.sort as usize].clone(),
            ))?;
        }
        Ok(out)
    }

    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        visit.call(&self.store)?;
        for ev in &self.evs {
            if let Some(Src::Obj(o)) = &ev.src {
                visit.call(o)?;
            }
        }
        Ok(())
    }
}

pub fn cfb(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CfbStore>()?;
    m.add_class::<CfbEvents>()?;
    m.add("KIND_PYOBJ", KIND_PYOBJ)?;
    m.add("KIND_UNKNOWN", KIND_UNKNOWN)?;
    m.add("KIND_BLOCK_TRIM", KIND_BLOCK_TRIM)?;
    m.add("KIND_MD", KIND_MD)?;
    m.add("KIND_TRIM", KIND_TRIM)?;
    m.add("KIND_BLOCK", KIND_BLOCK)?;
    m.add("KIND_BLOCK_BYTES", KIND_BLOCK_BYTES)?;
    m.add("CLASS_OTHER", CLASS_OTHER)?;
    m.add("CLASS_BLOCK", CLASS_BLOCK)?;
    m.add("CLASS_MD", CLASS_MD)?;
    m.add("CLASS_UNKNOWN", CLASS_UNKNOWN)?;
    m.add("F_THUMB", F_THUMB)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_reject_empty_ranges() {
        assert!(bounds(Some(5), Some(4), (true, true)).is_none());
        assert!(bounds(Some(5), Some(5), (true, false)).is_none());
        assert!(bounds(Some(5), Some(6), (false, false)).is_none());
        assert!(bounds(Some(5), Some(5), (true, true)).is_some());
        assert!(bounds(None, Some(-1), (true, true)).is_none());
        assert!(bounds(Some(-3), None, (true, true)).is_some());
    }
}
