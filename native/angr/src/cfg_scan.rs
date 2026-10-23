//! Immutable loader snapshot for CFG recovery.
//!
//! `LoaderSnapshot` (`angr.rustylib.cfg_scan.LoaderSnapshot`) is an immutable copy of what CFGFast needs from
//! cle: objects, sections, segments, symbols, arch constants, and zero-copy references to the loader's memory
//! backers. Queries mirror the cle methods they replace, without cle's last-hit caches.

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::BTreeSet;
use std::sync::Arc;

// ---------------------------------------------------------------------------------------------------------------
// Snapshot data
// ---------------------------------------------------------------------------------------------------------------

/// Which cle backend an object was loaded with, in the order `CFGBase._executable_memory_regions` tests them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackendKind {
    Elf,
    Pe,
    Xbe,
    MachO,
    HexSrec,
    Blob,
    NamedRegion,
    PeStubs,
    Pseudo,
    Other,
}

impl BackendKind {
    fn from_u8(v: u8) -> PyResult<Self> {
        Ok(match v {
            0 => Self::Elf,
            1 => Self::Pe,
            2 => Self::Xbe,
            3 => Self::MachO,
            4 => Self::HexSrec,
            5 => Self::Blob,
            6 => Self::NamedRegion,
            7 => Self::PeStubs,
            8 => Self::Pseudo,
            9 => Self::Other,
            _ => return Err(PyValueError::new_err(format!("unknown backend kind {v}"))),
        })
    }
}

type RegionTuple = (
    u64,
    u64,
    Option<u64>,
    Option<String>,
    bool,
    bool,
    bool,
    bool,
);

#[derive(Clone, Debug)]
pub struct RegionInfo {
    pub vaddr: u64,
    pub memsize: u64,
    /// `None` for regions without file backing (extern segments).
    pub filesize: Option<u64>,
    pub name: Option<String>,
    pub is_executable: bool,
    pub is_readable: bool,
    pub is_writable: bool,
    pub only_uninit: bool,
}

impl RegionInfo {
    pub fn end(&self) -> u64 {
        self.vaddr.wrapping_add(self.memsize)
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.vaddr <= addr && addr < self.end()
    }

    fn as_tuple(&self) -> RegionTuple {
        (
            self.vaddr,
            self.memsize,
            self.filesize,
            self.name.clone(),
            self.is_executable,
            self.is_readable,
            self.is_writable,
            self.only_uninit,
        )
    }
}

#[derive(Clone, Debug)]
pub struct SymbolInfo {
    pub relative_addr: i64,
    pub rebased_addr: u64,
    pub size: u64,
    pub is_function: bool,
    pub is_import: bool,
    pub name: Option<String>,
}

impl SymbolInfo {
    fn as_tuple(&self) -> (u64, u64, bool, Option<String>) {
        (
            self.rebased_addr,
            self.size,
            self.is_function,
            self.name.clone(),
        )
    }
}

/// `Clemory.min_addr`, `max_addr`, `consecutive` of an object's own memory (RVA based).
#[derive(Clone, Copy, Debug)]
pub struct MemInfo {
    pub min: u64,
    pub max: u64,
    pub consecutive: bool,
}

/// A zero-copy reference to one leaf backer (a `bytearray` or any other buffer-protocol object).
pub struct Backer {
    pub start: u64,
    buf: PyBuffer<u8>,
    ptr: *const u8,
    len: usize,
}

// The buffer export pins the Python object's storage for as long as the snapshot lives; the GIL serializes
// Python-side writes against our reads.
unsafe impl Send for Backer {}
unsafe impl Sync for Backer {}

impl Backer {
    fn new(start: u64, obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        let buf = PyBuffer::<u8>::get(obj)?;
        if !buf.is_c_contiguous() || buf.item_size() != 1 {
            return Err(PyTypeError::new_err(
                "memory backers must be contiguous byte buffers",
            ));
        }
        let ptr = buf.buf_ptr() as *const u8;
        let len = buf.len_bytes();
        Ok(Self {
            start,
            buf,
            ptr,
            len,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn end(&self) -> u64 {
        self.start.wrapping_add(self.len as u64)
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end()
    }

    pub fn bytes(&self) -> &[u8] {
        debug_assert_eq!(self.buf.len_bytes(), self.len);
        // SAFETY: the export keeps the buffer alive and fixed in size for the lifetime of `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

pub struct ObjectInfo {
    pub min_addr: u64,
    pub max_addr: u64,
    pub mapped_base: u64,
    pub kind: BackendKind,
    pub is_main: bool,
    pub has_memory: bool,
    pub is_outer: bool,
    /// `None` when the object's memory is not a `Clemory` (membership checks then always pass).
    pub mem: Option<MemInfo>,
    pub sections: Vec<RegionInfo>,
    pub segments: Vec<RegionInfo>,
    /// Indices into `sections`/`segments` in `Regions._sorted_list` order (mapped regions only).
    sections_sorted: Vec<usize>,
    segments_sorted: Vec<usize>,
    /// In `Backend.symbols` order (a `SortedKeyList` keyed by `relative_addr`).
    pub symbols: Vec<SymbolInfo>,
    /// `Hex`/`SRec` `regions`: `(addr, size)`.
    pub hex_regions: Vec<(u64, u64)>,
    /// Leaf backers of the object's own memory, RVA based.
    pub backers: Vec<Backer>,
}

impl ObjectInfo {
    /// `Regions.find_region_containing` without the backend's last-hit cache: cle's `key_bisect_find` over
    /// `Regions._sorted_list` keyed by region end. Overlapping regions make the key non-monotonic, so the bisection
    /// is replicated step by step instead of using `partition_point`.
    fn find_region(regions: &[RegionInfo], sorted: &[usize], addr: u64) -> Option<usize> {
        let (mut lo, mut hi) = (0usize, sorted.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if regions[sorted[mid]].end() <= addr {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let i = *sorted.get(lo)?;
        regions[i].contains(addr).then_some(i)
    }

    pub fn find_section_containing(&self, addr: u64) -> Option<usize> {
        Self::find_region(&self.sections, &self.sections_sorted, addr)
    }

    pub fn find_segment_containing(&self, addr: u64) -> Option<usize> {
        Self::find_region(&self.segments, &self.segments_sorted, addr)
    }

    /// `rva in obj.memory`.
    pub fn memory_contains_rva(&self, rva: u64) -> bool {
        let Some(mem) = self.mem else {
            return true;
        };
        if mem.consecutive {
            return mem.min <= rva && rva < mem.max;
        }
        if self.backers.is_empty() || rva < mem.min || rva >= mem.max {
            return false;
        }
        self.backers.iter().any(|b| b.contains(rva))
    }
}

#[derive(Clone, Debug)]
pub struct ArchInfo {
    pub name: String,
    pub bytes: u64,
    pub bits: u64,
    pub big_endian: bool,
    /// 0 when the arch leaves `instruction_alignment` unset.
    pub instruction_alignment: u64,
    pub nop_instruction: Vec<u8>,
    pub function_prologs: Vec<Vec<u8>>,
    pub thumb_prologs: Vec<Vec<u8>>,
    pub branch_delay_slot: bool,
    pub call_pushes_ret: bool,
}

impl ArchInfo {
    pub fn is_arm(&self) -> bool {
        self.name.starts_with("ARM")
    }
}

pub struct Snapshot {
    pub objects: Vec<ObjectInfo>,
    /// `objects[..loader_object_count]` is `loader.all_objects`; anything after it was appended explicitly.
    pub loader_object_count: usize,
    pub loader_min_addr: u64,
    pub loader_max_addr: u64,
    /// Leaf backers of `loader.memory`, in `Clemory.backers()` order.
    pub backers: Vec<Backer>,
    /// Backers are sorted by start and do not overlap, so point queries can bisect.
    simple_backers: bool,
    pub arch: ArchInfo,
}

impl Snapshot {
    /// The first backer (in order) containing `addr`: `Clemory.__getitem__`.
    fn backer_containing(&self, addr: u64) -> Option<&Backer> {
        if self.simple_backers {
            let pos = self.backers.partition_point(|b| b.start <= addr);
            let b = &self.backers[pos.checked_sub(1)?];
            return b.contains(addr).then_some(b);
        }
        self.backers.iter().find(|b| b.contains(addr))
    }

    /// Index of the first backer (in order) whose end is past `addr`: `next(Clemory.backers(addr))`.
    fn backer_ending_after(&self, addr: u64) -> Option<usize> {
        if self.simple_backers {
            let pos = self.backers.partition_point(|b| b.end() <= addr);
            return (pos < self.backers.len()).then_some(pos);
        }
        self.backers.iter().position(|b| b.end() > addr)
    }

    /// `loader.memory[addr]`.
    pub fn load_byte(&self, addr: u64) -> Option<u8> {
        let b = self.backer_containing(addr)?;
        Some(b.bytes()[(addr - b.start) as usize])
    }

    /// `loader.memory.unpack_word(addr, size=size)` with the loader's endianness; `None` when the word is
    /// unmapped or straddles two backers (a `KeyError` in Python).
    pub fn load_word(&self, addr: u64, size: usize) -> Option<u64> {
        debug_assert!((1..=8).contains(&size));
        let b = &self.backers[self.backer_ending_after(addr)?];
        if b.start > addr {
            return None;
        }
        let off = (addr - b.start) as usize;
        let data = b.bytes().get(off..off + size)?;
        Some(if self.arch.big_endian {
            data.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)
        } else {
            data.iter()
                .rev()
                .fold(0u64, |acc, &x| (acc << 8) | x as u64)
        })
    }

    /// `loader.memory.load(addr, n)`: reads across adjacent backers, stops at the first gap, `None` when
    /// nothing is mapped at `addr`.
    pub fn load_bytes(&self, addr: u64, n: usize) -> Option<Vec<u8>> {
        let mut idx = self.backer_ending_after(addr)?;
        let mut addr = addr;
        let mut n = n;
        let mut out: Vec<u8> = Vec::new();
        while idx < self.backers.len() {
            let b = &self.backers[idx];
            if b.start > addr {
                break;
            }
            let off = (addr - b.start) as usize;
            let take = n.min(b.len() - off);
            out.extend_from_slice(&b.bytes()[off..off + take]);
            addr += take as u64;
            n -= take;
            if n == 0 {
                break;
            }
            idx += 1;
        }
        if out.is_empty() { None } else { Some(out) }
    }

    /// The lowest mapped address at or after `addr`.
    pub fn next_mapped_addr(&self, addr: u64) -> Option<u64> {
        self.backers
            .iter()
            .filter(|b| b.end() > addr)
            .map(|b| b.start.max(addr))
            .min()
    }

    /// `loader.find_object_containing(addr, membership_check)` without the last-object cache.
    pub fn find_object_containing(&self, addr: u64, membership_check: bool) -> Option<usize> {
        if self.loader_object_count == 0
            || addr > self.loader_max_addr
            || addr < self.loader_min_addr
        {
            return None;
        }
        let loader_objs = &self.objects[..self.loader_object_count];
        let pos = loader_objs.partition_point(|o| o.min_addr <= addr);
        let idx = pos.checked_sub(1)?;
        let obj = &loader_objs[idx];
        if obj.is_outer || !(obj.min_addr <= addr && addr <= obj.max_addr) {
            return None;
        }
        if !membership_check || !obj.has_memory {
            return Some(idx);
        }
        obj.memory_contains_rva(addr.wrapping_sub(obj.mapped_base))
            .then_some(idx)
    }

    /// `loader.find_section_containing(addr)` (pseudo objects skipped).
    pub fn find_section_containing(&self, addr: u64) -> Option<(usize, usize)> {
        let oi = self.find_object_containing(addr, false)?;
        let obj = &self.objects[oi];
        if obj.kind == BackendKind::Pseudo {
            return None;
        }
        obj.find_section_containing(addr).map(|si| (oi, si))
    }

    /// `loader.find_segment_containing(addr)` (pseudo objects skipped).
    pub fn find_segment_containing(&self, addr: u64) -> Option<(usize, usize)> {
        let oi = self.find_object_containing(addr, false)?;
        let obj = &self.objects[oi];
        if obj.kind == BackendKind::Pseudo {
            return None;
        }
        obj.find_segment_containing(addr).map(|si| (oi, si))
    }

    /// `CFGBase._addrs_belong_to_same_segment`.
    pub fn addrs_belong_to_same_segment(&self, a: u64, b: u64) -> bool {
        let Some(oi) = self.find_object_containing(a, false) else {
            return self.find_object_containing(b, false).is_none();
        };
        let obj = &self.objects[oi];
        match obj.find_segment_containing(a) {
            None => obj.find_segment_containing(b).is_none(),
            Some(si) => obj.segments[si].contains(b),
        }
    }

    /// `CFGBase._addrs_belong_to_same_section`.
    pub fn addrs_belong_to_same_section(&self, a: u64, b: u64) -> bool {
        let Some(oi) = self.find_object_containing(a, false) else {
            return self.find_object_containing(b, false).is_none();
        };
        let obj = &self.objects[oi];
        match obj.find_section_containing(a) {
            None => {
                if obj.find_section_containing(b).is_none() {
                    self.addrs_belong_to_same_segment(a, b)
                } else {
                    false
                }
            }
            Some(si) => obj.sections[si].contains(b),
        }
    }

    /// `loader.find_symbol(addr, fuzzy=True)`: the last non-import symbol at or before `addr` in the object
    /// containing it.
    pub fn floor_symbol(&self, addr: u64) -> Option<&SymbolInfo> {
        let oi = self.find_object_containing(addr, true)?;
        let obj = &self.objects[oi];
        let rva = addr as i64 - obj.mapped_base as i64;
        let mut idx = obj.symbols.partition_point(|s| s.relative_addr <= rva);
        while idx > 0 {
            idx -= 1;
            if !obj.symbols[idx].is_import {
                return Some(&obj.symbols[idx]);
            }
        }
        None
    }

    /// `loader.find_symbol(addr)`: a non-import symbol at exactly `addr`, searching every loader object.
    pub fn symbol_at(&self, addr: u64) -> Option<&SymbolInfo> {
        for obj in &self.objects[..self.loader_object_count] {
            let rva = addr as i64 - obj.mapped_base as i64;
            let mut idx = obj.symbols.partition_point(|s| s.relative_addr <= rva);
            while idx > 0 && obj.symbols[idx - 1].rebased_addr == addr {
                idx -= 1;
                if !obj.symbols[idx].is_import {
                    return Some(&obj.symbols[idx]);
                }
            }
        }
        None
    }

    /// The first non-import symbol at or after `addr` in the object containing it.
    pub fn ceiling_symbol(&self, addr: u64) -> Option<&SymbolInfo> {
        let oi = self.find_object_containing(addr, true)?;
        let obj = &self.objects[oi];
        let rva = addr as i64 - obj.mapped_base as i64;
        let idx = obj.symbols.partition_point(|s| s.relative_addr < rva);
        obj.symbols[idx..].iter().find(|s| !s.is_import)
    }

    /// `CFGBase._executable_memory_regions(objects, force_segment)`.
    pub fn executable_memory_regions(
        &self,
        objects: Option<&[usize]>,
        force_segment: bool,
    ) -> Vec<(u64, u64)> {
        fn mapped_range(r: &RegionInfo) -> (u64, u64) {
            (
                r.vaddr,
                r.vaddr + r.memsize.min(r.filesize.unwrap_or(r.memsize)),
            )
        }

        let all: Vec<usize> = (0..self.loader_object_count).collect();
        let objects = objects.unwrap_or(&all);
        let mut regions: Vec<(u64, u64)> = Vec::new();
        let mut examined_any_object = false;

        for &oi in objects {
            let b = &self.objects[oi];
            if !b.has_memory {
                continue;
            }
            examined_any_object = true;
            match b.kind {
                BackendKind::Elf => {
                    let mut sections: Vec<(u64, u64)> = Vec::new();
                    if !force_segment && !b.sections.is_empty() {
                        sections.extend(
                            b.sections
                                .iter()
                                .filter(|s| s.is_executable)
                                .map(mapped_range),
                        );
                        regions.extend_from_slice(&sections);
                    }
                    let segments: Vec<(u64, u64)> = b
                        .segments
                        .iter()
                        .filter(|s| s.is_executable)
                        .map(mapped_range)
                        .collect();
                    if (b.sections.is_empty() && !segments.is_empty()) || force_segment {
                        regions.extend_from_slice(&segments);
                    } else if !sections.is_empty() && !segments.is_empty() {
                        for seg in &segments {
                            if !sections.iter().any(|sec| seg.0 <= sec.0 && sec.0 < seg.1) {
                                regions.push(*seg);
                            }
                        }
                    }
                }
                BackendKind::Pe => {
                    regions.extend(
                        b.sections
                            .iter()
                            .filter(|s| s.is_executable)
                            .map(mapped_range),
                    );
                }
                BackendKind::Xbe => {
                    for s in &b.sections {
                        let name_is_data =
                            matches!(s.name.as_deref(), Some(".data" | ".rdata" | ".rodata"));
                        if s.is_executable && !s.is_writable && !name_is_data {
                            regions.push((s.vaddr, s.end().wrapping_sub(1)));
                        }
                    }
                }
                BackendKind::MachO => {
                    // The whole of __TEXT is r-x; executable sections inside an executable segment are the regions.
                    // cle MachO sections carry no segment link in the snapshot, so the Python side pre-filters
                    // them: a MachO section is marked executable only when its segment is executable as well.
                    if !b.segments.is_empty() {
                        regions.extend(
                            b.sections
                                .iter()
                                .filter(|s| s.is_executable)
                                .map(mapped_range),
                        );
                    }
                }
                BackendKind::HexSrec => {
                    regions.extend(b.hex_regions.iter().map(|&(a, s)| (a, a + s)));
                }
                BackendKind::Blob => regions.push((b.min_addr, b.max_addr + 1)),
                BackendKind::NamedRegion | BackendKind::PeStubs | BackendKind::Pseudo => {}
                BackendKind::Other => {
                    if !b.sections.is_empty() {
                        regions.extend(
                            b.sections
                                .iter()
                                .filter(|s| s.is_executable)
                                .map(mapped_range),
                        );
                    } else if !b.segments.is_empty() {
                        regions.extend(
                            b.segments
                                .iter()
                                .filter(|s| s.is_executable)
                                .map(mapped_range),
                        );
                    } else {
                        regions.push((b.min_addr, b.max_addr + 1));
                    }
                }
            }
        }

        if regions.is_empty() && !examined_any_object {
            regions = self.backers.iter().map(|b| (b.start, b.end())).collect();
        }
        regions.retain(|&(s, e)| e > s);
        regions.sort_by_key(|r| r.0);
        regions
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Python-facing specs used to build a snapshot
// ---------------------------------------------------------------------------------------------------------------

#[derive(FromPyObject)]
struct RegionSpec {
    vaddr: u64,
    memsize: u64,
    filesize: Option<u64>,
    name: Option<String>,
    is_executable: bool,
    is_readable: bool,
    is_writable: bool,
    only_uninit: bool,
}

impl RegionSpec {
    fn into_info(self) -> RegionInfo {
        RegionInfo {
            vaddr: self.vaddr,
            memsize: self.memsize,
            filesize: self.filesize,
            name: self.name,
            is_executable: self.is_executable,
            is_readable: self.is_readable,
            is_writable: self.is_writable,
            only_uninit: self.only_uninit,
        }
    }
}

#[derive(FromPyObject)]
struct SymbolSpec {
    relative_addr: i64,
    rebased_addr: u64,
    size: u64,
    is_function: bool,
    is_import: bool,
    name: Option<String>,
}

#[derive(FromPyObject)]
struct ObjectSpec<'py> {
    min_addr: u64,
    max_addr: u64,
    mapped_base: u64,
    kind: u8,
    is_main: bool,
    has_memory: bool,
    is_outer: bool,
    mem: Option<(u64, u64, bool)>,
    sections: Vec<RegionSpec>,
    segments: Vec<RegionSpec>,
    sections_sorted: Vec<usize>,
    segments_sorted: Vec<usize>,
    symbols: Vec<SymbolSpec>,
    hex_regions: Vec<(u64, u64)>,
    backers: Vec<(u64, Bound<'py, PyAny>)>,
}

impl ObjectSpec<'_> {
    fn into_info(self) -> PyResult<ObjectInfo> {
        let sections: Vec<RegionInfo> = self
            .sections
            .into_iter()
            .map(RegionSpec::into_info)
            .collect();
        let segments: Vec<RegionInfo> = self
            .segments
            .into_iter()
            .map(RegionSpec::into_info)
            .collect();
        if self.sections_sorted.iter().any(|&i| i >= sections.len())
            || self.segments_sorted.iter().any(|&i| i >= segments.len())
        {
            return Err(PyValueError::new_err("sorted region index out of range"));
        }
        let sections_sorted = self.sections_sorted;
        let segments_sorted = self.segments_sorted;
        let backers = self
            .backers
            .iter()
            .map(|(start, obj)| Backer::new(*start, obj))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(ObjectInfo {
            min_addr: self.min_addr,
            max_addr: self.max_addr,
            mapped_base: self.mapped_base,
            kind: BackendKind::from_u8(self.kind)?,
            is_main: self.is_main,
            has_memory: self.has_memory,
            is_outer: self.is_outer,
            mem: self.mem.map(|(min, max, consecutive)| MemInfo {
                min,
                max,
                consecutive,
            }),
            sections,
            segments,
            sections_sorted,
            segments_sorted,
            symbols: self
                .symbols
                .into_iter()
                .map(|s| SymbolInfo {
                    relative_addr: s.relative_addr,
                    rebased_addr: s.rebased_addr,
                    size: s.size,
                    is_function: s.is_function,
                    is_import: s.is_import,
                    name: s.name,
                })
                .collect(),
            hex_regions: self.hex_regions,
            backers,
        })
    }
}

#[derive(FromPyObject)]
struct ArchSpec {
    name: String,
    bytes: u64,
    bits: u64,
    big_endian: bool,
    instruction_alignment: Option<u64>,
    nop_instruction: Vec<u8>,
    function_prologs: Vec<Vec<u8>>,
    thumb_prologs: Vec<Vec<u8>>,
    branch_delay_slot: bool,
    call_pushes_ret: bool,
}

/// An immutable snapshot of the loader, built once per CFG recovery.
#[pyclass(module = "angr.rustylib.cfg_scan", frozen)]
pub struct LoaderSnapshot {
    pub inner: Arc<Snapshot>,
}

fn symbol_tuple(s: Option<&SymbolInfo>) -> Option<(u64, u64, bool, Option<String>)> {
    s.map(SymbolInfo::as_tuple)
}

#[pymethods]
impl LoaderSnapshot {
    /// `objects` are `loader.all_objects` (plus any explicitly appended object past `loader_object_count`),
    /// `backers` the leaf backers of `loader.memory` in `Clemory.backers()` order.
    #[new]
    #[pyo3(signature = (objects, loader_object_count, backers, arch, loader_min_addr=0, loader_max_addr=0))]
    fn new(
        objects: Vec<ObjectSpec<'_>>,
        loader_object_count: usize,
        backers: Vec<(u64, Bound<'_, PyAny>)>,
        arch: ArchSpec,
        loader_min_addr: u64,
        loader_max_addr: u64,
    ) -> PyResult<Self> {
        if loader_object_count > objects.len() {
            return Err(PyValueError::new_err(
                "loader_object_count exceeds the number of objects",
            ));
        }
        let objects = objects
            .into_iter()
            .map(ObjectSpec::into_info)
            .collect::<PyResult<Vec<_>>>()?;
        let backers = backers
            .iter()
            .map(|(start, obj)| Backer::new(*start, obj))
            .collect::<PyResult<Vec<_>>>()?;
        let simple_backers = backers.windows(2).all(|w| w[0].end() <= w[1].start);
        let mut function_prologs = arch.function_prologs;
        function_prologs.sort();
        let mut thumb_prologs = arch.thumb_prologs;
        thumb_prologs.sort();
        Ok(Self {
            inner: Arc::new(Snapshot {
                objects,
                loader_object_count,
                loader_min_addr,
                loader_max_addr,
                backers,
                simple_backers,
                arch: ArchInfo {
                    name: arch.name,
                    bytes: arch.bytes,
                    bits: arch.bits,
                    big_endian: arch.big_endian,
                    instruction_alignment: arch.instruction_alignment.unwrap_or(0),
                    nop_instruction: arch.nop_instruction,
                    function_prologs,
                    thumb_prologs,
                    branch_delay_slot: arch.branch_delay_slot,
                    call_pushes_ret: arch.call_pushes_ret,
                },
            }),
        })
    }

    #[getter]
    fn object_count(&self) -> usize {
        self.inner.objects.len()
    }

    #[getter]
    fn loader_object_count(&self) -> usize {
        self.inner.loader_object_count
    }

    #[getter]
    fn arch_name(&self) -> String {
        self.inner.arch.name.clone()
    }

    #[getter]
    fn arch_bytes(&self) -> u64 {
        self.inner.arch.bytes
    }

    #[getter]
    fn big_endian(&self) -> bool {
        self.inner.arch.big_endian
    }

    #[getter]
    fn instruction_alignment(&self) -> Option<u64> {
        (self.inner.arch.instruction_alignment != 0)
            .then_some(self.inner.arch.instruction_alignment)
    }

    /// `(min_addr, max_addr, mapped_base, kind, is_main, has_memory, is_outer)` of an object.
    fn object(&self, idx: usize) -> PyResult<(u64, u64, u64, u8, bool, bool, bool)> {
        let o = self
            .inner
            .objects
            .get(idx)
            .ok_or_else(|| PyValueError::new_err("object index out of range"))?;
        Ok((
            o.min_addr,
            o.max_addr,
            o.mapped_base,
            o.kind as u8,
            o.is_main,
            o.has_memory,
            o.is_outer,
        ))
    }

    fn sections(&self, idx: usize) -> Vec<RegionTuple> {
        self.inner.objects[idx]
            .sections
            .iter()
            .map(RegionInfo::as_tuple)
            .collect()
    }

    fn segments(&self, idx: usize) -> Vec<RegionTuple> {
        self.inner.objects[idx]
            .segments
            .iter()
            .map(RegionInfo::as_tuple)
            .collect()
    }

    /// `(start, size)` of every leaf backer of the loader memory.
    fn backers(&self) -> Vec<(u64, u64)> {
        self.inner
            .backers
            .iter()
            .map(|b| (b.start, b.len() as u64))
            .collect()
    }

    /// `(rva, size)` of every leaf backer of one object's memory.
    fn object_backers(&self, idx: usize) -> Vec<(u64, u64)> {
        self.inner.objects[idx]
            .backers
            .iter()
            .map(|b| (b.start, b.len() as u64))
            .collect()
    }

    fn load_byte(&self, addr: u64) -> Option<u8> {
        self.inner.load_byte(addr)
    }

    #[pyo3(signature = (addr, size=None))]
    fn load_word(&self, addr: u64, size: Option<usize>) -> PyResult<Option<u64>> {
        let size = size.unwrap_or(self.inner.arch.bytes as usize);
        if !(1..=8).contains(&size) {
            return Err(PyValueError::new_err("size must be between 1 and 8"));
        }
        Ok(self.inner.load_word(addr, size))
    }

    fn load_bytes<'py>(&self, py: Python<'py>, addr: u64, n: usize) -> Option<Bound<'py, PyBytes>> {
        self.inner.load_bytes(addr, n).map(|v| PyBytes::new(py, &v))
    }

    fn next_mapped_addr(&self, addr: u64) -> Option<u64> {
        self.inner.next_mapped_addr(addr)
    }

    #[pyo3(signature = (addr, membership_check=true))]
    fn find_object_containing(&self, addr: u64, membership_check: bool) -> Option<usize> {
        self.inner.find_object_containing(addr, membership_check)
    }

    fn find_section_containing(&self, addr: u64) -> Option<(usize, usize)> {
        self.inner.find_section_containing(addr)
    }

    fn find_segment_containing(&self, addr: u64) -> Option<(usize, usize)> {
        self.inner.find_segment_containing(addr)
    }

    fn addrs_belong_to_same_section(&self, a: u64, b: u64) -> bool {
        self.inner.addrs_belong_to_same_section(a, b)
    }

    fn addrs_belong_to_same_segment(&self, a: u64, b: u64) -> bool {
        self.inner.addrs_belong_to_same_segment(a, b)
    }

    /// `(rebased_addr, size, is_function, name)` of the symbol `loader.find_symbol(addr, fuzzy=True)` returns.
    fn floor_symbol(&self, addr: u64) -> Option<(u64, u64, bool, Option<String>)> {
        symbol_tuple(self.inner.floor_symbol(addr))
    }

    fn symbol_at(&self, addr: u64) -> Option<(u64, u64, bool, Option<String>)> {
        symbol_tuple(self.inner.symbol_at(addr))
    }

    fn ceiling_symbol(&self, addr: u64) -> Option<(u64, u64, bool, Option<String>)> {
        symbol_tuple(self.inner.ceiling_symbol(addr))
    }

    /// Sorted, deduplicated addresses of an object's function symbols.
    fn function_symbol_addrs(&self, idx: usize) -> Vec<u64> {
        let set: BTreeSet<u64> = self.inner.objects[idx]
            .symbols
            .iter()
            .filter(|s| s.is_function)
            .map(|s| s.rebased_addr)
            .collect();
        set.into_iter().collect()
    }

    #[pyo3(signature = (objects=None, force_segment=false))]
    fn executable_memory_regions(
        &self,
        objects: Option<Vec<usize>>,
        force_segment: bool,
    ) -> Vec<(u64, u64)> {
        self.inner
            .executable_memory_regions(objects.as_deref(), force_segment)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------------------------------------------

#[pymodule]
pub fn cfg_scan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LoaderSnapshot>()?;
    Ok(())
}
