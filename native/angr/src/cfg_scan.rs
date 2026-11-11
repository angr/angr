//! Byte-level pre-scan half of CFGFast's scan loop.
//!
//! `LoaderSnapshot` (`angr.rustylib.cfg_scan.LoaderSnapshot`) is an immutable copy of what CFGFast needs from
//! cle: objects, sections, segments, symbols, arch constants, and zero-copy references to the loader's memory
//! backers. Queries mirror the cle methods they replace, without cle's last-hit caches.
//!
//! `LinearSweep` ports CFGFast's linear-sweep address selection (`_next_unscanned_addr`, `_next_code_addr*`) and
//! the byte classifiers (`_scan_for_*`), writing `SegmentList` directly and returning `MemoryData` creation
//! requests for Python to apply in order. `func_addrs_from_prologues` and the Go stack-check preamble matcher
//! port the regex-over-backers prologue scan.
//!
//! Every routine mirrors the Python it replaces step by step; the quirks (a string scan returning the offset of
//! `bx lr`, the off-by-one count of `_scan_for_repeating_bytes` with `repeating_byte=None`, ...) are kept on
//! purpose so that the recovered CFG stays byte-identical.

use crate::segmentlist::SegmentList;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, LazyLock};

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
    obj: Py<PyAny>,
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
            obj: obj.clone().unbind(),
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

    /// `Regions.find_region_next_to` over the sections: the first mapped section (in `_sorted_list` order) at the
    /// bisection point of `addr`, whether or not it contains `addr`.
    pub fn find_section_next_to(&self, addr: u64) -> Option<usize> {
        let sorted = &self.sections_sorted;
        let (mut lo, mut hi) = (0usize, sorted.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.sections[sorted[mid]].end() <= addr {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        sorted.get(lo).copied()
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
    /// An empty snapshot (no objects, no memory) for unit tests.
    #[cfg(test)]
    pub fn empty_for_tests() -> Self {
        Snapshot {
            objects: Vec::new(),
            loader_object_count: 0,
            loader_min_addr: 0,
            loader_max_addr: 0,
            backers: Vec::new(),
            simple_backers: true,
            arch: ArchInfo {
                name: "AMD64".into(),
                bytes: 8,
                bits: 64,
                big_endian: false,
                instruction_alignment: 1,
                nop_instruction: Vec::new(),
                function_prologs: Vec::new(),
                thumb_prologs: Vec::new(),
                branch_delay_slot: false,
                call_pushes_ret: true,
            },
        }
    }

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
        self.load_word_endian(addr, size, self.arch.big_endian)
    }

    /// `load_word` with an explicit endianness (`unpack_word(..., endness=...)`).
    pub fn load_word_endian(&self, addr: u64, size: usize, big_endian: bool) -> Option<u64> {
        debug_assert!((1..=8).contains(&size));
        let b = &self.backers[self.backer_ending_after(addr)?];
        if b.start > addr {
            return None;
        }
        let off = (addr - b.start) as usize;
        let data = b.bytes().get(off..off + size)?;
        Some(if big_endian {
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

    /// `loader.find_section_next_to(addr)` (pseudo objects skipped).
    pub fn find_section_next_to(&self, addr: u64) -> Option<(usize, usize)> {
        let oi = self.find_object_containing(addr, false)?;
        let obj = &self.objects[oi];
        if obj.kind == BackendKind::Pseudo {
            return None;
        }
        obj.find_section_next_to(addr).map(|si| (oi, si))
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

    fn find_section_next_to(&self, addr: u64) -> Option<(usize, usize)> {
        self.inner.find_section_next_to(addr)
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
// Regex translation (Python `re` byte patterns -> `regex::bytes`)
// ---------------------------------------------------------------------------------------------------------------

/// Rewrite a Python `re` byte pattern as `regex` syntax: escape sequences are copied verbatim, raw non-printable
/// bytes become `\xNN`. Returns `None` for syntax `regex` does not support (look-around), which the caller then
/// hands back to Python.
pub fn compile_py_byte_regex(pattern: &[u8], anchored: bool) -> Option<Regex> {
    let mut text = String::with_capacity(pattern.len() * 2 + 8);
    if anchored {
        text.push_str("^(?:");
    }
    let mut i = 0;
    while i < pattern.len() {
        let b = pattern[i];
        if b == b'\\' && i + 1 < pattern.len() {
            text.push('\\');
            text.push(pattern[i + 1] as char);
            i += 2;
            continue;
        }
        if (0x20..0x7f).contains(&b) {
            text.push(b as char);
        } else {
            text.push_str(&format!("\\x{b:02x}"));
        }
        i += 1;
    }
    if anchored {
        text.push(')');
    }
    RegexBuilder::new(&text).unicode(false).build().ok()
}

// ---------------------------------------------------------------------------------------------------------------
// Go stack-growth preambles (port of angr/analyses/cfg/go_prologue.py)
// ---------------------------------------------------------------------------------------------------------------

const GUARD64: &str = r"[\x10\x18]";
const GUARD32: &str = r"[\x08\x0c]";
const X86_JBE: &str = r"(?:(?P<rel8>\x76[\x00-\xff])|\x0f\x86(?P<rel32>[\x00-\xff]{4}))";

fn amd64_pattern() -> String {
    let g_load = concat!(
        r"(?:",
        r"\x64\x4c\x8b\x34\x25[\x00-\xff]{4}",
        r"|\x4c\x8b\x35[\x00-\xff]{4}\x65\x4d\x8b\x36\x4d\x8b\x36",
        r")?"
    );
    let frame_bottom = concat!(
        r"(?:",
        r"\x4c\x8d\x64\x24[\x00-\xff]",
        r"|\x4c\x8d\xa4\x24[\x00-\xff]{4}",
        r"|\x49\x89\xe4",
        r"(?:\x49\x83\xec[\x00-\xff]|\x49\x81\xec[\x00-\xff]{4})",
        r"(?:\x72[\x00-\xff]|\x0f\x82[\x00-\xff]{4})",
        r")"
    );
    let cmp_rsp = format!(r"\x49\x3b\x66{GUARD64}");
    let cmp_r12 = format!(r"\x4d\x3b\x66{GUARD64}");
    format!("{g_load}(?:{cmp_rsp}|{frame_bottom}{cmp_r12}){X86_JBE}")
}

fn x86_pattern() -> String {
    let g_load = concat!(
        r"(?:",
        r"\x8b\x0d[\x00-\xff]{4}\x64\x8b\x09\x8b\x09",
        r"|[\x64\x65]\x8b\x0d[\x00-\xff]{4}\x8b\x89[\x00-\xff]{4}",
        r")"
    );
    let frame_bottom = concat!(
        r"(?:",
        r"\x8d\x44\x24[\x00-\xff]",
        r"|\x8d\x84\x24[\x00-\xff]{4}",
        r"|\x89\xe0\x2d[\x00-\xff]{4}",
        r"(?:\x72[\x00-\xff]|\x0f\x82[\x00-\xff]{4})",
        r")"
    );
    let cmp_esp = format!(r"\x3b\x61{GUARD32}");
    let cmp_eax = format!(r"\x3b\x41{GUARD32}");
    format!("{g_load}(?:{cmp_esp}|{frame_bottom}{cmp_eax}){X86_JBE}")
}

fn arm_pattern() -> String {
    let g_load = format!(r"{GUARD32}\x10\x9a\xe5");
    let r11_to_r2 = r"(?:\x0b\x20\x5d\xe0|\x0b\x20\x8d\xe0)";
    let frame_bottom = format!(
        concat!(
            r"(?:",
            r"[\x00-\xff][\x20-\x2f]\x4d\xe2",
            r"|[\x00-\xff][\xb0-\xbf][\x00-\x0f]\xe3",
            "{r11}",
            r"|[\x00-\xff][\xb0-\xbf]\x9f\xe5",
            "{r11}",
            r")"
        ),
        r11 = r11_to_r2
    );
    let cmp_sp = r"\x01\x00\x5d\xe1";
    let cmp_r2 = r"\x01\x00\x52[\xe1\x21]";
    let bls = r"(?P<b>[\x00-\xff]{3}\x9a)";
    format!("{g_load}(?:{cmp_sp}|{frame_bottom}{cmp_r2}){bls}")
}

fn a64_frame_bottom(reg: &str) -> String {
    let x27 = r"[\x1b\x3b\x5b\x7b\x9b\xbb\xdb\xfb]";
    let bcc = r"[\x03\x23\x43\x63\x83\xa3\xc3\xe3][\x00-\xff]{2}\x54";
    let movz_x27 = format!(r"{x27}[\x00-\xff][\x80-\x9f]\xd2");
    let movk_x27 = format!(r"{x27}[\x00-\xff][\xa0-\xbf]\xf2");
    format!(
        concat!(
            r"(?:",
            "{reg}",
            r"\x03\x00\x91",
            r"|",
            "{reg}",
            r"[\x00-\xff][\x00-\x7f]\xd1",
            r"|",
            "{reg}",
            r"[\x00-\xff][\x00-\x7f]\xf1",
            "{bcc}",
            r"|",
            "{movz}",
            r"(?:",
            "{movk}",
            r")?",
            "{reg}",
            r"\x63\x3b\xeb",
            "{bcc}",
            r")"
        ),
        reg = reg,
        bcc = bcc,
        movz = movz_x27,
        movk = movk_x27
    )
}

fn a64_pattern() -> String {
    let guard = r"[\x0b\x0f]";
    let bls = r"(?P<b>[\x09\x29\x49\x69\x89\xa9\xc9\xe9][\x00-\xff]{2}\x54)";
    let check = format!(
        r"\x90{guard}\x40\xf9(?:\xff\x63\x30\xeb|{fb}\x3f\x02\x10\xeb)",
        fb = a64_frame_bottom(r"\xf1")
    );
    let check_go117 = format!(
        r"\x81{guard}\x40\xf9{fb}\x5f\x00\x01\xeb",
        fb = a64_frame_bottom(r"\xe2")
    );
    format!("(?:{check}|{check_go117}){bls}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BranchKind {
    X86,
    Arm,
    Aarch64,
}

struct GoPreamble {
    regex: Regex,
    anchored: Regex,
    branch: BranchKind,
    alignment: usize,
    anchors: &'static [&'static [u8]],
}

fn build_preamble(
    pattern: &str,
    branch: BranchKind,
    alignment: usize,
    anchors: &'static [&'static [u8]],
) -> GoPreamble {
    let build = |p: &str| {
        RegexBuilder::new(p)
            .unicode(false)
            .build()
            .expect("Go preamble pattern is valid")
    };
    GoPreamble {
        regex: build(pattern),
        anchored: build(&format!("^(?:{pattern})")),
        branch,
        alignment,
        anchors,
    }
}

static ARM_ANCHORS: [&[u8]; 2] = [b"\x08\x10\x9a\xe5", b"\x0c\x10\x9a\xe5"];
static A64_ANCHORS: [&[u8]; 4] = [
    b"\x90\x0b\x40\xf9",
    b"\x90\x0f\x40\xf9",
    b"\x81\x0b\x40\xf9",
    b"\x81\x0f\x40\xf9",
];

static GO_AMD64: LazyLock<GoPreamble> =
    LazyLock::new(|| build_preamble(&amd64_pattern(), BranchKind::X86, 1, &[]));
static GO_X86: LazyLock<GoPreamble> =
    LazyLock::new(|| build_preamble(&x86_pattern(), BranchKind::X86, 1, &[]));
static GO_ARM: LazyLock<GoPreamble> =
    LazyLock::new(|| build_preamble(&arm_pattern(), BranchKind::Arm, 4, &ARM_ANCHORS));
static GO_A64: LazyLock<GoPreamble> =
    LazyLock::new(|| build_preamble(&a64_pattern(), BranchKind::Aarch64, 4, &A64_ANCHORS));

fn go_preamble(arch_name: &str) -> Option<&'static GoPreamble> {
    match arch_name {
        "AMD64" => Some(&GO_AMD64),
        "X86" => Some(&GO_X86),
        "ARMEL" | "ARMHF" => Some(&GO_ARM),
        "AARCH64" => Some(&GO_A64),
        _ => None,
    }
}

pub fn go_preamble_supported(arch_name: &str) -> bool {
    go_preamble(arch_name).is_some()
}

fn branch_target(branch: BranchKind, caps: &regex::bytes::Captures<'_>, end: usize) -> i64 {
    match branch {
        BranchKind::X86 => {
            let disp = match caps.name("rel8") {
                Some(m) => m.as_bytes()[1] as i8 as i64,
                None => i32::from_le_bytes(
                    caps.name("rel32")
                        .expect("rel32 group")
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                ) as i64,
            };
            end as i64 + disp
        }
        BranchKind::Arm => {
            let word = u32::from_le_bytes(
                caps.name("b")
                    .expect("b group")
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            );
            let mut disp = (word & 0xFF_FFFF) as i64;
            if word & 0x80_0000 != 0 {
                disp -= 0x100_0000;
            }
            end as i64 - 4 + 8 + disp * 4
        }
        BranchKind::Aarch64 => {
            let word = u32::from_le_bytes(
                caps.name("b")
                    .expect("b group")
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            );
            let imm19 = ((word >> 5) & 0x7FFFF) as i64;
            let disp = if imm19 & 0x40000 != 0 {
                imm19 - 0x80000
            } else {
                imm19
            };
            end as i64 - 4 + disp * 4
        }
    }
}

fn find_all_overlapping(blob: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || blob.len() < needle.len() {
        return out;
    }
    for pos in 0..=blob.len() - needle.len() {
        if &blob[pos..pos + needle.len()] == needle {
            out.push(pos);
        }
    }
    out
}

/// `find_go_stack_check_preambles(blob, arch_name, base)`: `(start, end, branch_target)` offsets into `blob`
/// of every preamble whose stack-growth branch goes forward.
pub fn find_go_stack_check_preambles(
    blob: &[u8],
    arch_name: &str,
    base: u64,
) -> Vec<(usize, usize, usize)> {
    let Some(pre) = go_preamble(arch_name) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut push = |start: usize, end: usize, caps: &regex::bytes::Captures<'_>| {
        let target = branch_target(pre.branch, caps, end);
        if target > end as i64 {
            out.push((start, end, target as usize));
        }
    };
    if pre.anchors.is_empty() {
        for caps in pre.regex.captures_iter(blob) {
            let m = caps.get(0).expect("whole match");
            push(m.start(), m.end(), &caps);
        }
        return out;
    }
    let mut positions: BTreeSet<usize> = BTreeSet::new();
    for anchor in pre.anchors {
        for pos in find_all_overlapping(blob, anchor) {
            if (base.wrapping_add(pos as u64)).is_multiple_of(pre.alignment as u64) {
                positions.insert(pos);
            }
        }
    }
    for pos in positions {
        if let Some(caps) = pre.anchored.captures(&blob[pos..]) {
            let m = caps.get(0).expect("whole match");
            push(pos + m.start(), pos + m.end(), &caps);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------
// Prologue scan (port of CFGFast._func_addrs_from_prologues / _backer_exec_slices / _prologue_preambles)
// ---------------------------------------------------------------------------------------------------------------

const PROLOGUE_SCAN_PADDING: usize = 64;

pub(crate) fn addr_in_regions(regions: &[(u64, u64)], addr: u64) -> bool {
    regions.iter().any(|&(s, e)| s <= addr && addr < e)
}

/// `CFGFast._backer_exec_slices`: backer-relative `[start, end)` slices of the executable regions.
pub fn backer_exec_slices(
    exec_regions: &[(u64, u64)],
    backer_mva: u64,
    backer_size: u64,
) -> Vec<(u64, u64)> {
    if exec_regions.is_empty() {
        return vec![(0, backer_size)];
    }
    let mut sorted = exec_regions.to_vec();
    sorted.sort();
    let mut slices: Vec<(u64, u64)> = Vec::new();
    for (start, end) in sorted {
        let lo = start.max(backer_mva).wrapping_sub(backer_mva);
        let hi = end
            .min(backer_mva.wrapping_add(backer_size))
            .wrapping_sub(backer_mva);
        if lo >= hi {
            continue;
        }
        match slices.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => slices.push((lo, hi)),
        }
    }
    slices
}

enum Prolog {
    Native(Regex),
    /// A pattern `regex` cannot compile; matched through the Python callback.
    Python(Vec<u8>),
}

fn compile_prologs(patterns: &[Vec<u8>]) -> Vec<Prolog> {
    patterns
        .iter()
        .map(|p| match compile_py_byte_regex(p, false) {
            Some(r) => Prolog::Native(r),
            None => Prolog::Python(p.clone()),
        })
        .collect()
}

/// Match starts (relative to the whole backer) of `prolog` within `backer[lo..endpos]`.
fn prolog_match_starts(
    prolog: &Prolog,
    backer: &Backer,
    lo: usize,
    endpos: usize,
    fallback: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<usize>> {
    match prolog {
        Prolog::Native(re) => Ok(re
            .find_iter(&backer.bytes()[lo..endpos])
            .map(|m| m.start() + lo)
            .collect()),
        Prolog::Python(pattern) => {
            let Some(cb) = fallback else {
                return Err(PyValueError::new_err(format!(
                    "prologue pattern {pattern:?} is not supported by the regex engine and no fallback was given"
                )));
            };
            let py = cb.py();
            let args = (PyBytes::new(py, pattern), backer.obj.bind(py), lo, endpos);
            cb.call1(args)?.extract::<Vec<usize>>()
        }
    }
}

/// `CFGFast._func_addrs_from_prologues` for object `binary_idx`. `fallback(pattern, backer, lo, endpos)` is the
/// Python `re.finditer` for patterns `regex` rejects.
pub fn func_addrs_from_prologues(
    snap: &Snapshot,
    binary_idx: usize,
    exec_regions: &[(u64, u64)],
    has_arm_code: bool,
    fallback: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<u64>> {
    let arch = &snap.arch;
    let regexes = if has_arm_code {
        compile_prologs(&arch.function_prologs)
    } else {
        Vec::new()
    };
    let thumb_regexes = compile_prologs(&arch.thumb_prologs);
    let is_arm = arch.is_arm();
    let alignment = arch.instruction_alignment.max(1);
    let binary = &snap.objects[binary_idx];
    let base = binary.mapped_base;

    let mut found: Vec<u64> = Vec::new();
    for backer in &binary.backers {
        let start_ = backer.start;
        let backer_mva = start_.wrapping_add(base);
        for (lo, hi) in backer_exec_slices(exec_regions, backer_mva, backer.len() as u64) {
            let lo = lo as usize;
            let endpos = backer.len().min(hi as usize + PROLOGUE_SCAN_PADDING);
            let blob = &backer.bytes()[lo..endpos];
            let blob_rva = start_ + lo as u64;
            let blob_mva = blob_rva.wrapping_add(base);

            let mut covered: HashSet<u64> = HashSet::new();
            for (p_start, p_end, target) in
                find_go_stack_check_preambles(blob, &arch.name, blob_mva)
            {
                if !addr_in_regions(exec_regions, blob_mva.wrapping_add(target as u64)) {
                    continue;
                }
                let mapped = blob_mva + p_start as u64;
                if addr_in_regions(exec_regions, mapped) {
                    found.push(mapped);
                    covered.insert(blob_rva + p_end as u64);
                }
            }

            for regex in &regexes {
                for m in prolog_match_starts(regex, backer, lo, endpos, fallback)? {
                    let position = m as u64 + start_;
                    if covered.contains(&position) {
                        continue;
                    }
                    let aligned = if is_arm {
                        position.is_multiple_of(4)
                    } else {
                        position.is_multiple_of(alignment)
                    };
                    if aligned {
                        let mapped = position.wrapping_add(base);
                        if addr_in_regions(exec_regions, mapped) {
                            found.push(mapped);
                        }
                    }
                }
            }
            for regex in &thumb_regexes {
                for m in prolog_match_starts(regex, backer, lo, endpos, fallback)? {
                    let position = m as u64 + start_;
                    if position.is_multiple_of(alignment) {
                        let mapped = position.wrapping_add(base);
                        if addr_in_regions(exec_regions, mapped) {
                            found.push(mapped + 1);
                        }
                    }
                }
            }
        }
    }
    Ok(found)
}

// ---------------------------------------------------------------------------------------------------------------
// Linear sweep
// ---------------------------------------------------------------------------------------------------------------

/// Where `_load_a_byte_as_int` reads from: the snapshot, or a Python callback when CFGFast has a base state.
pub struct ByteSource<'a> {
    snap: &'a Snapshot,
    callback: Option<&'a Bound<'a, PyAny>>,
}

impl ByteSource<'_> {
    pub fn byte(&self, addr: u64) -> PyResult<Option<u8>> {
        match self.callback {
            None => Ok(self.snap.load_byte(addr)),
            Some(cb) => cb.call1((addr,))?.extract::<Option<u8>>(),
        }
    }
}

/// A `MemoryData(addr, size, sort)` to be stored in `model.memory_data`.
pub type MemReq = (u64, u64, &'static str);

const SORT_POINTER_ARRAY: &str = "pointer-array";
const SORT_ALIGNMENT: &str = "alignment";
const SORT_FP: &str = "fp";
const SORT_STRING: &str = "string";
const SORT_UNICODE: &str = "unicode";
const SORT_UNKNOWN: &str = "unknown";

pub(crate) static PRINTABLE: LazyLock<[bool; 256]> = LazyLock::new(|| {
    // string.printable without \x0b and \x0c
    let mut t = [false; 256];
    for b in 0x20u8..0x7f {
        t[b as usize] = true;
    }
    for b in *b"\t\n\r" {
        t[b as usize] = true;
    }
    t
});

enum Core {
    Addr(u64),
    Done,
    /// `ContinueScanningNotification`
    Continue,
}

pub struct Sweep {
    pub snap: Arc<Snapshot>,
    /// CFG recovery regions, sorted by start.
    pub regions: Vec<(u64, u64)>,
    pub exec_regions: Vec<(u64, u64)>,
    /// `_next_addr + 1`: the first candidate of the next `_next_unscanned_addr` call. `None` until the first call.
    resume_from: Option<u64>,
    nodecode_window_size: u64,
    nodecode_threshold: f64,
    nodecode_step: u64,
    is_x86: bool,
    check_xfg: bool,
    is_arm: bool,
    ptr_size: u64,
    instruction_alignment: u64,
}

impl Sweep {
    /// `CFGBase._inside_regions`.
    pub fn inside_regions(&self, addr: u64) -> bool {
        self.region_end(addr).is_some()
    }

    /// `CFGBase._inside_regions_and_region_end`: the end of the region containing `addr`.
    pub fn region_end(&self, addr: u64) -> Option<u64> {
        let pos = self.regions.partition_point(|r| r.0 <= addr);
        let (_, end) = self.regions[pos.checked_sub(1)?];
        (addr < end).then_some(end)
    }

    /// `CFGBase._next_address_in_regions`.
    pub fn next_address_in_regions(&self, addr: u64) -> Option<u64> {
        if self.inside_regions(addr) {
            return Some(addr);
        }
        let pos = self.regions.partition_point(|r| r.0 < addr);
        self.regions.get(pos).map(|r| r.0)
    }

    pub fn next_addr(&self) -> Option<i64> {
        self.resume_from.map(|r| r as i64 - 1)
    }

    pub fn set_next_addr(&mut self, next_addr: Option<i64>) {
        self.resume_from = next_addr.map(|n| (n + 1) as u64);
    }

    /// `CFGFast._next_unscanned_addr`.
    pub fn next_unscanned_addr(
        &mut self,
        seg_list: &SegmentList,
        alignment: Option<u64>,
    ) -> Option<u64> {
        let mut curr = match self.resume_from {
            None => {
                let min = self.regions.first().map(|r| r.0);
                self.resume_from = min.map(|m| m + 1);
                min
            }
            Some(r) => Some(r),
        };
        if let Some(c) = curr
            && !self.inside_regions(c)
        {
            curr = self.next_address_in_regions(c);
        }
        let mut curr = curr?;
        if seg_list.has_blocks() {
            curr = seg_list.next_free_pos(curr)?;
        }
        if let Some(a) = alignment
            && a > 0
            && curr % a > 0
        {
            curr = curr - curr % a + a;
        }
        let mut accepted = false;
        for &(start, end) in &self.regions {
            if start <= curr && curr < end {
                accepted = true;
                break;
            }
            if curr < start {
                accepted = true;
                curr = start;
                break;
            }
        }
        if !accepted {
            return None;
        }
        self.resume_from = Some(curr + 1);
        self.inside_regions(curr).then_some(curr)
    }

    /// `CFGFast._update_unscanned_addr`.
    pub fn update_unscanned_addr(&mut self, new_addr: u64) {
        if let Some(r) = self.resume_from
            && r > new_addr
        {
            self.resume_from = Some(new_addr);
        }
    }

    /// `CFGFast._scan_for_printable_strings`.
    pub fn scan_for_printable_strings(
        &self,
        bytes: &ByteSource<'_>,
        start_addr: u64,
        min_length_nullterminated: usize,
        min_length_non_nullterminated: usize,
    ) -> PyResult<usize> {
        let mut addr = start_addr;
        let mut sz: Vec<u8> = Vec::new();
        let mut is_sz = true;
        let mut region_end: Option<u64> = None;
        loop {
            let inside = match region_end {
                Some(end) if addr < end => true,
                _ => {
                    region_end = self.region_end(addr);
                    region_end.is_some()
                }
            };
            if !inside {
                break;
            }
            let Some(val) = bytes.byte(addr)? else {
                break;
            };
            if val == 0 {
                break;
            }
            if !PRINTABLE[val as usize] {
                is_sz = false;
                break;
            }
            sz.push(val);
            addr += 1;
        }

        if !sz.is_empty()
            && sz.len() >= min_length_nullterminated.min(min_length_non_nullterminated)
        {
            if self.is_arm {
                let bx_lr: &[u8] = if self.snap.arch.big_endian {
                    b"\x47\x70"
                } else {
                    b"\x70\x47"
                };
                if let Some(pos) = sz.windows(2).position(|w| w == bx_lr) {
                    return Ok(pos);
                }
            }
            if is_sz && sz.len() >= min_length_nullterminated {
                return Ok(sz.len() + 1);
            }
            if !is_sz && sz.len() >= min_length_non_nullterminated {
                return Ok(sz.len());
            }
        }
        Ok(0)
    }

    /// `CFGFast._scan_for_printable_widestrings`.
    pub fn scan_for_printable_widestrings(
        &self,
        bytes: &ByteSource<'_>,
        start_addr: u64,
        min_length_nullterminated: usize,
        min_length_non_nullterminated: usize,
    ) -> PyResult<usize> {
        let mut addr = start_addr;
        let mut sz_len = 0usize;
        let mut is_sz = true;
        let mut region_end: Option<u64> = None;
        loop {
            let inside = match region_end {
                Some(end) if addr < end => true,
                _ => {
                    region_end = self.region_end(addr);
                    region_end.is_some()
                }
            };
            if !inside {
                break;
            }
            let Some(val0) = bytes.byte(addr)? else {
                break;
            };
            let Some(val1) = bytes.byte(addr + 1)? else {
                break;
            };
            if val0 == 0 && val1 == 0 {
                break;
            }
            if val0 != 0 && val1 == 0 && PRINTABLE[val0 as usize] {
                sz_len += 2;
                addr += 2;
                continue;
            }
            is_sz = false;
            break;
        }

        if sz_len > 0 && sz_len >= min_length_nullterminated.min(min_length_non_nullterminated) * 2
        {
            if is_sz && sz_len >= min_length_nullterminated * 2 {
                return Ok(sz_len + 2);
            }
            if !is_sz && sz_len >= min_length_non_nullterminated * 2 {
                return Ok(sz_len);
            }
        }
        Ok(0)
    }

    /// `CFGFast._scan_for_repeating_bytes`.
    pub fn scan_for_repeating_bytes(
        &self,
        bytes: &ByteSource<'_>,
        start_addr: u64,
        repeating_byte: Option<u8>,
        threshold: u64,
    ) -> PyResult<u64> {
        let mut addr = start_addr;
        let mut repeating_length = 0u64;
        let mut last_byte = repeating_byte;
        while self.inside_regions(addr) {
            let Some(val) = bytes.byte(addr)? else {
                break;
            };
            match last_byte {
                None => last_byte = Some(val),
                Some(b) if b == val => repeating_length += 1,
                Some(_) => break,
            }
            addr += 1;
        }
        Ok(if repeating_length >= threshold {
            repeating_length
        } else {
            0
        })
    }

    /// `CFGFast._repeating_byte_run_length`.
    pub fn repeating_byte_run_length(
        &self,
        start_addr: u64,
        min_length: u64,
        ignore: Option<u8>,
    ) -> u64 {
        let Some(region_end) = self.region_end(start_addr) else {
            return 0;
        };
        if region_end - start_addr < min_length {
            return 0;
        }
        let Some(head) = self.snap.load_bytes(start_addr, min_length as usize) else {
            return 0;
        };
        if (head.len() as u64) < min_length {
            return 0;
        }
        let filler = head[0];
        if ignore == Some(filler) || head.iter().any(|&b| b != filler) {
            return 0;
        }
        let mut length = min_length;
        while start_addr + length < region_end {
            let n = 0x1000u64.min(region_end - start_addr - length) as usize;
            let Some(chunk) = self.snap.load_bytes(start_addr + length, n) else {
                break;
            };
            if chunk.is_empty() {
                break;
            }
            let matched = chunk.iter().take_while(|&&b| b == filler).count();
            length += matched as u64;
            if matched < chunk.len() {
                break;
            }
        }
        length
    }

    /// `CFGFast._scan_for_fp_constants`.
    pub fn scan_for_fp_constants(&self, start_addr: u64, threshold: u64) -> u64 {
        for (size, exp_shift, exp_mask, exp_lo, exp_hi, min_count) in [
            (8u64, 52u32, 0x7FFu64, 959u64, 1087u64, threshold),
            (4, 23, 0xFF, 95, 159, threshold * 2),
        ] {
            let mut addr = start_addr;
            let mut fp_count = 0u64;
            let mut first_val: Option<u64> = None;
            let mut has_multiple_values = false;
            let uniform_mul = if size == 8 {
                u64::MAX / 0xFF
            } else {
                0xFFFF_FFFFu64 / 0xFF
            };

            while self.inside_regions(addr) {
                let Some(val) = self.snap.load_word(addr, size as usize) else {
                    break;
                };
                if val == (val & 0xFF).wrapping_mul(uniform_mul) {
                    break;
                }
                let exponent = (val >> exp_shift) & exp_mask;
                if !(exp_lo <= exponent && exponent <= exp_hi) {
                    break;
                }
                match first_val {
                    None => first_val = Some(val),
                    Some(f) if f != val => has_multiple_values = true,
                    Some(_) => {}
                }
                fp_count += 1;
                addr += size;
            }
            if fp_count >= min_count && has_multiple_values {
                return fp_count * size;
            }
        }
        0
    }

    /// `CFGFast._scan_for_monotonic_byte_ramp`.
    pub fn scan_for_monotonic_byte_ramp(
        &self,
        bytes: &ByteSource<'_>,
        start_addr: u64,
        threshold: u64,
    ) -> PyResult<u64> {
        let mut addr = start_addr;
        let mut last_byte: Option<u8> = None;
        let mut ramp_length = 0u64;
        while self.inside_regions(addr) {
            let Some(val) = bytes.byte(addr)? else {
                break;
            };
            if let Some(last) = last_byte
                && val != last.wrapping_add(1)
            {
                break;
            }
            last_byte = Some(val);
            ramp_length += 1;
            addr += 1;
        }
        Ok(if ramp_length >= threshold {
            ramp_length
        } else {
            0
        })
    }

    /// `CFGFast._scan_for_consecutive_pointers`.
    pub fn scan_for_consecutive_pointers(&self, start_addr: u64, threshold: u64) -> u64 {
        let current_object = self.snap.find_object_containing(start_addr, true);
        let mut addr = start_addr;
        let mut pointer_count = 0u64;
        while self.inside_regions(addr) {
            let Some(val) = self.snap.load_word(addr, self.ptr_size as usize) else {
                break;
            };
            let obj = self.snap.find_object_containing(val, true);
            if obj.is_some() && obj == current_object {
                pointer_count += 1;
            } else {
                break;
            }
            addr += self.ptr_size;
        }
        if pointer_count >= threshold {
            pointer_count
        } else {
            0
        }
    }

    /// `CFGFast._scan_for_mixed_pointers`.
    pub fn scan_for_mixed_pointers(&self, start_addr: u64, threshold: u64, window: u64) -> u64 {
        let current_object = self.snap.find_object_containing(start_addr, true);
        let mut addr = start_addr;
        let mut ctr = 0u64;
        let mut pointer_count = 0u64;
        while self.inside_regions(addr) && ctr < window {
            ctr += 1;
            let Some(val) = self.snap.load_word(addr, self.ptr_size as usize) else {
                break;
            };
            let obj = self.snap.find_object_containing(val, true);
            if obj.is_some() && obj == current_object {
                pointer_count += 1;
            }
            addr += self.ptr_size;
        }
        if pointer_count >= threshold { ctr } else { 0 }
    }

    /// `CFGFast._scan_for_win_xfg_hash`.
    pub fn scan_for_win_xfg_hash(&self, start_addr: u64) -> bool {
        let Some(ptr) = self.snap.load_word(start_addr, 8) else {
            return false;
        };
        (ptr & 0x8000_0600_1050_0070) == 0x8000_0600_1050_0070
            && ((ptr & !0xFFFD_BFFF_7EDF_FB70u64) & 0xFFFF_FFFF_FFFF_FFFE) == 0
    }

    /// `CFGFast._nodecode_bytes_ratio`.
    pub fn nodecode_bytes_ratio(seg_list: &SegmentList, cutoff_addr: i64, window_size: u64) -> f64 {
        if cutoff_addr - 1 < 0 {
            return 0.0;
        }
        seg_list.sort_ratio_backwards(
            (cutoff_addr - 1) as u64,
            window_size,
            Some("nodecode".to_owned()),
        )
    }

    /// `CFGFast._next_code_addr_core`.
    fn next_code_addr_core(
        &mut self,
        seg_list: &mut SegmentList,
        bytes: &ByteSource<'_>,
        out: &mut Vec<MemReq>,
    ) -> PyResult<Core> {
        let Some(next_addr) = self.next_unscanned_addr(seg_list, None) else {
            return Ok(Core::Done);
        };
        let mut start_addr = next_addr;
        let ptr_size = self.ptr_size;

        loop {
            let mut matched_something = false;

            if start_addr % ptr_size == 0 {
                let threshold = if start_addr <= 0x100000 { 6 } else { 1 };
                let pointer_count = self.scan_for_consecutive_pointers(start_addr, threshold);
                let pointer_length = pointer_count * ptr_size;
                if pointer_length > 0 {
                    matched_something = true;
                    seg_list.occupy(
                        start_addr,
                        pointer_length,
                        Some(SORT_POINTER_ARRAY.to_owned()),
                    );
                    out.push((start_addr, pointer_length, SORT_POINTER_ARRAY));
                    start_addr += pointer_length;
                } else {
                    let (threshold, window) = if start_addr <= 0x100000 {
                        (4, 6)
                    } else {
                        (4, 8)
                    };
                    let pointer_count = self.scan_for_mixed_pointers(start_addr, threshold, window);
                    let pointer_length = pointer_count * ptr_size;
                    if pointer_length > 0 {
                        matched_something = true;
                        seg_list.occupy(
                            start_addr,
                            pointer_length,
                            Some(SORT_POINTER_ARRAY.to_owned()),
                        );
                        out.push((start_addr, pointer_length, SORT_POINTER_ARRAY));
                        start_addr += pointer_length;
                    }
                }
            }

            if !matched_something {
                let fp_addr_4 = start_addr + (start_addr.wrapping_neg() % 4);
                let fp_addr_8 = start_addr + (start_addr.wrapping_neg() % 8);
                let candidates: &[u64] = if fp_addr_4 == fp_addr_8 {
                    &[fp_addr_4]
                } else {
                    &[fp_addr_4, fp_addr_8]
                };
                for &fp_addr in candidates {
                    let fp_length = self.scan_for_fp_constants(fp_addr, 4);
                    if fp_length > 0 {
                        matched_something = true;
                        if fp_addr > start_addr {
                            seg_list.occupy(
                                start_addr,
                                fp_addr - start_addr,
                                Some(SORT_ALIGNMENT.to_owned()),
                            );
                            out.push((start_addr, fp_addr - start_addr, SORT_ALIGNMENT));
                        }
                        seg_list.occupy(fp_addr, fp_length, Some(SORT_FP.to_owned()));
                        out.push((fp_addr, fp_length, SORT_FP));
                        start_addr = fp_addr + fp_length;
                        break;
                    }
                }
            }

            if !matched_something {
                let leading_nulls: u64 = if bytes.byte(start_addr)? == Some(0) {
                    1
                } else {
                    0
                };
                let str_addr = start_addr + leading_nulls;
                let mut is_widestring = false;
                let mut string_length =
                    self.scan_for_printable_strings(bytes, str_addr, 3, 13)? as u64;
                if string_length == 0 {
                    is_widestring = true;
                    string_length =
                        self.scan_for_printable_widestrings(bytes, str_addr, 3, 9)? as u64;
                }
                if string_length > 0 {
                    matched_something = true;
                    if leading_nulls > 0 {
                        seg_list.occupy(start_addr, leading_nulls, Some(SORT_ALIGNMENT.to_owned()));
                        out.push((start_addr, leading_nulls, SORT_ALIGNMENT));
                    }
                    seg_list.occupy(str_addr, string_length, Some(SORT_STRING.to_owned()));
                    out.push((
                        str_addr,
                        string_length,
                        if is_widestring {
                            SORT_UNICODE
                        } else {
                            SORT_STRING
                        },
                    ));
                    start_addr = str_addr + string_length;
                }
            }

            if !matched_something && self.is_x86 {
                let cc_length = self.scan_for_repeating_bytes(bytes, start_addr, Some(0xCC), 1)?;
                if cc_length > 0 {
                    matched_something = true;
                    seg_list.occupy(start_addr, cc_length, Some(SORT_ALIGNMENT.to_owned()));
                    out.push((start_addr, cc_length, SORT_ALIGNMENT));
                    start_addr += cc_length;
                }
            }

            if self.check_xfg && self.scan_for_win_xfg_hash(start_addr) {
                seg_list.occupy(start_addr, 8, Some(SORT_ALIGNMENT.to_owned()));
                out.push((start_addr, 8, SORT_ALIGNMENT));
                start_addr += 8;
                // an xfg hash always has a function right after
                break;
            }

            let zeros_length = self.scan_for_repeating_bytes(bytes, start_addr, Some(0x00), 2)?;
            if zeros_length > 0 {
                matched_something = true;
                seg_list.occupy(start_addr, zeros_length, Some(SORT_ALIGNMENT.to_owned()));
                out.push((start_addr, zeros_length, SORT_ALIGNMENT));
                start_addr += zeros_length;
            }

            let repeating_byte_length =
                self.scan_for_repeating_bytes(bytes, start_addr, None, 16)?;
            if repeating_byte_length > 0 {
                matched_something = true;
                seg_list.occupy(
                    start_addr,
                    repeating_byte_length,
                    Some("nodecode".to_owned()),
                );
                out.push((start_addr, repeating_byte_length, SORT_UNKNOWN));
                start_addr += repeating_byte_length;
            }

            let ramp_length = self.scan_for_monotonic_byte_ramp(bytes, start_addr, 16)?;
            if ramp_length > 0 {
                matched_something = true;
                seg_list.occupy(start_addr, ramp_length, Some("nodecode".to_owned()));
                out.push((start_addr, ramp_length, SORT_UNKNOWN));
                start_addr += ramp_length;
            }

            if !matched_something {
                break;
            }
        }

        let instr_alignment = self.instruction_alignment.max(1);
        if start_addr % instr_alignment > 0 {
            let size = instr_alignment - (start_addr % instr_alignment);
            let mut segment_sort = SORT_ALIGNMENT;
            if start_addr >= 1
                && seg_list.occupied_by_sort(start_addr - 1).as_deref() == Some("nodecode")
            {
                segment_sort = "nodecode";
            }
            seg_list.occupy(start_addr, size, Some(segment_sort.to_owned()));
            out.push((start_addr, size, SORT_UNKNOWN));
            start_addr = start_addr - start_addr % instr_alignment + instr_alignment;
            if !self.inside_regions(start_addr) {
                return Ok(Core::Continue);
            }
        }
        Ok(Core::Addr(start_addr))
    }

    /// `CFGFast._next_code_addr`.
    pub fn next_code_addr(
        &mut self,
        seg_list: &mut SegmentList,
        bytes: &ByteSource<'_>,
        out: &mut Vec<MemReq>,
    ) -> PyResult<Option<u64>> {
        loop {
            match self.next_code_addr_core(seg_list, bytes, out)? {
                Core::Continue => continue,
                Core::Done => return Ok(None),
                Core::Addr(addr) => {
                    if !seg_list.is_occupied(addr) {
                        return Ok(Some(addr));
                    }
                }
            }
        }
    }

    /// `CFGFast._next_code_addr_smart`.
    pub fn next_code_addr_smart(
        &mut self,
        seg_list: &mut SegmentList,
        bytes: &ByteSource<'_>,
        out: &mut Vec<MemReq>,
    ) -> PyResult<Option<u64>> {
        let ratio = match self.next_addr() {
            None => 0.0,
            Some(next_addr) => {
                Self::nodecode_bytes_ratio(seg_list, next_addr, self.nodecode_window_size)
            }
        };
        let next_allowed_addr: i64 = match self.next_addr() {
            Some(next_addr) if ratio >= self.nodecode_threshold => {
                next_addr + self.nodecode_step as i64
            }
            _ => 0,
        };
        loop {
            match self.next_code_addr_core(seg_list, bytes, out)? {
                Core::Continue => continue,
                Core::Done => return Ok(None),
                Core::Addr(addr) => {
                    if !seg_list.is_occupied(addr) {
                        if (addr as i64) < next_allowed_addr {
                            seg_list.occupy(
                                addr,
                                self.snap.arch.instruction_alignment,
                                Some("skip".to_owned()),
                            );
                            continue;
                        }
                        return Ok(Some(addr));
                    }
                }
            }
        }
    }
}

/// The linear-sweep state of one CFGFast run.
#[pyclass(module = "angr.rustylib.cfg_scan")]
pub struct LinearSweep {
    pub(crate) inner: Sweep,
}

fn sweep_bytes<'a>(sweep: &'a Sweep, callback: Option<&'a Bound<'a, PyAny>>) -> ByteSource<'a> {
    ByteSource {
        snap: &sweep.snap,
        callback,
    }
}

#[pymethods]
impl LinearSweep {
    /// `check_xfg` is `arch in {X86, AMD64} and not (simos is Linux)`.
    #[new]
    #[pyo3(signature = (snapshot, regions, exec_regions, nodecode_window_size, nodecode_threshold, nodecode_step, check_xfg))]
    fn new(
        snapshot: &LoaderSnapshot,
        regions: Vec<(u64, u64)>,
        exec_regions: Vec<(u64, u64)>,
        nodecode_window_size: u64,
        nodecode_threshold: f64,
        nodecode_step: u64,
        check_xfg: bool,
    ) -> Self {
        let snap = snapshot.inner.clone();
        let mut regions = regions;
        regions.sort();
        let is_x86 = matches!(snap.arch.name.as_str(), "X86" | "AMD64");
        let is_arm = snap.arch.is_arm();
        let ptr_size = snap.arch.bytes;
        let instruction_alignment = snap.arch.instruction_alignment;
        Self {
            inner: Sweep {
                snap,
                regions,
                exec_regions,
                resume_from: None,
                nodecode_window_size,
                nodecode_threshold,
                nodecode_step,
                is_x86,
                check_xfg,
                is_arm,
                ptr_size,
                instruction_alignment,
            },
        }
    }

    #[getter]
    fn get_next_addr(&self) -> Option<i64> {
        self.inner.next_addr()
    }

    #[setter]
    fn set_next_addr(&mut self, value: Option<i64>) {
        self.inner.set_next_addr(value);
    }

    fn inside_regions(&self, addr: u64) -> bool {
        self.inner.inside_regions(addr)
    }

    fn region_end(&self, addr: u64) -> Option<u64> {
        self.inner.region_end(addr)
    }

    fn addr_in_exec_memory_regions(&self, addr: u64) -> bool {
        addr_in_regions(&self.inner.exec_regions, addr)
    }

    #[pyo3(signature = (seg_list, alignment=None))]
    fn next_unscanned_addr(
        &mut self,
        seg_list: PyRef<'_, SegmentList>,
        alignment: Option<u64>,
    ) -> Option<u64> {
        self.inner.next_unscanned_addr(&seg_list, alignment)
    }

    fn update_unscanned_addr(&mut self, new_addr: u64) {
        self.inner.update_unscanned_addr(new_addr);
    }

    /// Returns `(addr or None, [(addr, size, sort), ...])`; the second item lists the `MemoryData` records to
    /// store, in creation order.
    #[pyo3(signature = (seg_list, byte_loader=None))]
    fn next_code_addr(
        &mut self,
        mut seg_list: PyRefMut<'_, SegmentList>,
        byte_loader: Option<Bound<'_, PyAny>>,
    ) -> PyResult<(Option<u64>, Vec<MemReq>)> {
        let mut out = Vec::new();
        let snap = self.inner.snap.clone();
        let bytes = ByteSource {
            snap: &snap,
            callback: byte_loader.as_ref(),
        };
        let addr = self.inner.next_code_addr(&mut seg_list, &bytes, &mut out)?;
        Ok((addr, out))
    }

    #[pyo3(signature = (seg_list, byte_loader=None))]
    fn next_code_addr_smart(
        &mut self,
        mut seg_list: PyRefMut<'_, SegmentList>,
        byte_loader: Option<Bound<'_, PyAny>>,
    ) -> PyResult<(Option<u64>, Vec<MemReq>)> {
        let mut out = Vec::new();
        let snap = self.inner.snap.clone();
        let bytes = ByteSource {
            snap: &snap,
            callback: byte_loader.as_ref(),
        };
        let addr = self
            .inner
            .next_code_addr_smart(&mut seg_list, &bytes, &mut out)?;
        Ok((addr, out))
    }

    #[staticmethod]
    fn nodecode_bytes_ratio(
        seg_list: PyRef<'_, SegmentList>,
        cutoff_addr: i64,
        window_size: u64,
    ) -> f64 {
        Sweep::nodecode_bytes_ratio(&seg_list, cutoff_addr, window_size)
    }

    #[pyo3(signature = (start_addr, min_length_nullterminated=3, min_length_non_nullterminated=13, byte_loader=None))]
    fn scan_for_printable_strings(
        &self,
        start_addr: u64,
        min_length_nullterminated: usize,
        min_length_non_nullterminated: usize,
        byte_loader: Option<Bound<'_, PyAny>>,
    ) -> PyResult<usize> {
        let bytes = sweep_bytes(&self.inner, byte_loader.as_ref());
        self.inner.scan_for_printable_strings(
            &bytes,
            start_addr,
            min_length_nullterminated,
            min_length_non_nullterminated,
        )
    }

    #[pyo3(signature = (start_addr, min_length_nullterminated=3, min_length_non_nullterminated=9, byte_loader=None))]
    fn scan_for_printable_widestrings(
        &self,
        start_addr: u64,
        min_length_nullterminated: usize,
        min_length_non_nullterminated: usize,
        byte_loader: Option<Bound<'_, PyAny>>,
    ) -> PyResult<usize> {
        let bytes = sweep_bytes(&self.inner, byte_loader.as_ref());
        self.inner.scan_for_printable_widestrings(
            &bytes,
            start_addr,
            min_length_nullterminated,
            min_length_non_nullterminated,
        )
    }

    #[pyo3(signature = (start_addr, repeating_byte, threshold=2, byte_loader=None))]
    fn scan_for_repeating_bytes(
        &self,
        start_addr: u64,
        repeating_byte: Option<u8>,
        threshold: u64,
        byte_loader: Option<Bound<'_, PyAny>>,
    ) -> PyResult<u64> {
        let bytes = sweep_bytes(&self.inner, byte_loader.as_ref());
        self.inner
            .scan_for_repeating_bytes(&bytes, start_addr, repeating_byte, threshold)
    }

    #[pyo3(signature = (start_addr, min_length, ignore=None))]
    fn repeating_byte_run_length(
        &self,
        start_addr: u64,
        min_length: u64,
        ignore: Option<u8>,
    ) -> u64 {
        self.inner
            .repeating_byte_run_length(start_addr, min_length, ignore)
    }

    #[pyo3(signature = (start_addr, threshold=4))]
    fn scan_for_fp_constants(&self, start_addr: u64, threshold: u64) -> u64 {
        self.inner.scan_for_fp_constants(start_addr, threshold)
    }

    #[pyo3(signature = (start_addr, threshold=16, byte_loader=None))]
    fn scan_for_monotonic_byte_ramp(
        &self,
        start_addr: u64,
        threshold: u64,
        byte_loader: Option<Bound<'_, PyAny>>,
    ) -> PyResult<u64> {
        let bytes = sweep_bytes(&self.inner, byte_loader.as_ref());
        self.inner
            .scan_for_monotonic_byte_ramp(&bytes, start_addr, threshold)
    }

    #[pyo3(signature = (start_addr, threshold=2))]
    fn scan_for_consecutive_pointers(&self, start_addr: u64, threshold: u64) -> u64 {
        self.inner
            .scan_for_consecutive_pointers(start_addr, threshold)
    }

    #[pyo3(signature = (start_addr, threshold=3, window=6))]
    fn scan_for_mixed_pointers(&self, start_addr: u64, threshold: u64, window: u64) -> u64 {
        self.inner
            .scan_for_mixed_pointers(start_addr, threshold, window)
    }

    fn scan_for_win_xfg_hash(&self, start_addr: u64) -> bool {
        self.inner.scan_for_win_xfg_hash(start_addr)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------------------------------------------

#[pyfunction]
#[pyo3(name = "go_preamble_supported")]
fn py_go_preamble_supported(arch_name: &str) -> bool {
    go_preamble_supported(arch_name)
}

#[pyfunction]
#[pyo3(name = "find_go_stack_check_preambles", signature = (blob, arch_name, base=0))]
fn py_find_go_stack_check_preambles(
    blob: &[u8],
    arch_name: &str,
    base: u64,
) -> Vec<(usize, usize, usize)> {
    find_go_stack_check_preambles(blob, arch_name, base)
}

#[pyfunction]
#[pyo3(name = "func_addrs_from_prologues", signature = (snapshot, binary_idx, exec_regions, has_arm_code=true, fallback=None))]
fn py_func_addrs_from_prologues(
    snapshot: &LoaderSnapshot,
    binary_idx: usize,
    exec_regions: Vec<(u64, u64)>,
    has_arm_code: bool,
    fallback: Option<Bound<'_, PyAny>>,
) -> PyResult<Vec<u64>> {
    if binary_idx >= snapshot.inner.objects.len() {
        return Err(PyValueError::new_err("binary index out of range"));
    }
    func_addrs_from_prologues(
        &snapshot.inner,
        binary_idx,
        &exec_regions,
        has_arm_code,
        fallback.as_ref(),
    )
}

#[pyfunction]
fn backer_exec_slices_py(
    exec_regions: Vec<(u64, u64)>,
    backer_mva: u64,
    backer_size: u64,
) -> Vec<(u64, u64)> {
    backer_exec_slices(&exec_regions, backer_mva, backer_size)
}

/// Match starts of a Python byte regex over `blob`, or `None` when the pattern needs Python's `re`.
#[pyfunction]
fn regex_find_all(pattern: &[u8], blob: &[u8]) -> Option<Vec<usize>> {
    let re = compile_py_byte_regex(pattern, false)?;
    Some(re.find_iter(blob).map(|m| m.start()).collect())
}

#[pymodule]
pub fn cfg_scan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LoaderSnapshot>()?;
    m.add_class::<LinearSweep>()?;
    m.add_function(wrap_pyfunction!(py_go_preamble_supported, m)?)?;
    m.add_function(wrap_pyfunction!(py_find_go_stack_check_preambles, m)?)?;
    m.add_function(wrap_pyfunction!(py_func_addrs_from_prologues, m)?)?;
    m.add_function(wrap_pyfunction!(backer_exec_slices_py, m)?)?;
    m.add_function(wrap_pyfunction!(regex_find_all, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_byte_regex_translation() {
        let re = compile_py_byte_regex(br"\x48[\x83,\x81]\xec[\x00-\xff]", false).unwrap();
        assert_eq!(re.find(b"\x90\x48\x83\xec\x20").unwrap().start(), 1);
        assert!(re.find(b"\x48\x84\xec\x20").is_none());
        // raw high bytes are escaped, not treated as UTF-8
        let re = compile_py_byte_regex(b"\x94\x21[\xc0-\xff]", false).unwrap();
        assert_eq!(re.find(b"\x00\x94\x21\xf0").unwrap().start(), 1);
        assert!(compile_py_byte_regex(br"(?!\x94)\x7c", false).is_none());
    }

    #[test]
    fn go_amd64_preamble() {
        // cmp rsp, [r14+0x10]; jbe +0x40
        let blob = b"\x49\x3b\x66\x10\x76\x40\x90\x90";
        assert_eq!(
            find_go_stack_check_preambles(blob, "AMD64", 0),
            vec![(0, 6, 6 + 0x40)]
        );
        // backwards branch is dropped
        let blob = b"\x49\x3b\x66\x10\x76\xfe";
        assert!(find_go_stack_check_preambles(blob, "AMD64", 0).is_empty());
    }

    #[test]
    fn exec_slices() {
        assert_eq!(backer_exec_slices(&[], 0x1000, 0x100), vec![(0, 0x100)]);
        assert_eq!(
            backer_exec_slices(
                &[(0x1010, 0x1020), (0x1020, 0x1030), (0x2000, 0x3000)],
                0x1000,
                0x100
            ),
            vec![(0x10, 0x30)]
        );
    }
}
