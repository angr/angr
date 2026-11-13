"""
Build the Rust-side :class:`angr.rustylib.cfg_scan.LoaderSnapshot`: an immutable copy of what CFG recovery needs
from cle (objects, sections, segments, symbols, memory backers, arch constants), taken once per analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import archinfo
from cle import (
    ELF,
    PE,
    XBE,
    Blob,
    Clemory,
    Coff,
    ExternObject,
    Hex,
    KernelObject,
    MachO,
    PEStubs,
    SRec,
    TLSObject,
)
from cle.backends import Backend, NamedRegion
from cle.backends.macho.section import MachOSection
from cle.backends.region import Region, Section
from cle.backends.regions import Regions

from angr.rustylib.cfg_scan import LoaderSnapshot

if TYPE_CHECKING:
    from cle import Loader


# cfg_scan.BackendKind, in the order CFGBase._executable_memory_regions tests backends
KIND_ELF = 0
KIND_PE = 1
KIND_XBE = 2
KIND_MACHO = 3
KIND_HEX_SREC = 4
KIND_BLOB = 5
KIND_NAMED_REGION = 6
KIND_PE_STUBS = 7
KIND_PSEUDO = 8
KIND_OTHER = 9


@dataclass(slots=True)
class RegionSpec:
    vaddr: int
    memsize: int
    filesize: int | None
    name: str | None
    is_executable: bool
    is_readable: bool
    is_writable: bool
    only_uninit: bool


@dataclass(slots=True)
class SymbolSpec:
    relative_addr: int
    rebased_addr: int
    size: int
    is_function: bool
    is_import: bool
    name: str | None


@dataclass(slots=True)
class ArchSpec:
    name: str
    bytes: int
    bits: int
    big_endian: bool
    instruction_alignment: int | None
    nop_instruction: bytes
    function_prologs: list[bytes]
    thumb_prologs: list[bytes]
    branch_delay_slot: bool
    call_pushes_ret: bool


@dataclass(slots=True)
class ObjectSpec:
    min_addr: int
    max_addr: int
    mapped_base: int
    kind: int
    is_main: bool
    has_memory: bool
    is_outer: bool
    mem: tuple[int, int, bool] | None
    sections: list[RegionSpec] = field(default_factory=list)
    segments: list[RegionSpec] = field(default_factory=list)
    sections_sorted: list[int] = field(default_factory=list)
    segments_sorted: list[int] = field(default_factory=list)
    symbols: list[SymbolSpec] = field(default_factory=list)
    hex_regions: list[tuple[int, int]] = field(default_factory=list)
    backers: list[tuple[int, object]] = field(default_factory=list)


def _leaf_backers(memory: Clemory) -> list[tuple[int, object]]:
    # list[int] backers have no buffer interface; they are rare, so copy them
    return [(start, bytes(data) if isinstance(data, list) else data) for start, data in memory.backers()]


def backend_kind(obj: Backend) -> int:
    if isinstance(obj, ELF):
        return KIND_ELF
    if isinstance(obj, (Coff, PE)):
        return KIND_PE
    if isinstance(obj, XBE):
        return KIND_XBE
    if isinstance(obj, MachO):
        return KIND_MACHO
    if isinstance(obj, (Hex, SRec)):
        return KIND_HEX_SREC
    if isinstance(obj, Blob):
        return KIND_BLOB
    if isinstance(obj, NamedRegion):
        return KIND_NAMED_REGION
    if isinstance(obj, PEStubs):
        return KIND_PE_STUBS
    if isinstance(obj, (ExternObject, KernelObject, TLSObject)):
        return KIND_PSEUDO
    return KIND_OTHER


def _only_uninit(region: Region) -> bool:
    # only sections carry this flag, and the bare Section base class leaves it unimplemented
    if not isinstance(region, Section):
        return False
    try:
        return bool(region.only_contains_uninitialized_data)
    except NotImplementedError:
        return False


def _region_spec(region: Region, exec_segment_sections: set[int] | None) -> RegionSpec:
    is_executable = region.is_executable
    if exec_segment_sections is not None and isinstance(region, MachOSection):
        # _executable_memory_regions only uses MachO sections that sit inside an executable segment
        is_executable = is_executable and id(region) in exec_segment_sections
    return RegionSpec(
        vaddr=region.vaddr,
        memsize=region.memsize,
        filesize=region.filesize,
        name=region.name if isinstance(region, Section) and isinstance(region.name, str) else None,
        is_executable=is_executable,
        is_readable=region.is_readable,
        is_writable=region.is_writable,
        only_uninit=_only_uninit(region),
    )


def _sorted_indices(regions: Regions) -> list[int]:
    # find_region_containing bisects Regions._sorted_list, whose order among equal vaddrs depends on insertion history
    pos = {id(r): i for i, r in enumerate(regions)}
    return [pos[id(r)] for r in regions._sorted_list]  # pylint:disable=protected-access


def object_spec(obj: Backend) -> ObjectSpec:
    kind = backend_kind(obj)
    if obj.is_outer:
        # containers (fat binaries, archives) are skipped by every loader lookup and may lack memory or regions
        return ObjectSpec(obj.min_addr, obj.max_addr, obj.mapped_base, kind, obj.is_main_bin, False, True, None)

    mem = None
    backers: list[tuple[int, object]] = []
    if obj.has_memory and isinstance(obj.memory, Clemory):
        mem = (obj.memory.min_addr, obj.memory.max_addr, obj.memory.consecutive)
        backers = _leaf_backers(obj.memory)

    exec_segment_sections: set[int] | None = None
    if isinstance(obj, MachO):
        exec_segment_sections = {id(sec) for seg in obj.segments if seg.is_executable for sec in seg.sections}

    hex_regions: list[tuple[int, int]] = []
    if isinstance(obj, (Hex, SRec)):
        hex_regions = list(obj.regions)

    return ObjectSpec(
        min_addr=obj.min_addr,
        max_addr=obj.max_addr,
        mapped_base=obj.mapped_base,
        kind=kind,
        is_main=obj.is_main_bin,
        has_memory=obj.has_memory,
        is_outer=obj.is_outer,
        mem=mem,
        sections=[_region_spec(sec, exec_segment_sections) for sec in obj.sections],
        segments=[_region_spec(seg, None) for seg in obj.segments],
        sections_sorted=_sorted_indices(obj.sections),
        segments_sorted=_sorted_indices(obj.segments),
        symbols=[
            SymbolSpec(
                relative_addr=sym.relative_addr,
                rebased_addr=sym.rebased_addr,
                size=sym.size,
                is_function=sym.is_function,
                is_import=sym.is_import,
                name=sym.name,
            )
            for sym in obj.symbols
        ],
        hex_regions=hex_regions,
        backers=backers,
    )


def arch_spec(arch: archinfo.Arch) -> ArchSpec:
    thumb_prologs = list(arch.thumb_prologs) if isinstance(arch, archinfo.ArchARM) else []
    return ArchSpec(
        name=arch.name,
        bytes=arch.bytes,
        bits=arch.bits,
        big_endian=arch.memory_endness == archinfo.Endness.BE,
        instruction_alignment=arch.instruction_alignment,
        nop_instruction=bytes(arch.nop_instruction),
        function_prologs=sorted(arch.function_prologs),
        thumb_prologs=sorted(thumb_prologs),
        branch_delay_slot=arch.branch_delay_slot,
        call_pushes_ret=arch.call_pushes_ret,
    )


def build_loader_snapshot(
    loader: Loader, arch: archinfo.Arch, extra_objects: list[Backend] | None = None
) -> LoaderSnapshot:
    """
    Snapshot ``loader``. ``extra_objects`` are appended after ``loader.all_objects`` (and are excluded from
    loader-wide lookups); use :func:`object_index` to find them.
    """

    objects = list(loader.all_objects)
    loader_object_count = len(objects)
    for obj in extra_objects or []:
        if not any(obj is o for o in objects):
            objects.append(obj)

    backers = _leaf_backers(loader.memory)

    loader_min_addr = loader.min_addr if loader.all_objects else 0
    loader_max_addr = loader.max_addr if loader.all_objects else 0
    return LoaderSnapshot(
        [object_spec(obj) for obj in objects],
        loader_object_count,
        backers,
        arch_spec(arch),
        loader_min_addr,
        loader_max_addr,
    )


def object_index(loader: Loader, obj: Backend, extra_objects: list[Backend] | None = None) -> int:
    """
    The index of ``obj`` in the snapshot built by :func:`build_loader_snapshot` with the same arguments.
    """

    objects = list(loader.all_objects)
    for extra in extra_objects or []:
        if not any(extra is o for o in objects):
            objects.append(extra)
    for idx, o in enumerate(objects):
        if o is obj:
            return idx
    raise ValueError(f"{obj!r} is not part of the loader snapshot")
