"""
Read Go runtime type descriptors (``internal/abi.Type``) and itabs out of a binary's ``runtime.moduledata``.

This is the DWARF-less counterpart of :mod:`angr.go.analyses.dwarf_signatures`: the descriptors are the ground truth
for the layout of every type in this binary. Type strings follow the canonical syntax of :mod:`angr.go.signature`;
named types are qualified with the full import path taken from the descriptor's ``UncommonType.PkgPath``.

Layouts handled (``src/runtime/symtab.go`` and ``src/internal/abi/type.go``):

- go1.20 .. go1.25: ``moduledata.typelinks`` ([]int32 offsets from ``types``) and ``itablinks`` ([]*itab).
- go1.26+: ``typedesclen`` / ``itaboffset`` / ``itabsize`` describe contiguous runs of descriptors and itabs that are
  walked with ``Type.DescriptorSize``; ``epclntab`` was inserted after ``gofunc``.
- go1.18 / go1.19 (no ``covctrs``) are accepted as well since the descriptor layout is identical.
"""

from __future__ import annotations

import logging
import os
import re
import struct
from typing import TYPE_CHECKING, NamedTuple

from cle.backends.gopclntab import GO_PCLNTAB_MAGICS, PCLNTAB_SECTION_NAMES

from angr.go.analyses.dwarf_signatures import (
    _BASIC_KIND_NAMES,
    KIND_ARRAY,
    KIND_CHAN,
    KIND_FUNC,
    KIND_INTERFACE,
    KIND_MAP,
    KIND_PTR,
    KIND_SLICE,
    KIND_STRUCT,
    _goarch,
)
from angr.go.signature import GoNamedType, GoSignatureSet, GoStructField
from angr.go.sim_type import PREDECLARED
from angr.go.utils.version import identify_go_version

if TYPE_CHECKING:
    from angr.project import Project

log = logging.getLogger(__name__)

TFLAG_UNCOMMON = 1 << 0
TFLAG_EXTRA_STAR = 1 << 1
TFLAG_NAMED = 1 << 2
KIND_MASK = 0x1F

NAME_EMBEDDED = 1 << 3

UNCOMMON_SIZE = 16
METHOD_SIZE = 16
IMETHOD_SIZE = 8

_CHAN_PREFIX = {1: "<-chan ", 2: "chan<- ", 3: "chan "}

# moduledata word indices shared by every supported layout (the pcHeader pointer is word 0)
_MD_FUNCNAMETAB = 1
_MD_MINPC = 20
_MD_MAXPC = 21
_MD_TEXT = 22
_MD_ETEXT = 23

_PCLNTAB_MAGIC_RE = re.compile(rb"[\xf0\xf1\xfa]\xff\xff\xff\x00\x00[\x01\x02\x04][\x04\x08]")


class _Layout(NamedTuple):
    name: str
    types: int  # word index of moduledata.types
    contiguous: bool  # typedesclen/itaboffset/itabsize instead of typelinks/itablinks


_LAYOUT_TYPELINKS_118 = _Layout("go1.18", 35, False)
_LAYOUT_TYPELINKS = _Layout("go1.20", 37, False)
_LAYOUT_CONTIGUOUS = _Layout("go1.26", 37, True)


class _Moduledata(NamedTuple):
    addr: int
    layout: _Layout
    types: int
    etypes: int
    typelinks: list[int]  # descriptor addresses (typelinks layout)
    typedesc_end: int  # end of the contiguous descriptor run (contiguous layout)
    itabs: list[int]  # itab addresses (typelinks layout)
    itab_range: tuple[int, int]  # contiguous layout


class GoTypeDescriptors:
    """
    The runtime type descriptors of one binary.

    :ivar go_version:       The Go release the binary was built with, when identifiable.
    :ivar types:            Every named type as a GoNamedType record (only ``types`` is filled).
    :ivar addr_to_name:     Descriptor address -> canonical Go type string.
    :ivar name_to_addr:     The reverse map (first descriptor wins).
    :ivar itabs:            itab address -> (interface type name, concrete type name).
    :ivar moduledata_addr:  Address of ``runtime.firstmoduledata``, or None when none was found.
    :ivar types_addr:       ``moduledata.types``: the base that every NameOff/TypeOff (and DWARF's
                            ``DW_AT_go_runtime_type``) is relative to.

    The eager walk covers everything reachable from the typelinks and itabs; descriptors that only code references
    (anonymous interfaces of type assertions, map buckets, ...) are parsed on demand by :meth:`resolve`.
    """

    __slots__ = (
        "_reader",
        "addr_to_name",
        "go_version",
        "itabs",
        "moduledata_addr",
        "name_to_addr",
        "types",
        "types_addr",
    )

    def __init__(
        self,
        go_version: str | None = None,
        goarch: str | None = None,
        types: GoSignatureSet | None = None,
        addr_to_name: dict[int, str] | None = None,
        itabs: dict[int, tuple[str, str]] | None = None,
        moduledata_addr: int | None = None,
        types_addr: int | None = None,
        reader: _Reader | None = None,
    ):
        self._reader = reader
        self.go_version = go_version
        self.types = types if types is not None else GoSignatureSet(go_version=go_version, goarch=goarch)
        self.addr_to_name = addr_to_name if addr_to_name is not None else {}
        self.name_to_addr: dict[str, int] = {}
        for addr, name in self.addr_to_name.items():
            self.name_to_addr.setdefault(name, addr)
        self.itabs = itabs if itabs is not None else {}
        self.moduledata_addr = moduledata_addr
        self.types_addr = types_addr

    def resolve(self, addr: int) -> str | None:
        """The type string of the descriptor at ``addr``, parsing it on demand when no typelink reached it."""
        name = self.addr_to_name.get(addr)
        if name is not None or self._reader is None:
            return name
        name = self._reader.resolve(addr)
        if name is not None:
            self._index_new_names()
        return name

    def resolve_itab(self, addr: int) -> tuple[str, str] | None:
        pair = self.itabs.get(addr)
        if pair is not None or self._reader is None:
            return pair
        pair = self._reader.resolve_itab(addr)
        if pair is not None:
            self._index_new_names()
        return pair

    def _index_new_names(self) -> None:
        for addr, name in self.addr_to_name.items():
            self.name_to_addr.setdefault(name, addr)

    def __repr__(self):
        return (
            f"<GoTypeDescriptors {self.go_version}: {len(self.addr_to_name)} descriptors, "
            f"{len(self.types.types)} named types, {len(self.itabs)} itabs>"
        )


class _Memory:
    """Byte access to the loaded image with one cached slab per segment of the main object."""

    def __init__(self, project: Project):
        self._memory = project.loader.memory
        self._obj = project.loader.main_object
        self._slabs: list[tuple[int, int, bytes]] = []
        self._failed: set[int] = set()

    def detach(self, start: int, end: int) -> None:
        """Keep only a copy of ``[start, end)`` and drop the loader so the owner no longer pins a Project."""
        data = self.read(start, end - start)
        self._slabs = [(start, end, data)] if data is not None else []
        self._memory = None
        self._obj = None

    def slab_at(self, addr: int, n: int = 1) -> tuple[bytes, int] | None:
        for start, end, data in self._slabs:
            if start <= addr and addr + n <= end:
                return data, addr - start
        if self._memory is None:
            return None
        region = self._obj.segments.find_region_containing(addr) or self._obj.sections.find_region_containing(addr)
        if region is not None and region.vaddr not in self._failed and region.memsize:
            try:
                data = self._memory.load(region.vaddr, region.memsize)
            except KeyError:
                self._failed.add(region.vaddr)
            else:
                self._slabs.append((region.vaddr, region.vaddr + len(data), data))
                if addr + n <= region.vaddr + len(data):
                    return data, addr - region.vaddr
        try:
            data = self._memory.load(addr, n)
        except KeyError:
            return None
        return (data, 0) if len(data) == n else None

    def read(self, addr: int, n: int) -> bytes | None:
        r = self.slab_at(addr, n)
        if r is None:
            return None
        data, off = r
        return data[off : off + n]

    def unpack(self, fmt: str, addr: int) -> tuple | None:
        n = struct.calcsize(fmt)
        r = self.slab_at(addr, n)
        if r is None:
            return None
        data, off = r
        return struct.unpack_from(fmt, data, off)


class _Header(NamedTuple):
    size: int
    ptr_bytes: int
    tflag: int
    align: int
    kind: int
    str_off: int


class _Reader:
    """Walks the descriptor graph starting from the moduledata roots and spells canonical type strings."""

    def __init__(self, project: Project, go_version: str | None):
        arch = project.arch
        self.project = project
        self.go_version = go_version
        m = re.match(r"go1\.(\d+)", go_version or "")
        self.minor: int | None = int(m.group(1)) if m else None
        self.ptr = arch.bytes
        self.end = "<" if arch.memory_endness == "Iend_LE" else ">"
        self.mem = _Memory(project)
        self._w = "Q" if self.ptr == 8 else "I"
        self._fmt_word = self.end + self._w
        self._fmt_header = self.end + self._w * 2 + "IBBBB" + self._w * 2 + "ii"
        self._fmt_uncommon = self.end + "iHHI"
        self.common = 4 * self.ptr + 16
        self.md: _Moduledata | None = None

        self._headers: dict[int, _Header] = {}
        self._names: dict[int, str] = {}
        self._name_addrs: dict[str, int] = {}
        self._pending: list[tuple[int, str, _Header]] = []
        self.types: dict[str, GoNamedType] = {}
        self.itabs: dict[int, tuple[str, str]] = {}

    # ------------------------------------------------------------------ primitives

    def word(self, addr: int) -> int | None:
        r = self.mem.unpack(self._fmt_word, addr)
        return r[0] if r is not None else None

    def words(self, addr: int, n: int) -> tuple | None:
        return self.mem.unpack(self.end + self._w * n, addr) if n else ()

    def header(self, addr: int) -> _Header | None:
        h = self._headers.get(addr)
        if h is None:
            r = self.mem.unpack(self._fmt_header, addr)
            if r is None:
                return None
            size, ptr_bytes, _hash, tflag, align, _falign, kind, _eq, _gc, str_off, _ptrtothis = r
            h = _Header(size, ptr_bytes, tflag, align, kind & KIND_MASK, str_off)
            self._headers[addr] = h
        return h

    def name(self, addr: int) -> tuple[str, int]:
        """Decode an ``abi.Name``: flag byte, varint length, bytes."""
        r = self.mem.slab_at(addr, 2)
        if r is None:
            return "", 0
        data, off = r
        flags = data[off]
        i = off + 1
        length = shift = 0
        while i < len(data):
            b = data[i]
            i += 1
            length |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        return data[i : i + length].decode("utf-8", "replace"), flags

    def name_off(self, off: int) -> str:
        return self.name(self.md.types + off)[0] if off else ""

    def type_off(self, off: int) -> int | None:
        return self.md.types + off if off not in (0, -1, 0xFFFFFFFF) else None

    def looks_like_descriptor(self, addr: int) -> bool:
        h = self.header(addr)
        if h is None or not 1 <= h.kind <= 26 or h.ptr_bytes > h.size or h.size >= 1 << 48:
            return False
        if h.align not in (1, 2, 4, 8, 16, 32):
            return False
        if h.str_off <= 0 or self.md.types + h.str_off >= self.md.etypes:
            return False
        s, _ = self.name(self.md.types + h.str_off)
        return 0 < len(s) < 4096 and s.isprintable()

    # ------------------------------------------------------------------ moduledata

    def find_moduledata(self) -> _Moduledata | None:
        loader = self.project.loader
        pclntab = self._find_pclntab()
        if pclntab is None:
            return None
        sym = loader.find_symbol("runtime.firstmoduledata")
        if sym is not None:
            md = self._parse_moduledata(sym.rebased_addr, pclntab)
            if md is not None:
                return md
        needle = struct.pack(self._fmt_word, pclntab)
        obj = loader.main_object
        regions = [r for r in obj.sections if r.is_writable and r.memsize] or [
            r for r in obj.segments if r.is_writable and r.memsize
        ]
        for region in regions:
            data = self.mem.read(region.vaddr, region.memsize)
            if data is None:
                continue
            pos = data.find(needle)
            while pos != -1:
                if pos % self.ptr == 0:
                    md = self._parse_moduledata(region.vaddr + pos, pclntab)
                    if md is not None:
                        return md
                pos = data.find(needle, pos + 1)
        return None

    def _find_pclntab(self) -> int | None:
        loader = self.project.loader
        obj = loader.main_object
        sym = loader.find_symbol("runtime.pclntab")
        if sym is not None:
            return sym.rebased_addr
        for sec in obj.sections:
            if sec.name in PCLNTAB_SECTION_NAMES and sec.memsize:
                return sec.vaddr
        regions = [r for r in obj.sections if not r.is_writable and not r.is_executable and r.memsize] or [
            r for r in obj.segments if not r.is_writable and not r.is_executable and r.memsize
        ]
        for region in regions:
            data = self.mem.read(region.vaddr, region.memsize)
            if data is None:
                continue
            for m in _PCLNTAB_MAGIC_RE.finditer(data):
                magic = struct.unpack_from(self.end + "I", data, m.start())[0]
                if magic in GO_PCLNTAB_MAGICS and data[m.start() + 7] == self.ptr:
                    return region.vaddr + m.start()
        return None

    def _parse_moduledata(self, addr: int, pclntab: int) -> _Moduledata | None:
        nwords = 52
        r = self.words(addr, nwords)
        if r is None:
            return None
        w = list(r)
        if w[0] != pclntab:
            return None
        # every []T header spells len == cap; text <= minpc < maxpc <= etext
        for lo in (2, 5, 8, 11, 14, 17):
            if w[lo] != w[lo + 1]:
                return None
        if not w[_MD_TEXT] <= w[_MD_MINPC] < w[_MD_MAXPC] <= w[_MD_ETEXT]:
            return None
        if not pclntab <= w[_MD_FUNCNAMETAB] < pclntab + (1 << 32):
            return None

        candidates = [_LAYOUT_CONTIGUOUS, _LAYOUT_TYPELINKS, _LAYOUT_TYPELINKS_118]
        if self.minor is not None and self.minor < 26:
            candidates = [_LAYOUT_TYPELINKS, _LAYOUT_TYPELINKS_118, _LAYOUT_CONTIGUOUS]
        for layout in candidates:
            md = self._try_layout(addr, layout, w)
            if md is not None:
                log.debug("moduledata at %#x uses the %s layout", addr, layout.name)
                return md
        log.warning("moduledata at %#x has an unrecognized layout", addr)
        return None

    def _try_layout(self, addr: int, layout: _Layout, w: list[int]) -> _Moduledata | None:
        i = layout.types
        types = w[i]
        if layout.contiguous:
            typedesclen, etypes, itaboffset, itabsize = w[i + 1], w[i + 2], w[i + 3], w[i + 4]
            span = etypes - types
            if not (0 < span < 1 << 32 and self.ptr <= typedesclen <= span and itaboffset + itabsize <= span):
                return None
            if w[i + 9] != w[i + 10]:  # textsectmap len == cap
                return None
            if self.mem.slab_at(types, span) is None:
                return None
            return _Moduledata(
                addr,
                layout,
                types,
                etypes,
                [],
                types + typedesclen,
                [],
                (types + itaboffset, types + itaboffset + itabsize),
            )

        etypes = w[i + 1]
        tl_ptr, tl_len, tl_cap = w[i + 7], w[i + 8], w[i + 9]
        it_ptr, it_len, it_cap = w[i + 10], w[i + 11], w[i + 12]
        if not 0 < etypes - types < 1 << 32 or w[i + 5] != w[i + 6] or tl_len != tl_cap or it_len != it_cap:
            return None
        if tl_len >= 1 << 24 or it_len >= 1 << 24:
            return None
        if self.mem.slab_at(types, etypes - types) is None:
            return None
        typelinks: list[int] = []
        if tl_len:
            r = self.mem.unpack(self.end + "i" * tl_len, tl_ptr)
            if r is None:
                return None
            typelinks = [types + off for off in r]
        itabs: list[int] = []
        if it_len:
            r = self.words(it_ptr, it_len)
            if r is None:
                return None
            itabs = list(r)
        return _Moduledata(addr, layout, types, etypes, typelinks, 0, itabs, (0, 0))

    # ------------------------------------------------------------------ enumeration

    def read(self) -> bool:
        self.md = self.find_moduledata()
        if self.md is None:
            return False
        roots: list[int] = []
        itab_addrs: list[int] = []
        if self.md.layout.contiguous:
            roots = self._walk_descriptors(self.md.types + self.ptr, self.md.typedesc_end)
            itab_addrs = self._walk_itabs(*self.md.itab_range)
        else:
            roots = list(self.md.typelinks)
            itab_addrs = list(self.md.itabs)

        for addr in roots:
            if self.looks_like_descriptor(addr):
                self.spell(addr)
            else:
                log.debug("skipping non-descriptor typelink target %#x", addr)
        self._drain()

        for addr in itab_addrs:
            r = self.words(addr, 2)
            if r is None:
                continue
            inter, typ = r
            if not (self.looks_like_descriptor(inter) and self.looks_like_descriptor(typ)):
                continue
            self.itabs[addr] = (self.spell(inter), self.spell(typ))
        self._drain()
        # everything resolve() may still need lives in [types, etypes)
        self.mem.detach(self.md.types, self.md.etypes)
        self.project = None
        return True

    def resolve(self, addr: int) -> str | None:
        md = self.md
        if md is None or not md.types <= addr < md.etypes or addr % self.ptr or not self.looks_like_descriptor(addr):
            return None
        name = self.spell(addr)
        self._drain()
        return name

    def resolve_itab(self, addr: int) -> tuple[str, str] | None:
        md = self.md
        if md is None or not md.types <= addr < md.etypes or addr % self.ptr:
            return None
        r = self.words(addr, 2)
        if r is None:
            return None
        inter, typ = r
        if not (self.looks_like_descriptor(inter) and self.looks_like_descriptor(typ)):
            return None
        if self.header(inter).kind != KIND_INTERFACE:
            return None
        pair = (self.spell(inter), self.spell(typ))
        self._drain()
        self.itabs[addr] = pair
        return pair

    def _walk_descriptors(self, start: int, end: int) -> list[int]:
        found: list[int] = []
        addr = _align_up(start, self.ptr)
        while addr < end:
            if not self.looks_like_descriptor(addr):
                resync = self._resync(addr, end)
                if resync is None:
                    log.warning("descriptor walk lost sync at %#x; %d descriptors found", addr, len(found))
                    break
                log.debug("descriptor walk resynced from %#x to %#x", addr, resync)
                addr = resync
            found.append(addr)
            size = self.descriptor_size(addr)
            if size is None:
                break
            addr = _align_up(addr + size, self.ptr)
        return found

    def _resync(self, addr: int, end: int) -> int | None:
        probe = _align_up(addr + 1, self.ptr)
        while probe < min(end, addr + 0x1000):
            if self.looks_like_descriptor(probe):
                return probe
            probe += self.ptr
        return None

    def _walk_itabs(self, start: int, end: int) -> list[int]:
        found: list[int] = []
        addr = start
        base = 4 * self.ptr  # Inter, Type, Hash (padded to a word), Fun[0]
        while addr + base <= end:
            r = self.words(addr, 4)
            if r is None:
                break
            inter, _typ, _hash, fun0 = r
            found.append(addr)
            size = base
            if fun0:
                ih = self.header(inter)
                nmethods = self.word(inter + self.common + 2 * self.ptr) if ih is not None else None
                if nmethods is None or nmethods > 1 << 16:
                    break
                size += max(nmethods - 1, 0) * self.ptr
            addr = _align_up(addr + size, self.ptr)
        return found

    def descriptor_size(self, addr: int) -> int | None:
        h = self.header(addr)
        if h is None:
            return None
        base = self.kind_size(h.kind)
        add = 0
        if h.kind == KIND_FUNC:
            r = self.mem.unpack(self.end + "HH", addr + self.common)
            if r is None:
                return None
            add = (r[0] + (r[1] & 0x7FFF)) * self.ptr
        elif h.kind == KIND_INTERFACE:
            n = self.word(addr + self.common + 2 * self.ptr)
            add = (n or 0) * IMETHOD_SIZE
        elif h.kind == KIND_STRUCT:
            n = self.word(addr + self.common + 2 * self.ptr)
            add = (n or 0) * 3 * self.ptr
        size = base
        if h.tflag & TFLAG_UNCOMMON:
            r = self.mem.unpack(self._fmt_uncommon, addr + base)
            if r is None:
                return None
            size += UNCOMMON_SIZE + r[1] * METHOD_SIZE
        return size + add

    def kind_size(self, kind: int) -> int:
        """sizeof the kind-specific descriptor struct (without UncommonType and trailing arrays)."""
        c, p = self.common, self.ptr
        if kind in (KIND_PTR, KIND_SLICE):
            return c + p
        if kind == KIND_ARRAY:
            return c + 3 * p
        if kind == KIND_CHAN:
            return c + 2 * p
        if kind == KIND_FUNC:
            return _align_up(c + 4, p)
        if kind in (KIND_INTERFACE, KIND_STRUCT):
            return c + 4 * p
        if kind == KIND_MAP:
            # go1.22: Key Elem Bucket Hasher KeySize ValueSize BucketSize Flags
            # go1.24 swiss: Key Elem Group Hasher GroupSize SlotSize ElemOff Flags
            # go1.27: Key Elem Group Hasher GroupSize KeysOff KeyStride ElemsOff ElemStride ElemOff Flags
            minor = self.minor if self.minor is not None else 99
            if minor < 24:
                return c + 4 * p + 8
            if minor < 27:
                return _align_up(c + 7 * p + 4, p)
            return _align_up(c + 10 * p + 4, p)
        return c

    # ------------------------------------------------------------------ spelling

    def spell(self, addr: int) -> str:
        name = self._names.get(addr)
        if name is not None:
            return name
        h = self.header(addr)
        if h is None:
            self._names[addr] = "unsafe.Pointer"
            return "unsafe.Pointer"
        raw = self.name_off(h.str_off).replace("interface {}", "any")
        if h.tflag & TFLAG_EXTRA_STAR and raw.startswith("*"):
            raw = raw[1:]
        if h.tflag & TFLAG_NAMED:
            name = self._qualified_name(addr, h, raw)
            # types declared inside functions lose their linker-side "·N" suffix in Str; keep them distinct
            base, k = name, 1
            while self._name_addrs.get(name, addr) != addr:
                k += 1
                name = f"{base}·{k}"
            self._name_addrs[name] = addr
            self._names[addr] = name
            if name not in PREDECLARED and name not in self.types:
                self.types[name] = GoNamedType(name, "named")  # placeholder until drained
                self._pending.append((addr, name, h))
            return name
        # unnamed composite; the raw string guards against cycles while components are spelled
        self._names[addr] = raw or "unsafe.Pointer"
        name = self._compose(addr, h)
        self._names[addr] = name
        return name

    def _qualified_name(self, addr: int, h: _Header, raw: str) -> str:
        pkgpath = ""
        if h.tflag & TFLAG_UNCOMMON:
            r = self.mem.unpack(self._fmt_uncommon, addr + self.kind_size(h.kind))
            if r is not None:
                pkgpath = self.name_off(r[0])
        if not pkgpath:
            return raw
        bare = raw
        for prefix in (pkgpath + ".", pkgpath.rsplit("/", 1)[-1] + "."):
            if raw.startswith(prefix):
                bare = raw[len(prefix) :]
                break
        else:
            if "." in raw:
                bare = raw.split(".", 1)[1]
        return f"{pkgpath}.{bare}"

    def _compose(self, addr: int, h: _Header) -> str:
        kind = h.kind
        if kind in _BASIC_KIND_NAMES:
            return _BASIC_KIND_NAMES[kind]
        c = self.common
        if kind == KIND_PTR:
            return "*" + self._spell_word(addr + c)
        if kind == KIND_SLICE:
            return "[]" + self._spell_word(addr + c)
        if kind == KIND_ARRAY:
            return f"[{self.word(addr + c + 2 * self.ptr) or 0}]" + self._spell_word(addr + c)
        if kind == KIND_CHAN:
            d = self.word(addr + c + self.ptr) or 3
            return _CHAN_PREFIX.get(d & 3, "chan ") + self._spell_word(addr + c)
        if kind == KIND_MAP:
            return f"map[{self._spell_word(addr + c)}]{self._spell_word(addr + c + self.ptr)}"
        if kind == KIND_FUNC:
            return self._func_str(addr, h)
        if kind == KIND_INTERFACE:
            methods = self._imethods(addr)
            if not methods:
                return "any"
            return "interface { " + "; ".join(n + t[len("func") :] for n, t in methods) + " }"
        if kind == KIND_STRUCT:
            fields = self._fields(addr)
            if not fields:
                return "struct {}"
            return "struct { " + "; ".join(t if emb else f"{n} {t}" for n, t, _, emb in fields) + " }"
        return "unsafe.Pointer"

    def _spell_word(self, addr: int) -> str:
        target = self.word(addr)
        return self.spell(target) if target else "unsafe.Pointer"

    def _func_str(self, addr: int, h: _Header) -> str:
        r = self.mem.unpack(self.end + "HH", addr + self.common)
        if r is None:
            return "func()"
        n_in, n_out = r
        variadic = bool(n_out & 0x8000)
        n_out &= 0x7FFF
        arr = addr + self.kind_size(KIND_FUNC) + (UNCOMMON_SIZE if h.tflag & TFLAG_UNCOMMON else 0)
        ptrs = self.words(arr, n_in + n_out)
        if ptrs is None:
            return "func()"
        params = [self.spell(p) for p in ptrs[:n_in]]
        results = [self.spell(p) for p in ptrs[n_in:]]
        if variadic and params and params[-1].startswith("[]"):
            params[-1] = "..." + params[-1][2:]
        s = "func(" + ", ".join(params) + ")"
        if len(results) == 1:
            s += " " + results[0]
        elif results:
            s += " (" + ", ".join(results) + ")"
        return s

    def _imethods(self, addr: int) -> list[tuple[str, str]]:
        r = self.words(addr + self.common + self.ptr, 2)
        if r is None:
            return []
        mptr, n = r
        if n == 0 or n > 1 << 16:
            return []
        raw = self.mem.unpack(self.end + "ii" * n, mptr)
        if raw is None:
            return []
        out = []
        for i in range(n):
            name = self.name_off(raw[2 * i])
            t = self.type_off(raw[2 * i + 1])
            out.append((name, self.spell(t) if t is not None else "func()"))
        return out

    def _fields(self, addr: int) -> list[tuple[str, str, int, bool]]:
        r = self.words(addr + self.common + self.ptr, 2)
        if r is None:
            return []
        fptr, n = r
        if n == 0 or n > 1 << 16:
            return []
        raw = self.words(fptr, 3 * n)
        if raw is None:
            return []
        out = []
        for i in range(n):
            name_ptr, typ, offset = raw[3 * i : 3 * i + 3]
            name, flags = self.name(name_ptr)
            out.append(
                (name or f"_{i}", self.spell(typ) if typ else "unsafe.Pointer", offset, bool(flags & NAME_EMBEDDED))
            )
        return out

    def _methods(self, addr: int, h: _Header) -> None:
        """Spell the method types of a concrete type so they land in addr_to_name."""
        base = addr + self.kind_size(h.kind)
        r = self.mem.unpack(self._fmt_uncommon, base)
        if r is None:
            return
        _pkg, mcount, _xcount, moff = r
        if mcount == 0 or mcount > 1 << 16:
            return
        raw = self.mem.unpack(self.end + "iiii" * mcount, base + moff)
        if raw is None:
            return
        for i in range(mcount):
            t = self.type_off(raw[4 * i + 1])
            if t is not None and self.looks_like_descriptor(t):
                self.spell(t)

    # ------------------------------------------------------------------ named types

    def _drain(self) -> None:
        while self._pending:
            addr, name, h = self._pending.pop()
            self.types[name] = self._materialize(addr, name, h)
            if h.tflag & TFLAG_UNCOMMON:
                self._methods(addr, h)

    def _materialize(self, addr: int, name: str, h: _Header) -> GoNamedType:
        if h.kind == KIND_STRUCT:
            fields = [GoStructField(n, t, off) for n, t, off, _ in self._fields(addr)]
            return GoNamedType(name, "struct", size=h.size, align=h.align, fields=fields)
        if h.kind == KIND_INTERFACE:
            return GoNamedType(name, "interface", size=h.size, align=h.align, methods=self._imethods(addr))
        return GoNamedType(name, "named", size=h.size, align=h.align, underlying=self._compose(addr, h))


def _align_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


_CACHE: dict[tuple, GoTypeDescriptors] = {}
_CACHE_LIMIT = 8


def _cache_key(project: Project) -> tuple | None:
    obj = project.loader.main_object
    path = getattr(obj, "binary", None)
    if not path or not os.path.isfile(path):
        return None
    st = os.stat(path)
    return (os.path.abspath(path), st.st_mtime_ns, st.st_size, obj.mapped_base)


def read_go_type_descriptors(project: Project, use_cache: bool = True) -> GoTypeDescriptors:
    """
    Parse the runtime type descriptors and itabs of the main object. Returns an empty result when the binary has no
    Go moduledata. Results are cached per binary within the process.
    """
    key = _cache_key(project) if use_cache else None
    if key is not None and key in _CACHE:
        return _CACHE[key]

    go_version = identify_go_version(project)
    goarch = _goarch(project.arch)
    reader = _Reader(project, go_version)
    found = reader.read()
    result = GoTypeDescriptors(
        go_version=go_version,
        goarch=goarch,
        types=GoSignatureSet(go_version=go_version, goarch=goarch, types=reader.types),
        addr_to_name=reader._names,
        itabs=reader.itabs,
        moduledata_addr=reader.md.addr if found and reader.md is not None else None,
        types_addr=reader.md.types if found and reader.md is not None else None,
        reader=reader if found else None,
    )
    if key is not None:
        if len(_CACHE) >= _CACHE_LIMIT:
            del _CACHE[next(iter(_CACHE))]
        _CACHE[key] = result
    return result
