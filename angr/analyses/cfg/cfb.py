from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import cle
from archinfo import ArchARM
from cle.backends.externs import ExternObject, KernelObject
from cle.backends.ihex import Hex
from cle.backends.tls.elf_tls import ELFTLSObject

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.block import Block
from angr.errors import SimEngineError, SimMemoryError
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataDict, MemoryDataSort
from angr.rustylib.cfb import (
    CLASS_BLOCK,
    CLASS_MD,
    CLASS_OTHER,
    CLASS_UNKNOWN,
    F_THUMB,
    KIND_BLOCK_TRIM,
    KIND_MD,
    KIND_TRIM,
    KIND_UNKNOWN,
    CfbStore,
)

_l = logging.getLogger(name=__name__)


class CFBlanketView:
    """
    A view into the control-flow blanket.
    """

    def __init__(self, cfb):
        self._cfb = cfb

    def __getitem__(self, item):
        if isinstance(item, slice):
            addr = item.start
            start_addr = self._cfb.floor_addr(addr)

            addr_ = start_addr
            while True:
                obj = self._cfb[addr_]
                yield obj

                addr_ += obj
                # Find gaps
                # TODO: finish it
                raise NotImplementedError


#
# Memory region
#


class MemoryRegion:
    def __init__(self, addr, size, type_, object_, cle_region):
        self.addr = addr
        self.size = size
        self.type = type_
        self.object = object_
        self.cle_region = cle_region

    def __repr__(self):
        return f"<MemoryRegion {self.addr:#x}-{self.addr + self.size:#x}, type {self.type}>"


#
# An address can be mapped to one of the following types of object
# - Block
# - MemoryData
# - Unknown
#


class Unknown:
    """
    An unknown byte region in a control-flow blanket.
    """

    # the maximum number of bytes to load for display purposes; matches the display cap of the linear viewer in angr
    # management (101 lines of 16 bytes each)
    MAX_BYTES = 1616

    def __init__(self, addr, size, bytes_=None, object_=None, segment=None, section=None, loader=None):
        self.addr = addr
        self.size = size

        # Optional
        self._bytes = bytes_
        self._loader = loader
        self.object = object_
        self.segment = segment
        self.section = section

        if size == 0:
            raise Exception("You cannot create an unknown region of size 0.")

    @property
    def bytes(self):
        """
        The bytes of this region, for display purposes. Lazily loaded on first access (and capped at MAX_BYTES) when
        a loader is available.
        """
        if self._bytes is None and self._loader is not None:
            try:
                self._bytes = self._loader.memory.load(self.addr, min(self.size, self.MAX_BYTES))
            except KeyError:
                # the address is not mapped; do not retry
                self._loader = None
        return self._bytes

    def trimmed(self, new_start: int, new_size: int) -> Unknown:
        """
        Create a copy of this region covering [new_start, new_start + new_size). Bytes that were already loaded are
        sliced instead of being loaded again.
        """
        bytes_ = None
        if self._loader is None and self._bytes is not None:
            offset = new_start - self.addr
            if 0 <= offset < len(self._bytes):
                bytes_ = self._bytes[offset : offset + new_size]
        return Unknown(
            new_start,
            new_size,
            bytes_=bytes_,
            object_=self.object,
            segment=self.segment,
            section=self.section,
            loader=self._loader,
        )

    def __repr__(self):
        return f"<Unknown {self.addr:#x}-{self.addr + self.size:#x}>"


class _BlanketView:
    """
    `CFBlanket._blanket`: a read-only mapping view of the blanket, for code written against the SortedDict of earlier
    versions.
    """

    __slots__ = ("_cfb",)

    def __init__(self, cfb: CFBlanket):
        self._cfb = cfb

    def __len__(self) -> int:
        return len(self._cfb._store)

    def __contains__(self, addr) -> bool:
        return isinstance(addr, int) and addr in self._cfb._store

    def __getitem__(self, addr):
        return self._cfb[addr]

    def __iter__(self) -> Iterator[int]:
        return iter(self._cfb._store.keys())

    def get(self, addr, default=None):
        if addr not in self:
            return default
        return self._cfb[addr]

    def keys(self) -> list[int]:
        return self._cfb._store.keys()

    def values(self) -> list[Any]:
        return [obj for _, obj in self._cfb.items()]

    def items(self) -> list[tuple[int, Any]]:
        return self._cfb.items()

    def irange(self, minimum=None, maximum=None, inclusive=(True, True), reverse=False) -> Iterator[int]:
        return iter(self._cfb._store.irange(minimum, maximum, inclusive, reverse))


class CFBlanket(Analysis):
    """
    A Control-Flow Blanket is a representation for storing all instructions, data entries, and bytes of a full program.

    Region types:
    - section
    - segment
    - extern
    - tls
    - kernel
    """

    # the classes intervals() reports
    CLASS_BLOCK = CLASS_BLOCK
    CLASS_MD = CLASS_MD
    CLASS_UNKNOWN = CLASS_UNKNOWN
    CLASS_OTHER = CLASS_OTHER

    def __init__(
        self,
        exclude_region_types: set[str] | None = None,
        on_object_added: Callable[[int, Any], None] | None = None,
        on_object_removed: Callable[[int, Any], None] | None = None,
        on_objects_added: Callable[[list[tuple[int, Any]]], None] | None = None,
    ):
        """
        :param on_object_added:   Callable with parameters (addr, obj) called after an object is added to the blanket.
        :param on_object_removed: Callable with parameters (addr, obj) called after an object is removed from the
                                  blanket.
        :param on_objects_added:  Callable with a list of (addr, obj) called after objects are added to the blanket:
                                  once per add_obj/remove_obj call that added objects, once per add_objs call, and
                                  once for the initial build. The lists hold what on_object_added gets, in order.
        """
        self._store = CfbStore(Block, MemoryData, Unknown, isinstance(self.project.arch, ArchARM))
        # (object, segment, section, loader) of the native Unknown records, by region id
        self._unknown_regions: list[tuple[Any, Any, Any, Any]] = []
        self._unknown_region_ids: dict[tuple[int, int, int, bool], int] = {}
        # the memory data of the CFG model that MemoryData records refer to
        self._md_dict: MemoryDataDict | None = None

        self._on_object_added_callback = on_object_added
        self._on_object_removed_callback = on_object_removed
        self._on_objects_added_callback = on_objects_added
        # the (addr, obj) pairs not yet delivered to on_objects_added; None without that callback
        self._pending_added: list[tuple[int, Any]] | None = None if on_objects_added is None else []
        self._bulk_depth = 0
        self._regions = []
        self._exclude_region_types = exclude_region_types or set()

        self._init_regions()

        # initialize
        with self._bulk():
            self._add_function_blocks()
            self._mark_memory_data()
            self._mark_unknowns()

    def _init_regions(self):
        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.MetaELF):
                if obj.segments:
                    if "segment" not in self._exclude_region_types:
                        for segment in obj.segments:
                            if segment.memsize > 0:
                                mr = MemoryRegion(segment.vaddr, segment.memsize, "segment", obj, segment)
                                self._regions.append(mr)
                elif obj.sections:
                    if "section" not in self._exclude_region_types:
                        # Enumerate sections in an ELF file
                        for section in obj.sections:
                            if section.occupies_memory:
                                mr = MemoryRegion(section.vaddr, section.memsize, "section", obj, section)
                                self._regions.append(mr)
                else:
                    raise NotImplementedError(
                        "Currently ELFs without sections or segments are not supported. Please "
                        "implement or complain on GitHub."
                    )
            elif isinstance(obj, cle.PE):
                if obj.sections:
                    if "section" not in self._exclude_region_types:
                        for section in obj.sections:
                            mr = MemoryRegion(section.vaddr, section.memsize, "section", obj, section)
                            self._regions.append(mr)
                else:
                    raise NotImplementedError(
                        "Currently PEs without sections are not supported. Please report to "
                        "GitHub and provide an example binary."
                    )
            elif isinstance(obj, KernelObject):
                if "kernel" not in self._exclude_region_types:
                    size = obj.max_addr - obj.min_addr
                    mr = MemoryRegion(obj.min_addr, size, "kernel", obj, None)
                    self._regions.append(mr)
            elif isinstance(obj, ExternObject):
                if "extern" not in self._exclude_region_types:
                    size = obj.next_addr
                    mr = MemoryRegion(obj.min_addr, size, "extern", obj, None)
                    self._regions.append(mr)
            elif isinstance(obj, ELFTLSObject):
                if "tls" not in self._exclude_region_types:
                    size = obj.max_addr - obj.min_addr
                    mr = MemoryRegion(obj.min_addr, size, "tls", obj, None)
                    self._regions.append(mr)
            elif isinstance(obj, Hex):
                if obj.segments:
                    for segment in obj.segments:
                        mr = MemoryRegion(segment.vaddr, segment.memsize, "segment", obj, segment)
                        self._regions.append(mr)
                else:
                    base_addr = obj.min_addr  # but it's always 0
                    size = obj.max_addr - base_addr
                    mr = MemoryRegion(base_addr, size, "segment", obj, None)
                    self._regions.append(mr)
            elif hasattr(obj, "sections") and obj.sections:
                if "section" not in self._exclude_region_types:
                    for section in obj.sections:
                        if section.memsize > 0:
                            mr = MemoryRegion(section.vaddr, section.memsize, "section", obj, section)
                            self._regions.append(mr)
            elif hasattr(obj, "segments") and obj.segments:
                if "segment" not in self._exclude_region_types:
                    for segment in obj.segments:
                        if segment.memsize > 0:
                            mr = MemoryRegion(segment.vaddr, segment.memsize, "segment", obj, segment)
                            self._regions.append(mr)
            else:
                size = obj.size if hasattr(obj, "size") else obj.max_addr - obj.min_addr
                type_ = "TODO"
                mr = MemoryRegion(obj.min_addr, size, type_, obj, obj)
                self._regions.append(mr)

        # Sort them just in case
        self._regions = sorted(self._regions, key=lambda x: x.addr)

    @property
    def regions(self):
        """
        Return all memory regions.
        """

        return self._regions

    @property
    def _blanket(self) -> _BlanketView:
        """
        A read-only mapping view of the blanket (the SortedDict of earlier versions).
        """
        return _BlanketView(self)

    def floor_addr(self, addr: int) -> int:
        key = self._store.floor_key(addr)
        if key is None:
            raise KeyError(addr)
        return key

    def floor_item(self, addr: int) -> tuple[int, Any]:
        key = self.floor_addr(addr)
        return key, self[key]

    def floor_items(self, addr=None, reverse=False):
        """
        The items from the greatest key <= `addr` (or `addr` if there is none; everything if `addr` is None) to the
        end, ascending, or from the end down to there with `reverse`. Iteration resumes by key, so it survives
        concurrent changes.
        """
        if addr is None:
            start_addr = None
        else:
            key = self._store.floor_key(addr)
            start_addr = addr if key is None else key
        yield from self._iter_range(start_addr, None, reverse)

    def ceiling_addr(self, addr: int) -> int:
        key = self._store.ceiling_key(addr)
        if key is None:
            raise KeyError(addr)
        return key

    def ceiling_item(self, addr: int) -> tuple[int, Any]:
        key = self.ceiling_addr(addr)
        return key, self[key]

    def ceiling_items(self, addr=None, reverse=False, include_first=True):
        """
        The items from the start up to the smallest key >= `addr` (or `addr` if there is none; everything if `addr`
        is None), excluding that key unless `include_first`, ascending or descending with `reverse`. Iteration
        resumes by key, so it survives concurrent changes.
        """
        if addr is None:
            start_addr = None
        else:
            key = self._store.ceiling_key(addr)
            start_addr = addr if key is None else key
        yield from self._iter_range(None, start_addr if include_first else start_addr - 1, reverse)

    def _iter_range(self, minimum: int | None, maximum: int | None, reverse: bool) -> Iterator[tuple[int, Any]]:
        """
        The items with keys in [minimum, maximum], fetched in growing chunks.
        """
        limit = 16
        store = self._store
        while True:
            pairs, specs = store.scan(minimum, maximum, reverse, limit)
            if specs:
                self._materialize_pairs(pairs, specs)
            yield from pairs
            if len(pairs) < limit:
                return
            if reverse:
                maximum = pairs[-1][0] - 1
            else:
                minimum = pairs[-1][0] + 1
            limit = min(limit * 2, 4096)

    def items(self) -> list[tuple[int, Any]]:
        """
        All (addr, obj) pairs, ascending.
        """
        pairs, specs = self._store.scan(None, None, False)
        if specs:
            self._materialize_pairs(pairs, specs)
        return pairs

    def intervals(
        self, minimum: int | None = None, maximum: int | None = None
    ) -> list[tuple[int, int | None, int, str | None]]:
        """
        (addr, size, cls, sort) of every object with an address in [minimum, maximum], ascending, without creating
        the objects. cls is one of CLASS_BLOCK, CLASS_MD, CLASS_UNKNOWN and CLASS_OTHER; sort is the MemoryData sort.
        """
        return self._store.intervals(minimum, maximum)

    def __getitem__(self, addr):
        obj, spec = self._store.get(addr)
        if spec is None:
            return obj
        obj = self._materialize(spec)
        if spec[2] != KIND_MD:
            self._store.cache_put([(spec[1], spec[6], obj)])
        return obj

    def _materialize(self, spec: tuple) -> Any:
        """
        The object of a native record, from its spec (index, key, kind, size, flags, payload, generation, sort, src).
        """
        _, key, kind, size, flags, payload, _, sort, src = spec
        if kind == KIND_UNKNOWN:
            object_, segment, section, loader = self._unknown_regions[payload]
            # positional: about half the cost of keywords, and native Unknowns are the most common events
            return Unknown(key, size, None, object_, segment, section, loader)
        if kind == KIND_BLOCK_TRIM:
            return self.project.factory.block(key, size=size, thumb=bool(flags & F_THUMB))
        if kind == KIND_MD:
            md = self._md_dict.get(key) if self._md_dict is not None else None
            return md if md is not None else MemoryData(key, size, self._store.sort_name(sort))
        assert kind == KIND_TRIM
        if isinstance(src, int):
            base = self._md_dict.get(src) if self._md_dict is not None else None
            if base is None:
                return MemoryData(key, size, self._store.sort_name(sort))
            src = base
        return self._trim(src, key, key + size)

    def _materialize_pairs(self, pairs: list, specs: list) -> None:
        cache = []
        for spec in specs:
            obj = self._materialize(spec)
            pairs[spec[0]] = (spec[1], obj)
            if spec[2] != KIND_MD:
                cache.append((spec[1], spec[6], obj))
        if cache:
            self._store.cache_put(cache)

    @property
    def _want_events(self) -> bool:
        return self._on_object_added_callback is not None or self._pending_added is not None

    def _deliver_events(self) -> None:
        """
        Hand the store's queued events to on_object_added and to the on_objects_added queue.
        """
        pairs, specs = self._store.take_events()
        if specs:
            self._materialize_pairs(pairs, specs)
        cb = self._on_object_added_callback
        if cb:
            for addr, obj in pairs:
                cb(addr, obj)
        pending = self._pending_added
        if pending is not None:
            pending.extend(pairs)
            if self._bulk_depth == 0:
                self._flush_added()

    @staticmethod
    def _obj_size(obj) -> int | None:
        size = getattr(obj, "size", None)
        return size if isinstance(size, int) else None

    def add_obj(self, addr, obj):
        """
        Add an object `obj` to the blanket at the specified address `addr`, keeping the blanket non-overlapping:
        existing objects that overlap [addr, addr + obj.size) are removed or trimmed, and the trimmed-off remainders
        are re-inserted. Objects without an integer size are stored as zero-span entries and never cause trimming.

        on_object_added is called once the blanket holds `obj`: first for each re-inserted remainder, then for `obj`.
        """
        want = self._want_events
        self._store.add_obj(addr, obj, want)
        if want:
            self._deliver_events()

    def add_objs(self, objs: Iterable[tuple[int, Any]]) -> None:
        """
        add_obj() each (addr, obj) in order; on_objects_added gets all of their events in one call.
        """
        with self._bulk():
            if self._on_object_added_callback is not None:
                # on_object_added sees the blanket after each object
                for addr, obj in objs:
                    self.add_obj(addr, obj)
                return
            items = objs if isinstance(objs, list) else list(objs)
            want = self._pending_added is not None
            try:
                self._store.add_objs(items, want)
            except TypeError:
                # not (addr, obj) tuples; nothing was added
                self._store.add_objs([(addr, obj) for addr, obj in items], want)
            if want:
                self._deliver_events()

    @contextlib.contextmanager
    def _bulk(self) -> Iterator[None]:
        """
        Defer on_objects_added until the outermost bulk operation ends.
        """
        self._bulk_depth += 1
        try:
            yield
        finally:
            self._bulk_depth -= 1
            if self._bulk_depth == 0:
                self._flush_added()

    def _flush_added(self) -> None:
        pending = self._pending_added
        if pending:
            self._pending_added = []
            assert self._on_objects_added_callback is not None
            self._on_objects_added_callback(pending)

    def _trim(self, obj, new_start: int, new_end: int):
        """
        Create a copy of `obj` trimmed to [new_start, new_end), or None if the object cannot be trimmed.
        """
        new_size = new_end - new_start
        if new_size <= 0:
            return None
        if isinstance(obj, Unknown):
            return obj.trimmed(new_start, new_size)
        if isinstance(obj, Block):
            # constructing a Block with an explicit size does not lift; lifting only happens if the block is ever
            # rendered or otherwise accessed
            return self.project.factory.block(new_start, size=new_size, thumb=getattr(obj, "thumb", False))
        if isinstance(obj, MemoryData):
            # memory data objects may be shared with the knowledge base; trim a copy, never the original
            trimmed = obj.copy()
            trimmed.addr = new_start
            trimmed.size = new_size
            trimmed.reference_size = obj.reference_size
            return trimmed
        return None

    def _unknown_region(self, object_, segment, section, loader) -> int:
        """
        The region id of Unknown records with these attributes.
        """
        key = (id(object_), id(segment), id(section), loader is not None)
        region = self._unknown_region_ids.get(key)
        if region is None:
            region = len(self._unknown_regions)
            self._unknown_regions.append((object_, segment, section, loader))
            self._unknown_region_ids[key] = region
        return region

    def remove_obj(self, addr, fill: bool = True):
        """
        Remove the object at `addr` from the blanket. When `fill` is set (the default), the removed object's span is
        re-filled with an Unknown region so that the blanket remains a total cover of the mapped address space.
        Removing a missing address is a no-op.

        :return: The removed object, or None if no object exists at `addr`.
        """
        popped = self._store.pop(addr)
        if popped is None:
            return None
        obj, spec = popped
        if spec is not None:
            obj = self._materialize(spec)
        if obj is None:
            return None
        if self._on_object_removed_callback:
            self._on_object_removed_callback(addr, obj)

        size = self._obj_size(obj)
        if fill and size:
            cle_obj = self.project.loader.find_object_containing(addr, membership_check=False)
            loader = None if cle_obj is None or isinstance(cle_obj, ExternObject) else self.project.loader
            section = cle_obj.find_section_containing(addr) if cle_obj is not None else None
            want = self._want_events
            self._store.set_unknown(addr, size, self._unknown_region(cle_obj, None, section, loader), want)
            if want:
                self._deliver_events()
        return obj

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_store"] = self._store.state()
        del state["_unknown_region_ids"]
        return state

    def __setstate__(self, state):
        state = dict(state)
        store = CfbStore(Block, MemoryData, Unknown, isinstance(state["project"].arch, ArchARM))
        old_blanket = state.pop("_blanket", None)
        if old_blanket is None:
            store.load_state(*state.pop("_store"))
        else:
            # pickled by the SortedDict implementation
            store.put_objs(list(old_blanket.items()))
        self.__dict__.update(state)
        self._store = store
        self.__dict__.setdefault("_unknown_regions", [])
        self.__dict__.setdefault("_md_dict", None)
        self.__dict__.setdefault("_on_objects_added_callback", None)
        self.__dict__.setdefault("_pending_added", None)
        self.__dict__.setdefault("_bulk_depth", 0)
        self._unknown_region_ids = {
            (id(o), id(seg), id(sec), ldr is not None): i for i, (o, seg, sec, ldr) in enumerate(self._unknown_regions)
        }

    def add_function(self, func):
        """
        Add a function `func` and all blocks of this function to the blanket.
        """
        for block in func.blocks:
            self.add_obj(block.addr, block)

    def _add_function_blocks(self) -> None:
        """
        add_function() for every function of the knowledge base, without loading spilled functions.
        """
        factory_block = self.project.factory.block
        blocks = []
        for _, specs in self.kb.functions.iter_local_block_specs():
            for addr, size, byte_string in specs:
                # Function.blocks skips blocks it cannot create
                try:
                    block = factory_block(addr, size=size, byte_string=byte_string)
                except (SimEngineError, SimMemoryError):
                    continue
                blocks.append((block.addr, block))
        self.add_objs(blocks)

    def dbg_repr(self):
        """
        The debugging representation of this CFBlanket.

        :return:    The debugging representation of this CFBlanket.
        :rtype:     str
        """

        output = []

        for obj in self.project.loader.all_objects:
            for section in obj.sections:
                if section.memsize == 0:
                    continue
                min_addr, max_addr = section.min_addr, section.max_addr
                output.append(f"### Object {section!r}")
                output.append(f"### Range {min_addr:#x}-{max_addr:#x}")

                pos = min_addr
                while pos < max_addr:
                    try:
                        addr, thing = self.floor_item(pos)
                        output.append(f"{addr:#x}: {thing!r}")

                        if thing.size == 0:
                            pos += 1
                        else:
                            pos += thing.size
                    except KeyError:
                        pos += 1

                output.append("")

        return "\n".join(output)

    def _mark_memory_data(self):
        """
        Mark all memory data.

        :return: None
        """
        if "CFGFast" not in self.kb.cfgs:
            return
        cfg_model = self.kb.cfgs["CFGFast"]
        memory_data = cfg_model.memory_data
        if not isinstance(memory_data, MemoryDataDict):
            self.add_objs([(addr, md) for addr, md in memory_data.items() if md.sort != MemoryDataSort.CodeReference])
            return
        # MemoryData records refer to the model's records, minus code references
        self._md_dict = memory_data
        want = self._want_events
        self._store.mark_memory_data(memory_data.store, want)
        if want:
            self._deliver_events()

    def _mark_unknowns(self):
        """
        Mark all unmapped regions.

        :return: None
        """

        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.ELF):
                # sections?
                if obj.sections and "section" not in self._exclude_region_types:
                    for section in obj.sections:
                        if not section.memsize or not section.vaddr:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, section=section)
                elif obj.segments and "segment" not in self._exclude_region_types:
                    for segment in obj.segments:
                        if not segment.memsize:
                            continue
                        min_addr, max_addr = segment.min_addr, segment.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, segment=segment)
                else:
                    # is it empty?
                    _l.warning("Empty ELF object %s.", repr(obj))
            elif isinstance(obj, cle.PE):
                if obj.sections:
                    for section in obj.sections:
                        if not section.memsize:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, section=section)
                else:
                    # is it empty?
                    _l.warning("Empty PE object %s.", repr(obj))
            elif isinstance(obj, cle.MachO):
                if obj.sections and "section" not in self._exclude_region_types:
                    for section in obj.sections:
                        if not section.memsize or not section.vaddr:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, section=section)
                elif obj.segments and "segment" not in self._exclude_region_types:
                    for segment in obj.segments:
                        if not segment.memsize:
                            continue
                        min_addr, max_addr = segment.min_addr, segment.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, segment=segment)
                else:
                    # is it empty?
                    _l.warning("Empty MachO object %s.", repr(obj))
            elif isinstance(obj, ELFTLSObject):
                if "tls" in self._exclude_region_types:
                    # Skip them for now
                    pass
                else:
                    min_addr, max_addr = obj.min_addr, obj.max_addr
                    self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj)
            elif isinstance(obj, KernelObject):
                if "kernel" in self._exclude_region_types:
                    # skip
                    pass
                else:
                    min_addr, max_addr = obj.min_addr, obj.max_addr
                    self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj)
            else:
                min_addr, max_addr = obj.min_addr, obj.max_addr
                self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj)

    def _mark_unknowns_core(self, min_addr, max_addr, obj=None, segment=None, section=None):
        """
        Fill the gaps in [min_addr, max_addr) with Unknown regions.
        """
        loader = None if obj is None or isinstance(obj, cle.ExternObject) else self.project.loader
        want = self._want_events
        self._store.mark_unknowns([(min_addr, max_addr, self._unknown_region(obj, segment, section, loader))], want)
        if want:
            self._deliver_events()


AnalysesHub.register_default("CFB", CFBlanket)
AnalysesHub.register_default("CFBlanket", CFBlanket)
