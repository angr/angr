from __future__ import annotations

import contextlib
import logging
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import cle
from cle.backends.externs import ExternObject, KernelObject
from cle.backends.ihex import Hex
from cle.backends.tls.elf_tls import ELFTLSObject
from sortedcontainers import SortedDict

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.block import Block
from angr.errors import SimEngineError, SimMemoryError
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort

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
        self._blanket = SortedDict()

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

    def floor_addr(self, addr: int) -> int:
        key = self._floor_key(addr)
        if key is None:
            raise KeyError(addr)
        return key

    def floor_item(self, addr: int) -> tuple[int, Any]:
        key = self.floor_addr(addr)
        return key, self._blanket[key]

    def floor_items(self, addr=None, reverse=False):
        if addr is None:
            start_addr = None
        else:
            try:
                start_addr = next(self._blanket.irange(maximum=addr, reverse=True))
            except StopIteration:
                start_addr = addr

        for key in self._blanket.irange(minimum=start_addr, reverse=reverse):
            yield key, self._blanket[key]

    def ceiling_addr(self, addr: int) -> int:
        key = self._ceiling_key(addr)
        if key is None:
            raise KeyError(addr)
        return key

    def ceiling_item(self, addr: int) -> tuple[int, Any]:
        key = self.ceiling_addr(addr)
        return key, self._blanket[key]

    def ceiling_items(self, addr=None, reverse=False, include_first=True):
        if addr is None:
            start_addr = None
        else:
            try:
                start_addr = next(self._blanket.irange(minimum=addr))
            except StopIteration:
                start_addr = addr

        for key in self._blanket.irange(maximum=start_addr if include_first else start_addr - 1, reverse=reverse):
            yield key, self._blanket[key]

    def __getitem__(self, addr):
        return self._blanket[addr]

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
        size = self._obj_size(obj)
        pieces = self._carve(addr, addr + size) if size is not None and size > 0 else None
        self._blanket[addr] = obj
        cb = self._on_object_added_callback
        if cb:
            if pieces:
                for piece_addr, piece in pieces:
                    cb(piece_addr, piece)
            cb(addr, obj)
        pending = self._pending_added
        if pending is not None:
            if pieces:
                pending.extend(pieces)
            pending.append((addr, obj))
            if self._bulk_depth == 0:
                self._flush_added()

    def add_objs(self, objs: Iterable[tuple[int, Any]]) -> None:
        """
        add_obj() each (addr, obj) in order; on_objects_added gets all of their events in one call.
        """
        with self._bulk():
            for addr, obj in objs:
                self.add_obj(addr, obj)

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

    def _carve(self, start: int, end: int) -> list[tuple[int, Any]] | None:
        """
        Remove or trim existing objects so that no object in the blanket overlaps [start, end), except that an object
        at `start` may be left in place for the caller to overwrite.

        :return: The re-inserted remainders, in insertion order, or None if nothing overlaps.
        """
        blanket = self._blanket
        inner = self._overlapping_keys(start, end)
        if not inner:
            return None

        pieces: list[tuple[int, Any]] = []
        for key in inner:
            obj = blanket[key]
            obj_end = key + max(self._obj_size(obj) or 1, 1)
            left = self._trim(obj, key, start) if key < start else None
            if left is not None:
                # overwriting keeps the key in place
                blanket[key] = left
                pieces.append((key, left))
            elif key != start:
                del blanket[key]
            if obj_end > end:
                right = self._trim(obj, end, obj_end)
                if right is not None:
                    blanket[end] = right
                    pieces.append((end, right))
        return pieces

    def _overlapping_keys(self, start: int, end: int) -> list[int]:
        """
        The keys of the objects that overlap [start, end), ascending: the closest key before `start` if its object
        extends into the range, then every key in [start, end).

        This walks SortedList's sublists (_maxes/_lists, unchanged throughout sortedcontainers 2.x) directly: irange()
        builds an islice chain per call, and the positional API (bisect_left, keys()[i]) maintains a positional index
        on every later insertion; both are measurably slower for one lookup per added object.
        """
        sl = self._blanket._list
        maxes: list[int] = sl._maxes
        if not maxes:
            return []
        lists: list[list[int]] = sl._lists
        keys: list[int] = []
        pos = bisect_left(maxes, start)
        if pos == len(maxes):
            # every key is below start
            floor_key = maxes[-1]
        else:
            sub = lists[pos]
            idx = bisect_left(sub, start)
            if idx:
                floor_key = sub[idx - 1]
            elif pos:
                floor_key = lists[pos - 1][-1]
            else:
                floor_key = None
            n_lists = len(lists)
            while True:
                if idx == len(sub):
                    pos += 1
                    if pos == n_lists:
                        break
                    sub = lists[pos]
                    idx = 0
                key = sub[idx]
                if key >= end:
                    break
                keys.append(key)
                idx += 1
        if floor_key is not None and floor_key + max(self._obj_size(self._blanket[floor_key]) or 1, 1) > start:
            keys.insert(0, floor_key)
        return keys

    def _floor_key(self, addr: int) -> int | None:
        """
        The greatest key <= addr. Bisects SortedList's sublists like _overlapping_keys.
        """
        sl = self._blanket._list
        maxes: list[int] = sl._maxes
        pos = bisect_right(maxes, addr)
        if pos == len(maxes):
            return maxes[-1] if maxes else None
        sub: list[int] = sl._lists[pos]
        idx = bisect_right(sub, addr)
        if idx:
            return sub[idx - 1]
        return maxes[pos - 1] if pos else None

    def _ceiling_key(self, addr: int) -> int | None:
        """
        The smallest key >= addr. Bisects SortedList's sublists like _overlapping_keys.
        """
        sl = self._blanket._list
        maxes: list[int] = sl._maxes
        pos = bisect_left(maxes, addr)
        if pos == len(maxes):
            return None
        sub: list[int] = sl._lists[pos]
        return sub[bisect_left(sub, addr)]

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

    def remove_obj(self, addr, fill: bool = True):
        """
        Remove the object at `addr` from the blanket. When `fill` is set (the default), the removed object's span is
        re-filled with an Unknown region so that the blanket remains a total cover of the mapped address space.
        Removing a missing address is a no-op.

        :return: The removed object, or None if no object exists at `addr`.
        """
        obj = self._blanket.pop(addr, None)
        if obj is None:
            return None
        if self._on_object_removed_callback:
            self._on_object_removed_callback(addr, obj)

        size = self._obj_size(obj)
        if fill and size:
            cle_obj = self.project.loader.find_object_containing(addr, membership_check=False)
            loader = None if cle_obj is None or isinstance(cle_obj, ExternObject) else self.project.loader
            section = cle_obj.find_section_containing(addr) if cle_obj is not None else None
            filler = Unknown(addr, size, object_=cle_obj, section=section, loader=loader)
            self._blanket[addr] = filler
            if self._on_object_added_callback:
                self._on_object_added_callback(addr, filler)
            if self._pending_added is not None:
                self._pending_added.append((addr, filler))
                if self._bulk_depth == 0:
                    self._flush_added()
        return obj

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
        for _, specs in self.kb.functions.iter_local_block_specs():
            for addr, size, byte_string in specs:
                # Function.blocks skips blocks it cannot create
                try:
                    block = factory_block(addr, size=size, byte_string=byte_string)
                except (SimEngineError, SimMemoryError):
                    continue
                self.add_obj(block.addr, block)

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

        for addr, memory_data in cfg_model.memory_data.items():
            memory_data: MemoryData
            if memory_data.sort == MemoryDataSort.CodeReference:
                # skip Code Reference
                continue
            self.add_obj(addr, memory_data)

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
        # The region should be [min_addr, max_addr)

        try:
            addr = self.floor_addr(min_addr)
            if addr < min_addr:
                raise KeyError
        except KeyError:
            # there is no other lower address
            try:
                next_addr = self.ceiling_addr(min_addr)
                if next_addr >= max_addr:
                    raise KeyError
            except KeyError:
                next_addr = max_addr

            size = next_addr - min_addr
            loader = None if obj is None or isinstance(obj, cle.ExternObject) else self.project.loader
            self.add_obj(
                min_addr, Unknown(min_addr, size, object_=obj, segment=segment, section=section, loader=loader)
            )

        blanket = self._blanket
        addr = min_addr
        while addr < max_addr:
            # addr is always a key: min_addr has an object now, and every later addr was found by _ceiling_key (a gap
            # Unknown may overwrite the object there with a remainder, but never removes the key)
            last_item = blanket[addr]

            # Make sure everything has a non-zero size
            last_item_size = 1 if last_item.size == 0 or last_item.size is None else last_item.size
            end_addr = addr + last_item_size
            if end_addr < max_addr:
                next_key = self._ceiling_key(end_addr)
                next_addr = max_addr if next_key is None else next_key
                if next_addr > end_addr:
                    # there is a gap
                    size = next_addr - end_addr
                    loader = None if obj is None or isinstance(obj, cle.ExternObject) else self.project.loader
                    self.add_obj(
                        end_addr, Unknown(end_addr, size, object_=obj, segment=segment, section=section, loader=loader)
                    )
                addr = next_addr
            else:
                addr = max_addr


AnalysesHub.register_default("CFB", CFBlanket)
AnalysesHub.register_default("CFBlanket", CFBlanket)
