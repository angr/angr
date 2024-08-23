from __future__ import annotations
import logging
from typing import Any
from collections.abc import Callable

import cle
from cle.backends.externs import KernelObject, ExternObject
from cle.backends.tls.elf_tls import ELFTLSObject

from sortedcontainers import SortedDict

from ...knowledge_plugins.cfg.memory_data import MemoryDataSort, MemoryData
from ..analysis import Analysis

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
        return f"<MemoryRegion {self.addr:#x}-{self.addr+self.size:#x}, type {self.type}>"


#
# An address can be mapped to one of the following types of object
# - Block
# - MemoryData
# - Unknown
#


class Unknown:
    def __init__(self, addr, size, bytes_=None, object_=None, segment=None, section=None):
        self.addr = addr
        self.size = size

        # Optional
        self.bytes = bytes_
        self.object = object_
        self.segment = segment
        self.section = section

        if size == 0:
            raise Exception("You cannot create an unknown region of size 0.")

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
    ):
        """
        :param on_object_added: Callable with parameters (addr, obj) called after an object is added to the blanket.
        """
        self._blanket = SortedDict()

        self._on_object_added_callback = on_object_added
        self._regions = []
        self._exclude_region_types = exclude_region_types if exclude_region_types else set()

        self._init_regions()

        # initialize
        for func in self.kb.functions.values():
            self.add_function(func)
        self._mark_memory_data()
        self._mark_unknowns()

    def _init_regions(self):
        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.MetaELF):
                if obj.sections:
                    if "section" not in self._exclude_region_types:
                        # Enumerate sections in an ELF file
                        for section in obj.sections:
                            if section.occupies_memory:
                                mr = MemoryRegion(section.vaddr, section.memsize, "section", obj, section)
                                self._regions.append(mr)
                elif obj.segments:
                    if "segment" not in self._exclude_region_types:
                        for segment in obj.segments:
                            if segment.memsize > 0:
                                mr = MemoryRegion(segment.vaddr, segment.memsize, "segment", obj, segment)
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
                    size = obj.max_addr - obj.min_addr
                    mr = MemoryRegion(obj.min_addr, size, "extern", obj, None)
                    self._regions.append(mr)
            elif isinstance(obj, ELFTLSObject):
                if "tls" not in self._exclude_region_types:
                    size = obj.max_addr - obj.min_addr
                    mr = MemoryRegion(obj.min_addr, size, "tls", obj, None)
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

    def floor_addr(self, addr):
        try:
            return next(self._blanket.irange(maximum=addr, reverse=True))
        except StopIteration as err:
            raise KeyError(addr) from err

    def floor_item(self, addr):
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

    def ceiling_addr(self, addr):
        try:
            return next(self._blanket.irange(minimum=addr))
        except StopIteration as err:
            raise KeyError(addr) from err

    def ceiling_item(self, addr):
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

    def add_obj(self, addr, obj):
        """
        Adds an object `obj` to the blanket at the specified address `addr`
        """
        self._blanket[addr] = obj
        if self._on_object_added_callback:
            self._on_object_added_callback(addr, obj)

    def add_function(self, func):
        """
        Add a function `func` and all blocks of this function to the blanket.
        """
        for block in func.blocks:
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
            if obj is None or isinstance(obj, cle.ExternObject):
                bytes_ = None
            else:
                try:
                    _l.debug(
                        "Loading bytes from object %s, section %s, segment %s, address %#x.",
                        obj,
                        section,
                        segment,
                        min_addr,
                    )
                    bytes_ = self.project.loader.memory.load(min_addr, size)
                except KeyError:
                    # The address does not exist
                    bytes_ = None
            self.add_obj(
                min_addr, Unknown(min_addr, size, bytes_=bytes_, object_=obj, segment=segment, section=section)
            )

        addr = min_addr
        while addr < max_addr:
            last_addr, last_item = self.floor_item(addr)
            if last_addr < min_addr:
                # impossible
                raise Exception("Impossible")

            # Make sure everything has a non-zero size
            last_item_size = 1 if last_item.size == 0 or last_item.size is None else last_item.size
            end_addr = last_addr + last_item_size
            if end_addr < max_addr:
                try:
                    next_addr = self.ceiling_addr(end_addr)
                except KeyError:
                    next_addr = max_addr
                if next_addr > end_addr:
                    # there is a gap
                    size = next_addr - end_addr
                    if obj is None or isinstance(obj, cle.ExternObject):
                        bytes_ = None
                    else:
                        try:
                            _l.debug(
                                "Loading bytes from object %s, section %s, segment %s, address %#x.",
                                obj,
                                section,
                                segment,
                                end_addr,
                            )
                            bytes_ = self.project.loader.memory.load(end_addr, size)
                        except KeyError:
                            # The address does not exist
                            bytes_ = None
                    self.add_obj(
                        end_addr, Unknown(end_addr, size, bytes_=bytes_, object_=obj, segment=segment, section=section)
                    )
                addr = next_addr
            else:
                addr = max_addr


from angr.analyses import AnalysesHub

AnalysesHub.register_default("CFB", CFBlanket)
AnalysesHub.register_default("CFBlanket", CFBlanket)
