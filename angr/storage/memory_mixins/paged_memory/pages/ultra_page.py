# pylint:disable=arguments-differ
from __future__ import annotations
import logging
from typing import Any
from collections.abc import Iterable

from sortedcontainers import SortedDict

import claripy

from .....errors import SimMemoryError
from . import PageBase
from .cooperation import MemoryObjectMixin, SimMemoryObject


l = logging.getLogger(name=__name__)


class UltraPage(MemoryObjectMixin, PageBase):
    """
    Default page implementation
    """

    SUPPORTS_CONCRETE_LOAD = True

    def __init__(self, memory=None, init_zero=False, **kwargs):
        super().__init__(**kwargs)

        if memory is not None:
            self.concrete_data = bytearray(memory.page_size)
            if init_zero:
                self.symbolic_bitmap = bytearray(memory.page_size)
            else:
                self.symbolic_bitmap = bytearray(b"\1" * memory.page_size)
        else:
            self.concrete_data = None
            self.symbolic_bitmap = None

        self.symbolic_data = SortedDict()

    @classmethod
    def new_from_shared(cls, data, memory=None, **kwargs):
        o = cls(**kwargs)
        o.concrete_data = data
        o.symbolic_bitmap = bytearray(memory.page_size)
        o.refcount = 2  # pylint: disable=attribute-defined-outside-init
        return o

    def copy(self, memo):
        o = super().copy(memo)
        o.concrete_data = bytearray(self.concrete_data)
        o.symbolic_bitmap = bytearray(self.symbolic_bitmap)
        o.symbolic_data = SortedDict(self.symbolic_data)
        return o

    def load(
        self, addr, size=None, page_addr=None, endness=None, memory=None, cooperate=False, **kwargs
    ):  # pylint: disable=arguments-differ
        concrete_run = []
        symbolic_run = ...
        last_run = None
        result = []

        def cycle(end):
            if last_run is symbolic_run and symbolic_run is None:
                fill(end)
            elif last_run is concrete_run:
                new_ast = claripy.BVV(concrete_run, (end - result[-1][0]) * memory.state.arch.byte_width)
                new_obj = SimMemoryObject(new_ast, result[-1][0], endness)
                result[-1] = (result[-1][0], new_obj)

        def fill(end):
            global_end_addr = end
            global_start_addr = result[-1][0]
            size = global_end_addr - global_start_addr
            new_ast = self._default_value(
                global_start_addr,
                size,  # pylint: disable=assignment-from-no-return
                key=(self.category, global_start_addr),
                memory=memory,
                endness=endness,
                **kwargs,
            )
            new_item = SimMemoryObject(new_ast, global_start_addr, endness=endness)
            self.symbolic_data[global_start_addr - page_addr] = new_item
            result[-1] = (global_start_addr, new_item)

        subaddr = addr
        end = addr + size
        while subaddr < end:
            realaddr = subaddr + page_addr
            if self.symbolic_bitmap[subaddr]:
                cur_val = self._get_object(subaddr, page_addr, memory=memory)
                # it must be a different object
                cycle(realaddr)
                next_addr = subaddr + 1

                # figure out how long the current object is (limit end of page)
                if cur_val is None:
                    obj_end = end
                else:
                    obj_end = subaddr + cur_val.length
                    obj_end = min(end, obj_end)

                # determine how many bytes come from this object
                # loop until: end of object or not symbolic or until next object
                next_place = None
                while next_addr < obj_end and self.symbolic_bitmap[next_addr]:
                    if next_addr == subaddr + 1:  # first loop
                        next_place = self._get_next_place(next_addr)
                    if next_place is not None and next_place <= next_addr:
                        break
                    next_addr += 1

                subaddr = next_addr
                last_run = symbolic_run = cur_val
                result.append((realaddr, cur_val))

            else:
                max_concrete_read = subaddr
                while max_concrete_read < end and not self.symbolic_bitmap[max_concrete_read]:
                    max_concrete_read += 1
                cur_val = self.concrete_data[subaddr:max_concrete_read]
                subaddr = max_concrete_read
                # we know the last run was not a concrete one
                cycle(realaddr)
                if endness == "Iend_LE":
                    last_run = concrete_run = cur_val[::-1]
                else:
                    last_run = concrete_run = cur_val
                result.append((realaddr, cur_val))

        cycle(page_addr + addr + size)
        if not cooperate:
            result = self._force_load_cooperation(result, size, endness, page_addr=page_addr, memory=memory, **kwargs)
        return result

    def store(
        self,
        addr,
        data: int | SimMemoryObject,
        size: int | None = None,
        endness=None,
        memory=None,
        page_addr=None,  # pylint: disable=arguments-differ
        cooperate=False,
        **kwargs,
    ):
        super().store(
            addr, data, size=size, endness=endness, memory=memory, cooperate=cooperate, page_addr=page_addr, **kwargs
        )

        if not cooperate:
            data = self._force_store_cooperation(
                addr, data, size, endness, page_addr=page_addr, memory=memory, **kwargs
            )

        size = min(size, memory.page_size - addr)

        byte_width = memory.state.arch.byte_width

        if type(data) is not int and data.object.op == "BVV" and not data.object.annotations:
            # trim the unnecessary leading bytes if there are any
            full_bits = len(data.object)
            start = (page_addr + addr - data.base) & ((1 << memory.state.arch.bits) - 1)
            if start >= data.base + data.length:
                raise SimMemoryError("Not enough bytes to store.")
            start_bits = full_bits - start * byte_width - 1
            # trim the overflowing bytes if there are any
            end_bits = start_bits + 1 - size * byte_width
            if start_bits != full_bits - 1 or end_bits != 0:
                if endness == "Iend_LE":
                    start_bits, end_bits = len(data.object) - end_bits - 1, len(data.object) - start_bits - 1

                concrete_data: bytes = data.concrete_bytes(
                    (full_bits - start_bits - 1) // byte_width, (start_bits - end_bits + 1) // byte_width
                )
                data = int.from_bytes(concrete_data, "big")

        if type(data) is int or (data.object.op == "BVV" and not data.object.annotations):
            # mark range as not symbolic
            self.symbolic_bitmap[addr : addr + size] = b"\0" * size

            # store
            arange = range(addr, addr + size)
            ival = data if type(data) is int else data.object.args[0]
            if endness == "Iend_BE":
                arange = reversed(arange)

            assert memory.state.arch.byte_width == 8
            # TODO: Make UltraPage support architectures with greater byte_widths (but are still multiples of 8)
            for subaddr in arange:
                self.concrete_data[subaddr] = ival & 0xFF
                ival >>= 8
        else:
            # mark range as symbolic
            self.symbolic_bitmap[addr : addr + size] = b"\1" * size

            # set ending object
            try:
                endpiece = next(self.symbolic_data.irange(maximum=addr + size, reverse=True))
            except StopIteration:
                pass
            else:
                if endpiece != addr + size:
                    self.symbolic_data[addr + size] = self.symbolic_data[endpiece]

            # clear range
            for midpiece in self.symbolic_data.irange(maximum=addr + size - 1, minimum=addr, reverse=True):
                del self.symbolic_data[midpiece]

            # set.
            self.symbolic_data[addr] = data

    def merge(
        self,
        others: list[UltraPage],
        merge_conditions,
        common_ancestor=None,
        page_addr: int | None = None,  # pylint: disable=arguments-differ
        memory=None,
        changed_offsets: set[int] | None = None,
    ):
        all_pages = [self, *others]
        merged_to = None
        merged_objects = set()
        merged_offsets = set()

        if changed_offsets is None:
            changed_offsets = set()
            for other in others:
                changed_offsets |= self.changed_bytes(other, page_addr)

        for b in sorted(changed_offsets):
            if merged_to is not None and not b >= merged_to:
                l.info("merged_to = %d ... already merged byte 0x%x", merged_to, b)
                continue
            l.debug("... on byte 0x%x", b)

            memory_objects: list[tuple[SimMemoryObject, Any]] = []
            concretes: list[tuple[int, Any]] = []
            unconstrained_in: list[tuple[UltraPage, Any]] = []
            our_mo: SimMemoryObject | None = None

            # first get a list of all memory objects at that location, and
            # all memories that don't have those bytes
            for pg, fv in zip(all_pages, merge_conditions):
                if pg.symbolic_bitmap[b]:
                    mo = pg._get_object(b, page_addr)
                    if mo is not None:
                        l.info("... MO present in %s", fv)
                        memory_objects.append((mo, fv))
                        if pg is self:
                            our_mo = mo
                    else:
                        l.info("... not present in %s", fv)
                        unconstrained_in.append((pg, fv))
                else:
                    # concrete data
                    concretes.append((pg.concrete_data[b], fv))

            # fast path: no memory objects, no unconstrained positions, and only one concrete value
            if not memory_objects and not unconstrained_in and len({cv for cv, _ in concretes}) == 1:
                cv = concretes[0][0]
                self.store(b, cv, size=1, cooperate=True, page_addr=page_addr, memory=memory)
                continue

            # convert all concrete values into memory objects
            for cv, fv in concretes:
                mo = SimMemoryObject(claripy.BVV(cv, size=8), page_addr + b, "Iend_LE")
                memory_objects.append((mo, fv))

            mos = {mo for mo, _ in memory_objects}
            mo_bases = {mo.base for mo, _ in memory_objects}
            mo_lengths = {mo.length for mo, _ in memory_objects}

            if not unconstrained_in and not mos - merged_objects:
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and not unconstrained_in:
                to_merge = [(mo.object, fv) for mo, fv in memory_objects]

                # Update `merged_to`
                merged_to = b + next(iter(mo_lengths))

                merged_val = self._merge_values(to_merge, memory_objects[0][0].length, memory=memory)
                if merged_val is None:
                    continue

                if our_mo is None:
                    # this object does not exist in the current page. do the store
                    new_object = SimMemoryObject(merged_val, page_addr + b, memory_objects[0][0].endness)
                    self.store(
                        b, new_object, size=next(iter(mo_lengths)), cooperate=True, page_addr=page_addr, memory=memory
                    )
                    merged_objects.add(new_object)
                else:
                    # do the replacement
                    new_object = self._replace_memory_object(our_mo, merged_val, memory=memory)
                    merged_objects.add(new_object)

                merged_objects.update(mos)
                merged_offsets.add(b)

            else:
                # get the size that we can merge easily. This is the minimum of
                # the size of all memory objects and unallocated spaces.
                min_size = min(mo.length - (page_addr + b - mo.base) for mo, _ in memory_objects)
                for um, _ in unconstrained_in:
                    for i in range(min_size):
                        if um._contains(b + i, page_addr):
                            min_size = i
                            break
                merged_to = b + min_size
                l.info("... determined minimum size of %d", min_size)

                # Now, we have the minimum size. We'll extract/create expressions of that
                # size and merge them
                extracted = (
                    [(mo.bytes_at(page_addr + b, min_size), fv) for mo, fv in memory_objects] if min_size != 0 else []
                )
                created = [
                    (self._default_value(None, min_size, name=f"merge_uc_{uc.id}_{b:x}", memory=memory), fv)
                    for uc, fv in unconstrained_in
                ]
                to_merge = extracted + created

                merged_val = self._merge_values(to_merge, min_size, memory=memory)
                if merged_val is None:
                    continue

                self.store(
                    b,
                    merged_val,
                    size=len(merged_val) // memory.state.arch.byte_width,
                    inspect=False,
                    page_addr=page_addr,
                    memory=memory,
                )  # do not convert endianness again

                merged_offsets.add(b)

        return merged_offsets

    def concrete_load(self, addr, size, **kwargs):  # pylint: disable=arguments-differ
        if type(self.concrete_data) is bytearray:
            return (
                memoryview(self.concrete_data)[addr : addr + size],
                memoryview(self.symbolic_bitmap)[addr : addr + size],
            )
        return self.concrete_data[addr : addr + size], memoryview(self.symbolic_bitmap)[addr : addr + size]

    def changed_bytes(self, other, page_addr=None) -> set[int]:
        changed_candidates = super().changed_bytes(other)
        if changed_candidates is None:
            changed_candidates = range(len(self.symbolic_bitmap))

        changes: set[int] = set()

        for addr in changed_candidates:
            if self.symbolic_bitmap[addr] != other.symbolic_bitmap[addr]:
                changes.add(addr)
            elif self.symbolic_bitmap[addr] == 0:
                if self.concrete_data[addr] != other.concrete_data[addr]:
                    changes.add(addr)
            else:
                try:
                    aself = next(self.symbolic_data.irange(maximum=addr, reverse=True))
                except StopIteration:
                    aself = None
                try:
                    aother = next(other.symbolic_data.irange(maximum=addr, reverse=True))
                except StopIteration:
                    aother = None

                if aself is None and aother is None:
                    pass
                elif aself is None and aother is not None:
                    oobj = other.symbolic_data[aother]
                    if oobj.includes(addr + page_addr):
                        changes.add(addr)
                elif aother is None and aself is not None:
                    aobj = self.symbolic_data[aself]
                    if aobj.includes(addr + page_addr):
                        changes.add(addr)
                else:
                    real_addr = page_addr + addr
                    aobj = self.symbolic_data[aself]
                    oobj = other.symbolic_data[aother]

                    acont = aobj.includes(real_addr)
                    ocont = oobj.includes(real_addr)
                    if acont != ocont:
                        changes.add(addr)
                    elif acont is False:
                        pass
                    else:
                        abyte = aobj.bytes_at(real_addr, 1)
                        obyte = oobj.bytes_at(real_addr, 1)
                        if abyte is not obyte:
                            changes.add(addr)

        return changes

    def _contains(self, start: int, page_addr: int):
        if not self.symbolic_bitmap[start]:
            # concrete data
            return True
        # symbolic data or does not exist
        return self._get_object(start, page_addr) is not None

    def _get_object(self, start: int, page_addr: int, memory=None) -> SimMemoryObject | None:
        try:
            place = next(self.symbolic_data.irange(maximum=start, reverse=True))
        except StopIteration:
            return None
        else:
            obj = self.symbolic_data[place]
            if (
                obj.includes(start + page_addr)
                or memory is not None
                and obj.includes(start + page_addr + (1 << memory.state.arch.bits))
            ):
                return obj
            return None

    def _get_next_place(self, start):
        try:
            place = next(self.symbolic_data.irange(minimum=start, reverse=False))
        except StopIteration:
            return None
        else:
            return place

    def replace_all_with_offsets(self, offsets: Iterable[int], old: claripy.ast.BV, new: claripy.ast.BV, memory=None):
        memory_objects = set()
        for offset in sorted(offsets):
            try:
                a = next(self.symbolic_data.irange(maximum=offset, reverse=True))
            except StopIteration:
                a = None

            if a is None:
                continue
            aobj = self.symbolic_data[a]
            memory_objects.add(aobj)

        replaced_objects_cache = {}
        for mo in memory_objects:
            replaced_object = None

            if mo.object in replaced_objects_cache:
                if mo.object is not replaced_objects_cache[mo.object]:
                    replaced_object = replaced_objects_cache[mo.object]

            else:
                replaced_object = mo.object.replace(old, new)
                replaced_objects_cache[mo.object] = replaced_object
                if mo.object is replaced_object:
                    # The replace does not really occur
                    replaced_object = None

            if replaced_object is not None:
                self._replace_memory_object(mo, replaced_object, memory=memory)

    def _replace_memory_object(self, old: SimMemoryObject, new_content: claripy.Bits, memory=None):
        """
        Replaces the memory object `old` with a new memory object containing `new_content`.

        :param old:         A SimMemoryObject (i.e., one from :func:`memory_objects_for_hash()` or :func:`
                            memory_objects_for_name()`).
        :param new_content: The content (claripy expression) for the new memory object.
        :returns: the new memory object
        """

        if (
            old.object.size() if not old.is_bytes else len(old.object) * self.state.arch.byte_width
        ) != new_content.size():
            raise SimMemoryError("memory objects can only be replaced by the same length content")

        new = SimMemoryObject(new_content, old.base, old.endness, byte_width=old._byte_width)
        for k in list(self.symbolic_data):
            if self.symbolic_data[k] is old:
                self.symbolic_data[k] = new

        if isinstance(new.object, claripy.ast.BV):  # pylint:disable=isinstance-second-argument-not-valid-type
            for b in range(old.base, old.base + old.length):
                self._update_mappings(b, old.object, new.object, memory=memory)

        return new
