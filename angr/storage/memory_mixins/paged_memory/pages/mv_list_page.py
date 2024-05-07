# pylint:disable=abstract-method,arguments-differ,assignment-from-no-return
import logging
from typing import Union, Any
from collections.abc import Callable

from angr.utils.dynamic_dictlist import DynamicDictList
from .....storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from . import PageBase
from .cooperation import MemoryObjectSetMixin


l = logging.getLogger(name=__name__)

_MOTYPE = Union[SimMemoryObject, SimLabeledMemoryObject]


class MVListPage(
    MemoryObjectSetMixin,
    PageBase,
):
    """
    MVListPage allows storing multiple values at the same location, thus allowing weak updates.

    Each store() may take a value or multiple values, and a "weak" parameter to specify if this store is a weak update
    or not.
    Each load() returns an iterator of all values stored at that location.
    """

    def __init__(self, memory=None, content=None, sinkhole=None, mo_cmp=None, **kwargs):
        super().__init__(**kwargs)

        self.content: DynamicDictList[_MOTYPE | set[_MOTYPE] | None] = (
            DynamicDictList(max_size=memory.page_size, content=content) if content is not None else None
        )
        self.stored_offset = set()
        self._mo_cmp: Callable | None = mo_cmp

        if self.content is None:
            if memory is not None:
                self.content: DynamicDictList[_MOTYPE | set[_MOTYPE] | None] = DynamicDictList(
                    max_size=memory.page_size
                )

        self.sinkhole: _MOTYPE | None = sinkhole

    def copy(self, memo) -> "MVListPage":
        o = super().copy(memo)
        o.content = DynamicDictList(max_size=self.content.max_size, content=self.content)
        o.sinkhole = self.sinkhole
        o.stored_offset = self.stored_offset.copy()
        o._mo_cmp = self._mo_cmp
        return o

    def load(
        self, addr, size=None, endness=None, page_addr=None, memory=None, cooperate=False, **kwargs
    ) -> list[tuple[int, _MOTYPE]]:
        result = []
        last_seen = ...  # ;)

        # loop over the loading range. accumulate a result for each byte, but collapse results from adjacent bytes
        # using the same memory object
        for subaddr in range(addr, addr + size):
            items = self.content[subaddr]
            if items is None:
                items = {self.sinkhole} if self.sinkhole is not None else None
            if items != last_seen:
                if last_seen is None:
                    self._fill(result, subaddr, page_addr, endness, memory, **kwargs)
                result.append((subaddr + page_addr, items))
                last_seen = items

        if last_seen is None:
            self._fill(result, addr + size, page_addr, endness, memory, **kwargs)

        if not cooperate:
            result = self._force_load_cooperation(result, size, endness, memory=memory, **kwargs)
        return result

    def _fill(self, result, addr, page_addr, endness, memory, **kwargs):
        """
        Small utility function for behavior which is duplicated in load

        mutates result to generate a new memory object and replace the last entry in it, which is None. Then, it will
        insert the new memory object into self.content.
        """
        global_end_addr = addr + page_addr
        global_start_addr = result[-1][0]
        size = global_end_addr - global_start_addr
        new_ast = self._default_value(
            global_start_addr,
            size,
            name=f"{memory.id}_{global_start_addr:x}",
            key=(self.category, global_start_addr),
            memory=memory,
            **kwargs,
        )
        new_item = SimMemoryObject(
            new_ast,
            global_start_addr,
            endness=endness,
            byte_width=memory.state.arch.byte_width if memory is not None else 8,
        )
        subaddr_start = global_start_addr - page_addr
        for subaddr in range(subaddr_start, addr):
            self.content[subaddr] = {new_item}
            self.stored_offset.add(subaddr)
        result[-1] = (global_start_addr, new_item)

    def store(self, addr, data, size=None, endness=None, memory=None, cooperate=False, weak=False, **kwargs):
        super().store(addr, data, size=size, endness=endness, memory=memory, cooperate=cooperate, weak=weak, **kwargs)

        if not cooperate:
            data = self._force_store_cooperation(addr, data, size, endness, memory=memory, **kwargs)

        data: set[_MOTYPE]

        if size == len(self.content) and addr == 0 and len(data) == 1:
            self.sinkhole = next(iter(data))
            self.content = DynamicDictList(max_size=len(self.content))
            self.stored_offset = set()
        else:
            if not weak:
                if len(data) == 1:
                    # unpack
                    data: _MOTYPE = next(iter(data))
                for subaddr in range(addr, addr + size):
                    self.content[subaddr] = data
                    self.stored_offset.add(subaddr)
            else:
                for subaddr in range(addr, addr + size):
                    if self.content[subaddr] is None:
                        self.content[subaddr] = data
                    elif type(self.content[subaddr]) is set:
                        self.content[subaddr] |= data
                    else:
                        self.content[subaddr] = {self.content[subaddr]} | data
                    self.stored_offset.add(subaddr)

    def erase(self, addr, size=None, **kwargs) -> None:
        for off in range(size):
            self.content[addr + off] = None

    def merge(
        self,
        others: list["MVListPage"],
        merge_conditions,
        common_ancestor=None,
        page_addr: int = None,
        memory=None,
        changed_offsets: set[int] | None = None,
    ):
        if changed_offsets is None:
            changed_offsets = set()
            for other in others:
                changed_offsets |= self.changed_bytes(other, page_addr)

        all_pages: list["MVListPage"] = [self] + others
        if merge_conditions is None:
            merge_conditions = [None] * len(all_pages)

        merged_to = None
        merged_objects = set()
        merged_offsets = set()
        for b in sorted(changed_offsets):
            if merged_to is not None and not b >= merged_to:
                l.info("merged_to = %d ... already merged byte 0x%x", merged_to, b)
                continue
            l.debug("... on byte 0x%x", b)

            memory_object_sets: set[tuple[frozenset[SimMemoryObject], Any]] = set()
            unconstrained_in = []

            # first get a list of all memory objects at that location, and all memories that don't have those bytes
            self_has_memory_object_set = False
            for sm, fv in zip(all_pages, merge_conditions):
                if sm._contains(b, page_addr):
                    l.info("... present in %s", fv)
                    memory_objects = set()
                    for mo in sm.content_gen(b):
                        if mo.includes(page_addr + b):
                            memory_objects.add(mo)
                    memory_object_sets.add((frozenset(memory_objects), fv))
                    if sm is self:
                        self_has_memory_object_set = True
                else:
                    l.info("... not present in %s", fv)
                    unconstrained_in.append((sm, fv))

            if not memory_object_sets:
                continue
            if self_has_memory_object_set and len(memory_object_sets) == 1:
                continue

            mo_sets = {mo_set for mo_set, _ in memory_object_sets}
            mo_bases = set()
            mo_lengths = set()
            endnesses = set()
            for mo_set in mo_sets:
                for mo in mo_set:
                    mo_bases.add(mo.base)
                    mo_lengths.add(mo.length)
                    endnesses.add(mo.endness)

            if not unconstrained_in and not (mo_sets - merged_objects):  # pylint:disable=superfluous-parens
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and not unconstrained_in and len(endnesses) == 1:
                if len(memory_object_sets) == 1:
                    # nothing to merge!
                    continue

                the_endness = next(iter(endnesses))
                to_merge = []
                for mo_set, fv in memory_object_sets:
                    for mo in mo_set:
                        to_merge.append((mo.object, fv))

                # Update `merged_to`
                mo_base = list(mo_bases)[0]
                mo_length = next(iter(mo_lengths))
                size = min(mo_length - (page_addr + b - mo_base), len(self.content) - b)
                merged_to = b + size

                merged_val = self._merge_values(to_merge, mo_length, memory=memory)
                if merged_val is None:
                    # merge_values() determines that we should not attempt to merge this value
                    continue

                # do the replacement
                # TODO: Implement in-place replacement instead of calling store()
                # new_object = self._replace_memory_object(our_mo, merged_val, page_addr, memory.page_size)

                new_mos = {SimMemoryObject(v, mo_base, endness=the_endness) for v in merged_val}
                self.store(b, new_mos, size=size, cooperate=True, weak=False)

                merged_offsets.add(b)

            else:
                # get the size that we can merge easily. This is the minimum of the size of all memory objects and
                # unallocated spaces.
                min_size = len(self.content) - b
                mask = (1 << memory.state.arch.bits) - 1
                for mo_set in mo_sets:
                    for mo in mo_set:
                        min_size = min(min_size, mo.length - ((b + page_addr - mo.base) & mask))
                for um, _ in unconstrained_in:
                    for i in range(0, min_size):
                        if um._contains(b + i, page_addr):
                            min_size = i
                            break
                merged_to = b + min_size
                l.info("... determined minimum size of %d", min_size)

                # Now, we have the minimum size. We'll extract/create expressions of that
                # size and merge them
                extracted = []
                if min_size != 0:
                    for mo_set, fv in memory_object_sets:
                        for mo in mo_set:
                            extracted.append((mo.bytes_at(page_addr + b, min_size), fv))
                if not memory.skip_missing_values_during_merging:
                    created = [
                        (self._default_value(None, min_size, name=f"merge_uc_{uc.id}_{b:x}", memory=memory), fv)
                        for uc, fv in unconstrained_in
                    ]
                    to_merge = extracted + created
                else:
                    to_merge = extracted

                merged_val = self._merge_values(to_merge, min_size, memory=memory)
                if merged_val is None:
                    continue

                new_mos = {SimMemoryObject(v, page_addr + b, endness="Iend_BE") for v in merged_val}
                self.store(b, new_mos, size=min_size, cooperate=True, weak=False)
                merged_offsets.add(b)

        self.stored_offset |= merged_offsets
        return merged_offsets

    def compare(
        self, other: "MVListPage", page_addr: int = None, memory=None, changed_offsets=None
    ) -> bool:  # pylint: disable=unused-argument
        compared_to = None
        for b in sorted(changed_offsets):
            if compared_to is not None and not b >= compared_to:
                continue

            unconstrained_in = []
            self_has_memory_object_set = False
            memory_object_sets: set[frozenset[SimMemoryObject]] = set()
            for sm in [self, other]:
                if sm._contains(b, page_addr):
                    memory_objects = set()
                    for mo in sm.content_gen(b):
                        if mo.includes(page_addr + b):
                            memory_objects.add(mo)
                    memory_object_sets.add(frozenset(memory_objects))
                    if sm is self:
                        self_has_memory_object_set = True
                else:
                    unconstrained_in.append(sm)

            if not memory_object_sets:
                continue
            if self_has_memory_object_set and len(memory_object_sets) == 1:
                continue

            # TODO: compare_values even more?
            return False

        return True

    def changed_bytes(self, other: "MVListPage", page_addr: int = None):
        candidates: set[int] = super().changed_bytes(other)
        if candidates is not None:
            # using the result from the history tracking mixin as an approximation
            return candidates

        # slower path
        if candidates is None:
            candidates: set[int] = set()
            # resort to the slower solution
            if self.sinkhole is None:
                candidates |= self.stored_offset
            else:
                for i in range(len(self.content)):
                    if self._contains(i, page_addr):
                        candidates.add(i)

            if other.sinkhole is None:
                candidates |= other.stored_offset
            else:
                for i in range(len(other.content)):
                    if other._contains(i, page_addr):
                        candidates.add(i)

        byte_width = 8  # TODO: Introduce self.state if we want to use self.state.arch.byte_width
        differences: set[int] = set()
        for c in candidates:
            s_contains = self._contains(c, page_addr)
            o_contains = other._contains(c, page_addr)
            if not s_contains and o_contains:
                differences.add(c)
            elif s_contains and not o_contains:
                differences.add(c)
            else:
                if self.content[c] is None:
                    if self.sinkhole is not None:
                        self.content[c] = SimMemoryObject(
                            self.sinkhole.bytes_at(page_addr + c, 1),
                            page_addr + c,
                            byte_width=byte_width,
                            endness="Iend_BE",
                        )
                if other.content[c] is None:
                    if other.sinkhole is not None:
                        other.content[c] = SimMemoryObject(
                            other.sinkhole.bytes_at(page_addr + c, 1),
                            page_addr + c,
                            byte_width=byte_width,
                            endness="Iend_BE",
                        )
                if s_contains and self.content[c] != other.content[c]:
                    same = None
                    if self._mo_cmp is not None:
                        same = self._mo_cmp(self.content[c], other.content[c], page_addr + c, 1)
                    if same is None:
                        # Try to see if the bytes are equal
                        self_bytes = {mo.bytes_at(page_addr + c, 1) for mo in self.content_gen(c)}
                        other_bytes = {mo.bytes_at(page_addr + c, 1) for mo in other.content_gen(c)}
                        same = self_bytes == other_bytes

                    if same is False:
                        differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    def content_gen(self, index):
        if self.content[index] is None:
            return
        elif type(self.content[index]) is set:
            yield from self.content[index]
        else:
            yield self.content[index]

    def _contains(self, off: int, page_addr: int):
        if off >= len(self.content):
            return False
        if self.content[off] is not None:
            return True
        if self.sinkhole is None:
            return False
        return self.sinkhole.includes(page_addr + off)

    def _replace_mo(
        self, old_mo: SimMemoryObject, new_mo: SimMemoryObject, page_addr: int, page_size: int
    ) -> SimMemoryObject:
        if self.sinkhole is old_mo:
            self.sinkhole = new_mo
        else:
            start, end = self._resolve_range(old_mo, page_addr, page_size)
            for i in range(start, end):
                s = {new_mo}
                if self.content[i - page_addr] is old_mo:
                    self.content[i - page_addr] = s
        return new_mo

    @staticmethod
    def _resolve_range(mo: SimMemoryObject, page_addr: int, page_size) -> tuple[int, int]:
        start = max(mo.base, page_addr)
        end = min(mo.last_addr + 1, page_addr + page_size)
        if end <= start:
            l.warning("Nothing left of the memory object to store in SimPage.")
        return start, end

    def _get_objects(self, start: int, page_addr: int) -> list[SimMemoryObject] | None:
        mos = self.content[start]
        if mos is None:
            return None
        lst = []
        if type(mos) is set:
            for mo in mos:
                if mo.includes(start + page_addr):
                    lst.append(mo)
        else:
            lst.append(mos)
        if lst:
            return lst
        return None
