# pylint:disable=abstract-method
import logging
from typing import Optional, List, Set, Tuple

from . import PageBase
from angr.storage.memory_object import SimMemoryObject
from .cooperation import MemoryObjectMixin


l = logging.getLogger(name=__name__)


class ListPage(MemoryObjectMixin, PageBase):
    def __init__(self, memory=None, content=None, sinkhole=None, mo_cmp=None, **kwargs):
        super().__init__(**kwargs)

        self.content: List[Optional[SimMemoryObject]] = content
        self.stored_offset = set()
        if content is None:
            if memory is not None:
                self.content: List[Optional[SimMemoryObject]] = [None] * memory.page_size  # TODO: this isn't the best
        self._mo_cmp = mo_cmp

        self.sinkhole: Optional[SimMemoryObject] = sinkhole

    def copy(self, memo):
        o = super().copy(memo)
        o.content = list(self.content)
        o.stored_offset = self.stored_offset.copy()
        o.sinkhole = self.sinkhole
        o._mo_cmp = self._mo_cmp
        return o

    def load(self, addr, size=None, endness=None, page_addr=None, memory=None, cooperate=False, **kwargs):
        result = []
        last_seen = ...  # ;)

        # loop over the loading range. accumulate a result for each byte, but collapse results from adjacent bytes
        # using the same memory object
        for subaddr in range(addr, addr+size):
            item = self.content[subaddr]
            if item is None:
                item = self.sinkhole
            if item is not last_seen:
                if last_seen is None:
                    self._fill(result, subaddr, page_addr, endness, memory, **kwargs)
                result.append((subaddr + page_addr, item))
                last_seen = item

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
        new_ast = self._default_value(global_start_addr, size, name='%s_%x' % (memory.id, global_start_addr),
                                      key=(self.category, global_start_addr), memory=memory, **kwargs)
        new_item = SimMemoryObject(new_ast, global_start_addr, endness=endness,
                                   byte_width=memory.state.arch.byte_width if memory is not None else 8)
        subaddr_start = global_start_addr - page_addr
        for subaddr in range(subaddr_start, addr):
            self.content[subaddr] = new_item
            self.stored_offset.add(subaddr)
        result[-1] = (global_start_addr, new_item)

    def store(self, addr, data, size=None, endness=None, memory=None, cooperate=False, **kwargs):
        if not cooperate:
            data = self._force_store_cooperation(addr, data, size, endness, memory=memory, **kwargs)

        if size == len(self.content) and addr == 0:
            self.sinkhole = data
            self.content = [None]*len(self.content)
        else:
            max_addr = min(addr + size, len(self.content))
            for subaddr in range(addr, max_addr):
                self.content[subaddr] = data
                self.stored_offset.add(subaddr)

    def merge(self, others: List['ListPage'], merge_conditions, common_ancestor=None, page_addr: int=None,
              memory=None, changed_offsets: Optional[Set[int]]=None):

        if changed_offsets is None:
            changed_offsets = set()
            for other in others:
                changed_offsets |= self.changed_bytes(other, page_addr)

        all_pages: List['ListPage'] = [self] + others
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

            memory_objects = []
            unconstrained_in = []

            # first get a list of all memory objects at that location, and
            # all memories that don't have those bytes
            for sm, fv in zip(all_pages, merge_conditions):
                if sm._contains(b, page_addr):
                    l.info("... present in %s", fv)
                    memory_objects.append((sm.content[b], fv))
                else:
                    l.info("... not present in %s", fv)
                    unconstrained_in.append((sm, fv))

            mos = set(mo for mo, _ in memory_objects)
            mo_bases = set(mo.base for mo, _ in memory_objects)
            mo_lengths = set(mo.length for mo, _ in memory_objects)
            endnesses = set(mo.endness for mo in mos)

            if not unconstrained_in and not (mos - merged_objects):
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and not unconstrained_in and len(endnesses) == 1:
                the_endness = next(iter(endnesses))
                to_merge = [(mo.object, fv) for mo, fv in memory_objects]

                # Update `merged_to`
                mo_base = list(mo_bases)[0]
                mo_length = memory_objects[0][0].length
                size = mo_length - (page_addr + b - mo_base)
                merged_to = b + size

                merged_val = self._merge_values(to_merge, mo_length, memory=memory)
                if merged_val is None:
                    # merge_values() determines that we should not attempt to merge this value
                    continue

                # do the replacement
                # TODO: Implement in-place replacement instead of calling store()
                # new_object = self._replace_memory_object(our_mo, merged_val, page_addr, memory.page_size)

                self.store(b,
                           SimMemoryObject(merged_val, mo_base, endness=the_endness),
                           size=size,
                           cooperate=True
                           )
                # merged_objects.add(new_object)
                # merged_objects.update(mos)
                merged_offsets.add(b)

            else:
                # get the size that we can merge easily. This is the minimum of
                # the size of all memory objects and unallocated spaces.
                min_size = min([mo.length - (b + page_addr - mo.base) for mo, _ in memory_objects])
                for um, _ in unconstrained_in:
                    for i in range(0, min_size):
                        if um._contains(b + i, page_addr):
                            min_size = i
                            break
                merged_to = b + min_size
                l.info("... determined minimum size of %d", min_size)

                # Now, we have the minimum size. We'll extract/create expressions of that
                # size and merge them
                extracted = [(mo.bytes_at(page_addr+b, min_size), fv) for mo, fv in memory_objects] \
                    if min_size != 0 else []
                created = [
                    (self._default_value(None, min_size, name="merge_uc_%s_%x" % (uc.id, b), memory=memory),
                     fv) for
                    uc, fv in unconstrained_in
                ]
                to_merge = extracted + created

                merged_val = self._merge_values(to_merge, min_size, memory=memory)
                if merged_val is None:
                    continue

                self.store(b,
                           SimMemoryObject(merged_val, page_addr+b, endness='Iend_BE'),
                           size=min_size,
                           endness='Iend_BE', cooperate=True
                           )  # do not convert endianness again
                merged_offsets.add(b)

        self.stored_offset |= merged_offsets
        return merged_offsets

    def changed_bytes(self, other: 'ListPage', page_addr: int=None):

        candidates: Set[int] = set()
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
        differences: Set[int] = set()
        for c in candidates:
            s_contains = self._contains(c, page_addr)
            o_contains = other._contains(c, page_addr)
            if not s_contains and o_contains:
                differences.add(c)
            elif s_contains and not o_contains:
                differences.add(c)
            else:
                if self.content[c] is None:
                    self.content[c] = SimMemoryObject(self.sinkhole.bytes_at(page_addr+c, 1), page_addr + c,
                                                      byte_width=byte_width, endness='Iend_BE')
                if other.content[c] is None:
                    other.content[c] = SimMemoryObject(other.sinkhole.bytes_at(page_addr+c, 1), page_addr + c,
                                                       byte_width=byte_width, endness='Iend_BE')
                if s_contains and self.content[c] != other.content[c]:
                    same = None
                    if self._mo_cmp is not None:
                        same = self._mo_cmp(self.content[c], other.content[c], page_addr + c, 1)
                    if same is None:
                        # Try to see if the bytes are equal
                        self_byte = self.content[c].bytes_at(page_addr + c, 1)
                        other_byte = other.content[c].bytes_at(page_addr + c, 1)
                        same = self_byte is other_byte

                    if same is False:
                        differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    def _contains(self, off: int, page_addr: int):
        if off >= len(self.content):
            return False
        if self.content[off] is not None:
            return True
        if self.sinkhole is None:
            return False
        return self.sinkhole.includes(page_addr + off)

    def _replace_mo(self, old_mo: SimMemoryObject, new_mo: SimMemoryObject, page_addr: int,
                    page_size: int) -> SimMemoryObject:
        if self.sinkhole is old_mo:
            self.sinkhole = new_mo
        else:
            start, end = self._resolve_range(old_mo, page_addr, page_size)
            for i in range(start, end):
                if self.content[i-page_addr] is old_mo:
                    self.content[i-page_addr] = new_mo
        return new_mo

    @staticmethod
    def _resolve_range(mo: SimMemoryObject, page_addr: int, page_size) -> Tuple[int,int]:
        start = max(mo.base, page_addr)
        end = min(mo.last_addr + 1, page_addr + page_size)
        if end <= start:
            l.warning("Nothing left of the memory object to store in SimPage.")
        return start, end

    def _get_object(self, start: int, page_addr: int) -> Optional[SimMemoryObject]:
        mo = self.content[start]
        if mo is None:
            return None
        if mo.includes(start + page_addr):
            return mo
        return None
