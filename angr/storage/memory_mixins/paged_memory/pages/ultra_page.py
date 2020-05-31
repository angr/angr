from sortedcontainers import SortedDict
from typing import List, Set, Optional, Tuple, Union, Any
import logging

import claripy

from .....errors import SimMemoryError
from . import PageBase
from .cooperation import MemoryObjectMixin, SimMemoryObject


l = logging.getLogger(name=__name__)


class UltraPage(MemoryObjectMixin, PageBase):
    def __init__(self, memory=None, init_zero=False, **kwargs):
        super().__init__(**kwargs)

        if memory is not None:
            self.concrete_data = bytearray(memory.page_size)
            if init_zero:
                self.symbolic_bitmap = bytearray(memory.page_size)
            else:
                self.symbolic_bitmap = bytearray(b'\1'*memory.page_size)
        else:
            self.concrete_data = None
            self.symbolic_bitmap = None

        self.symbolic_data = SortedDict()

    @classmethod
    def new_from_shared(cls, data, memory=None, **kwargs):
        o = cls(**kwargs)
        o.concrete_data = data
        o.symbolic_bitmap = bytearray(memory.page_size)
        o.refcount = 2
        return o

    def copy(self, memo):
        o = super().copy(memo)
        o.concrete_data = bytearray(self.concrete_data)
        o.symbolic_bitmap = bytearray(self.symbolic_bitmap)
        o.symbolic_data = SortedDict(self.symbolic_data)
        return o

    def load(self, addr, size=None, page_addr=None, endness=None, memory=None, cooperate=False, **kwargs):
        concrete_run = []
        symbolic_run = ...
        last_run = None
        result = []

        def cycle(end):
            if last_run is symbolic_run and symbolic_run is None:
                fill(end)
            elif last_run is concrete_run:
                new_ast = claripy.BVV(concrete_run, (end - result[-1][0]) * 8)
                new_obj = SimMemoryObject(new_ast, result[-1][0], endness)
                result[-1] = (result[-1][0], new_obj)

        def fill(end):
            global_end_addr = end
            global_start_addr = result[-1][0]
            size = global_end_addr - global_start_addr
            new_ast = self._default_value(global_start_addr, size, name='%s_%x' % (memory.id, global_start_addr), key=(self.category, global_start_addr), memory=memory, **kwargs)
            new_item = SimMemoryObject(new_ast, global_start_addr, endness=endness)
            self.symbolic_data[global_start_addr - page_addr] = new_item
            result[-1] = (global_start_addr, new_item)

        for subaddr in range(addr, addr+size):
            realaddr = subaddr + page_addr
            if self.symbolic_bitmap[subaddr]:
                cur_val = self._get_object(subaddr, page_addr)
                if cur_val is last_run and last_run is symbolic_run:
                    pass
                else:
                    cycle(realaddr)
                    last_run = symbolic_run = cur_val
                    result.append((realaddr, cur_val))
            else:
                cur_val = self.concrete_data[subaddr]
                if last_run is concrete_run:
                    if endness == 'Iend_LE':
                        last_run = concrete_run = concrete_run | (cur_val << (8 * (realaddr - result[-1][0])))
                    else:
                        last_run = concrete_run = (concrete_run << 8) | cur_val
                    result[-1] = (result[-1][0], concrete_run)
                else:
                    cycle(realaddr)
                    last_run = concrete_run = cur_val
                    result.append((realaddr, cur_val))

        cycle(page_addr + addr + size)
        if not cooperate:
            result = self._force_load_cooperation(result, size, endness, memory=memory, **kwargs)
        return result

    def store(self, addr, data: Union[int,SimMemoryObject], size=None, endness=None, memory=None, page_addr=None,
              cooperate=False, **kwargs):
        if not cooperate:
            data = self._force_store_cooperation(addr, data, size, endness, memory=memory, **kwargs)

        if type(data) is int or data.object.op == 'BVV':
            # mark range as not symbolic
            self.symbolic_bitmap[addr:addr+size] = b'\0'*size

            # store
            arange = range(addr, addr+size)
            ival = data.object.args[0]
            if endness == 'Iend_BE':
                arange = reversed(arange)

            for subaddr in arange:
                self.concrete_data[subaddr] = ival & 0xff
                ival >>= 8
        else:
            # mark range as symbolic
            self.symbolic_bitmap[addr:addr+size] = b'\1'*size

            # set ending object
            try:
                endpiece = next(self.symbolic_data.irange(maximum=addr+size, reverse=True))
            except StopIteration:
                pass
            else:
                if endpiece != addr + size:
                    self.symbolic_data[addr + size] = self.symbolic_data[endpiece]

            # clear range
            for midpiece in self.symbolic_data.irange(maximum=addr+size-1, minimum=addr, reverse=True):
                del self.symbolic_data[midpiece]

            # set.
            self.symbolic_data[addr] = data

    def merge(self, others: List['UltraPage'], merge_conditions, common_ancestor=None, page_addr: int=None,
              memory=None):

        all_pages = [self] + others
        merged_to = None
        merged_objects = set()
        merged_bytes = set()

        changed_bytes: Set[int] = set()
        for o in others:
            changed_bytes |= self.changed_bytes(o, page_addr=page_addr)

        for b in sorted(changed_bytes):
            if merged_to is not None and not b >= merged_to:
                l.info("merged_to = %d ... already merged byte 0x%x", merged_to, b)
                continue
            l.debug("... on byte 0x%x", b)

            memory_objects: List[Tuple[SimMemoryObject,Any]] = []
            concretes: List[Tuple[int,Any]] = []
            unconstrained_in: List[Tuple['UltraPage',Any]] = []
            our_mo: Optional[SimMemoryObject] = None

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
            if not memory_objects and not unconstrained_in and len(set(cv for cv, _ in concretes)) == 1:
                cv = concretes[0][0]
                self.store(b, cv, size=1, cooperate=True, page_addr=page_addr)
                continue

            # convert all concrete values into memory objects
            for cv, fv in concretes:
                mo = SimMemoryObject(claripy.BVV(cv, size=8), page_addr + b, 'Iend_LE')
                memory_objects.append((mo, fv))

            mos = set(mo for mo, _ in memory_objects)
            mo_bases = set(mo.base for mo, _ in memory_objects)
            mo_lengths = set(mo.length for mo, _ in memory_objects)

            if not unconstrained_in and not (mos - merged_objects):
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and not unconstrained_in:

                to_merge = [(mo.object, fv) for mo, fv in memory_objects]

                # Update `merged_to`
                mo_base = list(mo_bases)[0]
                merged_to = mo_base + list(mo_lengths)[0]

                merged_val = self._merge_values(to_merge, memory_objects[0][0].length, memory=memory)

                if our_mo is None:
                    # this object does not exist in the current page. do the store
                    new_object = SimMemoryObject(merged_val, page_addr + b, memory_objects[0][0].endness)
                    self.store(b, new_object, size=list(mo_lengths)[0], cooperate=True)
                    merged_objects.add(new_object)
                else:
                    # do the replacement
                    new_object = self._replace_memory_object(our_mo, merged_val)
                    merged_objects.add(new_object)

                merged_objects.update(mos)
                merged_bytes.add(b)

            else:
                # get the size that we can merge easily. This is the minimum of
                # the size of all memory objects and unallocated spaces.
                min_size = min([mo.length - (b - mo.base) for mo, _ in memory_objects])
                for um, _ in unconstrained_in:
                    for i in range(0, min_size):
                        if um.contains(b + i, page_addr):
                            min_size = i
                            break
                merged_to = b + min_size
                l.info("... determined minimum size of %d", min_size)

                # Now, we have the minimum size. We'll extract/create expressions of that
                # size and merge them
                extracted = [(mo.bytes_at(b, min_size), fv) for mo, fv in memory_objects] if min_size != 0 else []
                created = [
                    (self._default_value(None, min_size, name="merge_uc_%s_%x" % (uc.id, b), memory=memory),
                     fv) for
                    uc, fv in unconstrained_in
                ]
                to_merge = extracted + created

                merged_val = self._merge_values(to_merge, min_size, memory=memory)

                self.store(b, merged_val, size=len(merged_val) // 8, endness='Iend_BE', inspect=False)  # do not convert endianness again

                merged_bytes.add(b)

        return merged_bytes

    def concrete_load(self, addr, size, **kwargs):
        if type(self.concrete_data) is bytearray:
            return memoryview(self.concrete_data)[addr:addr+size], memoryview(self.symbolic_bitmap)[addr:addr+size]
        else:
            return self.concrete_data[addr:addr+size], memoryview(self.symbolic_bitmap)[addr:addr+size]

    def changed_bytes(self, other, page_addr=None) -> Set[int]:
        changes = set()
        for addr in range(len(self.symbolic_bitmap)):
            if self.symbolic_bitmap[addr] != other.symbolic_bitmap[addr]:
                changes.add(addr)
            elif self.symbolic_bitmap[addr] == 0:
                if self.concrete_data[addr] != other.concrete_data[addr]:
                    changes.add(addr)
            else:
                try:
                    aself = next(self.symbolic_data.irange(maximum=addr))
                except StopIteration:
                    aself = None
                try:
                    aother = next(other.symbolic_data.irange(maximum=addr))
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

    def contains(self, start: int, page_addr: int):
        if not self.symbolic_bitmap[start]:
            # concrete data
            return True
        else:
            # symbolic data or does not exist
            return self._get_object(start, page_addr) is not None

    def _get_object(self, start: int, page_addr: int) -> Optional[SimMemoryObject]:
        try:
            place = next(self.symbolic_data.irange(maximum=start, reverse=True))
        except StopIteration:
            return None
        else:
            obj = self.symbolic_data[place]
            if obj.includes(start + page_addr):
                return obj
            else:
                return None

    def _replace_memory_object(self, old: SimMemoryObject, new_content: claripy.Bits):
        """
        Replaces the memory object `old` with a new memory object containing `new_content`.

        :param old:         A SimMemoryObject (i.e., one from :func:`memory_objects_for_hash()` or :func:`
                            memory_objects_for_name()`).
        :param new_content: The content (claripy expression) for the new memory object.
        :returns: the new memory object
        """

        if (old.object.size() if not old.is_bytes else len(old.object) * self.state.arch.byte_width) != new_content.size():
            raise SimMemoryError("memory objects can only be replaced by the same length content")

        new = SimMemoryObject(new_content, old.base, old.endness, byte_width=old._byte_width)
        for k in list(self.symbolic_data):
            if self.symbolic_data[k] is old:
                self.symbolic_data[k] = new
        return new
