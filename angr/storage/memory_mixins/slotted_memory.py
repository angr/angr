import claripy

from . import MemoryMixin
from .paged_memory.pages.ispo_mixin import ISPOMixin
from ...errors import SimMergeError


class SlottedMemoryMixin(MemoryMixin):
    def __init__(self, width=None, **kwargs):
        super().__init__(**kwargs)

        if width is None and isinstance(self, ISPOMixin):
            width = 4
        self.width = width

        self.contents = {}

    def set_state(self, state):
        super().set_state(state)
        if self.width is None:
            self.width = state.arch.bytes

    def copy(self, memo):
        o = super().copy(memo)
        o.width = self.width
        o.contents = dict(self.contents)
        return o

    def merge(self, others, merge_conditions, common_ancestor=None):
        if any(o.width != self.width for o in others):
            raise SimMergeError("Cannot merge slotted memory with disparate widths")
        addr_set = set(self.contents)
        for o in others:
            addr_set.update(o.contents)

        for addr in addr_set:
            self._single_store(
                addr,
                0,
                self.width,
                self.state.solver.ite_cases(
                    zip(merge_conditions[1:], (o._single_load(addr, 0, self.width) for o in others)),
                    self._single_load(addr, 0, self.width),
                ),
            )
        # FIXME: Return True only when merge actually happens
        return True

    def _resolve_access(self, addr, size):
        """
        Resolves a memory access of a certain size. Returns a sequence of the bases, offsets, and sizes of the accesses
        required to fulfil this.
        """

        # if we fit in one word
        first_offset = addr % self.width
        first_base = addr - first_offset
        if first_offset + size <= self.width:
            result = [(first_base, first_offset, size)]
        else:
            last_size = (addr + size) % self.width
            last_base = addr + size - last_size

            result = [(first_base, first_offset, self.width - first_offset)]
            result.extend((a, 0, self.width) for a in range(first_base + self.width, last_base, self.width))
            if last_size != 0:
                result.append((last_base, 0, last_size))

        # little endian: need to slice in reverse and also concatenate in reverse
        # if load endness and storage endness don't match, reverse whole data value before store/after load
        if self.endness == "Iend_LE":
            result = [(addr, self.width - offset - size, size) for addr, offset, size in reversed(result)]

        return result

    def _single_load(self, addr, offset, size, **kwargs):
        """
        Performs a single load.
        """
        try:
            d = self.contents[addr]
        except KeyError:
            d = self._default_value(addr, self.width, self.variable_key_prefix + (addr,), **kwargs)
            self.contents[addr] = d

        if offset == 0 and size == self.width:
            return d
        else:
            return d.get_bytes(offset, size)

    def _single_store(self, addr, offset, size, data):
        """
        Performs a single store.
        """

        if offset == 0 and size == self.width:
            self.contents[addr] = data
        elif offset == 0:
            cur = self._single_load(addr, size, self.width - size)
            self.contents[addr] = data.concat(cur)
        elif offset + size == self.width:
            cur = self._single_load(addr, 0, offset)
            self.contents[addr] = cur.concat(data)
        else:
            cur = self._single_load(addr, 0, self.width)
            start = cur.get_bytes(0, offset)
            end = cur.get_bytes(offset + size, self.width - offset - size)
            self.contents[addr] = start.concat(data, end)

    def load(self, addr, size=None, endness=None, **kwargs):
        accesses = self._resolve_access(addr, size)

        value = claripy.Concat(*(self._single_load(addr, offset, size) for addr, offset, size in accesses))
        if endness != self.endness:
            value = value.reversed

        return value

    def store(self, addr, data, size=None, endness=None, **kwargs):
        if endness != self.endness:
            data = data.reversed

        accesses = self._resolve_access(addr, size)
        cur_offset = 0
        for addr, offset, size in accesses:
            piece = data.get_bytes(cur_offset, size)
            self._single_store(addr, offset, size, piece)
            cur_offset += size

    def changed_bytes(self, other):
        changes = set()

        for addr, v in self.contents.items():
            for i in range(self.width):
                other_byte = other.load(addr + i, 1)
                our_byte = v.get_byte(i)
                if other_byte is our_byte:
                    changes.add(addr + i)

        return changes
