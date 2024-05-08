from typing import Any

import claripy

from angr.storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from .multi_values import MultiValues


class CooperationBase:
    """
    Any given subclass of this class which is not a subclass of MemoryMixin should have the property that any subclass
    it which *is* a subclass of MemoryMixin should all work with the same datatypes
    """

    @classmethod
    def _compose_objects(cls, objects, size, endness, **kwargs):
        """
        Provide this a list of the result of several load calls, and it will compose them into a single result.
        """

    @classmethod
    def _decompose_objects(cls, addr, data, endness, **kwargs) -> tuple[Any, int, int]:
        """
        A bidirectional generator. No idea if this is overengineered. Usage is that you send it a size to use
        and it yields a tuple of three elements: the object to store for the next n bytes, the base address of the
        object, and the size of the object.
        """

    @classmethod
    def _zero_objects(cls, addr, size, **kwargs):
        """
        Like decompose objects, but with a size to zero-fill instead of explicit data
        """

    @classmethod
    def _force_store_cooperation(cls, addr, data, size, endness, **kwargs):
        if data is not None:
            sub_gen = cls._decompose_objects(addr, data, endness, **kwargs)
        else:
            sub_gen = cls._zero_objects(addr, size, **kwargs)

        next(sub_gen)
        sub_data, _, _ = sub_gen.send(size)
        sub_gen.close()
        return sub_data

    @classmethod
    def _force_load_cooperation(cls, results, size, endness, **kwargs):
        return cls._compose_objects([results], size, endness, **kwargs)


class MemoryObjectMixin(CooperationBase):
    """
    Uses SimMemoryObjects in region storage.
    With this, load will return a list of tuple (address, MO) and store will take a MO.
    """

    @classmethod
    def _compose_objects(
        cls,
        objects: list[list[tuple[int, SimMemoryObject]]],
        size,
        endness=None,
        memory=None,
        labels: list | None = None,
        **kwargs,
    ):
        c_objects = []
        for objlist in objects:
            for element in objlist:
                if not c_objects or element[1] is not c_objects[-1][1]:
                    c_objects.append(element)

        mask = (1 << memory.state.arch.bits) - 1
        if labels is None:
            # fast path - ignore labels
            elements = [
                o.bytes_at(
                    a,
                    (
                        ((c_objects[i + 1][0] - a) & mask)
                        if i != len(c_objects) - 1
                        else ((c_objects[0][0] + size - a) & mask)
                    ),
                    endness=endness,
                )
                for i, (a, o) in enumerate(c_objects)
            ]
        else:
            # we need to extract labels for SimLabeledMemoryObjects
            elements = []
            offset = 0
            for i, (a, o) in enumerate(c_objects):
                length: int = (
                    ((c_objects[i + 1][0] - a) & mask)
                    if i != len(c_objects) - 1
                    else ((c_objects[0][0] + size - a) & mask)
                )
                byts = o.bytes_at(a, length, endness=endness)
                elements.append(byts)
                if isinstance(o, SimLabeledMemoryObject):
                    labels.append((offset, a - o.base, length, o.label))
                offset += length
        if len(elements) == 0:
            # nothing is read out
            return claripy.BVV(0, 0)
        if len(elements) == 1:
            return elements[0]

        if endness == "Iend_LE":
            elements = list(reversed(elements))

        return elements[0].concat(*elements[1:])

    @classmethod
    def _decompose_objects(cls, addr, data, endness, memory=None, page_addr=0, label=None, **kwargs):
        # the generator model is definitely overengineered here but wouldn't be if we were working with raw BVs
        cur_addr = addr + page_addr
        byte_width = memory.state.arch.byte_width if memory is not None else 8
        if label is None:
            memory_object = SimMemoryObject(data, cur_addr, endness, byte_width=byte_width)
        else:
            memory_object = SimLabeledMemoryObject(data, cur_addr, endness, byte_width=byte_width, label=label)

        if data.symbolic and data.op == "Concat":
            next_elem_size_left = data.args[0].size() // 8
            next_elem_index = 0

        size = yield
        max_size = kwargs.get("max_size", size)
        while True:
            if data.symbolic and data.op == "Concat" and data.size() > max_size:
                # Generate new memory object with only size bytes to speed up extracting bytes
                cur_data_size_bits = 0
                requested_size_bits = size * 8
                cur_data = []
                while cur_data_size_bits < requested_size_bits:
                    if next_elem_size_left == 0:
                        next_elem_index += 1

                    next_elem = data.args[next_elem_index]
                    cur_data.append(next_elem)
                    next_elem_size_left = next_elem.size()
                    added_size = min(requested_size_bits - cur_data_size_bits, next_elem.size())
                    cur_data_size_bits += added_size
                    next_elem_size_left = next_elem_size_left - added_size

                cur_data = claripy.Concat(*cur_data)
                if label is None:
                    memory_object = SimMemoryObject(cur_data, cur_addr, endness, byte_width=byte_width)
                else:
                    memory_object = SimLabeledMemoryObject(
                        cur_data, cur_addr, endness, byte_width=byte_width, label=label
                    )
            cur_addr += size
            size = yield memory_object, memory_object.base, memory_object.length

    @classmethod
    def _zero_objects(cls, addr, size, memory=None, **kwargs):
        data = claripy.BVV(0, size * memory.state.arch.byte_width if memory is not None else 8)
        return cls._decompose_objects(addr, data, "Iend_BE", memory=memory, **kwargs)


class MemoryObjectSetMixin(CooperationBase):
    """
    Uses sets of SimMemoryObjects in region storage.
    """

    @classmethod
    def _compose_objects(
        cls, objects: list[list[tuple[int, set[SimMemoryObject]]]], size, endness=None, memory=None, **kwargs
    ):
        c_objects: list[tuple[int, SimMemoryObject | set[SimMemoryObject]]] = []
        for objlist in objects:
            for element in objlist:
                if not c_objects or element[1] is not c_objects[-1][1]:
                    c_objects.append(element)

        mask = (1 << memory.state.arch.bits) - 1
        elements: list[set[claripy.ast.Base]] = []
        for i, (a, objs) in enumerate(c_objects):
            chopped_set = set()
            if type(objs) is not set:
                objs = {objs}
            for o in objs:
                if o.includes(a):
                    chopped = o.bytes_at(
                        a,
                        (
                            ((c_objects[i + 1][0] - a) & mask)
                            if i != len(c_objects) - 1
                            else ((c_objects[0][0] + size - a) & mask)
                        ),
                        endness=endness,
                    )
                    chopped_set.add(chopped)
            if chopped_set:
                elements.append(chopped_set)

        if len(elements) == 0:
            # nothing is read out
            return MultiValues(claripy.BVV(0, 0))

        if len(elements) == 1:
            if len(elements[0]) == 1:
                return MultiValues(next(iter(elements[0])))
            return MultiValues(offset_to_values={0: elements[0]})

        if endness == "Iend_LE":
            elements = list(reversed(elements))

        mv = MultiValues()
        offset = 0
        start_offset = 0
        prev_value = ...
        for i, value_set in enumerate(elements):
            if len(value_set) == 1:
                if prev_value is ...:
                    prev_value = next(iter(value_set))
                    start_offset = offset
                else:
                    prev_value = prev_value.concat(next(iter(value_set)))
            else:
                if prev_value is not ...:
                    mv.add_value(start_offset, prev_value)
                    prev_value = ...

                for value in value_set:
                    mv.add_value(offset, value)

            offset += next(iter(value_set)).size() // memory.state.arch.byte_width

        if prev_value is not ...:
            mv.add_value(start_offset, prev_value)
            prev_value = ...

        return mv

    @classmethod
    def _decompose_objects(cls, addr, data, endness, memory=None, page_addr=0, label=None, **kwargs):
        # the generator model is definitely overengineered here but wouldn't be if we were working with raw BVs
        cur_addr = addr + page_addr
        if isinstance(data, MultiValues):
            # for MultiValues, we return sets of SimMemoryObjects
            assert label is None  # TODO: Support labels

            size = yield
            offset_to_mos: dict[int, set[SimMemoryObject]] = {}
            for offset, vs in data.items():
                offset_to_mos[offset] = set()
                for v in vs:
                    offset_to_mos[offset].add(
                        SimMemoryObject(
                            v,
                            cur_addr + offset,
                            endness,
                            byte_width=memory.state.arch.byte_width if memory is not None else 0,
                        )
                    )

            sorted_offsets = list(sorted(offset_to_mos.keys()))
            pos = 0
            while pos < len(sorted_offsets):
                mos = set(offset_to_mos[sorted_offsets[pos]])
                first_mo = next(iter(mos))
                old_size = size

                size = yield mos, first_mo.base, first_mo.length
                cur_addr += min(first_mo.length, old_size)
                if sorted_offsets[pos] + first_mo.length <= cur_addr - addr - page_addr:
                    pos += 1

        else:
            if label is None:
                obj = SimMemoryObject(
                    data, cur_addr, endness, byte_width=memory.state.arch.byte_width if memory is not None else 8
                )
            else:
                obj = SimLabeledMemoryObject(
                    data,
                    cur_addr,
                    endness,
                    byte_width=memory.state.arch.byte_width if memory is not None else 8,
                    label=label,
                )
            _ = yield
            while True:
                _ = yield {obj}, obj.base, obj.length

    @classmethod
    def _zero_objects(cls, addr, size, memory=None, **kwargs):
        data = claripy.BVV(0, size * memory.state.arch.byte_width if memory is not None else 8)
        return cls._decompose_objects(addr, data, "Iend_BE", memory=memory, **kwargs)


class BasicClaripyCooperation(CooperationBase):
    """
    Mix this (along with PageBase) into a storage class which supports loading and storing claripy bitvectors and it
    will be able to work as a page in the paged memory model.
    """

    @classmethod
    def _compose_objects(cls, objects, size, endness, **kwargs):
        if endness == "Iend_LE":
            objects = reversed(objects)

        return claripy.Concat(*objects)

    @classmethod
    def _decompose_objects(cls, addr, data, endness, memory=None, **kwargs):
        if endness == "Iend_BE":
            size = yield
            offset = 0
            while True:
                data_slice = data.get_bytes(offset, size)
                data_slide_base = addr + offset
                offset += size
                size = yield data_slice, data_slide_base, data_slice.length
        else:
            size = yield
            offset = len(data) // (memory.state.arch.byte_width if memory is not None else 8)
            while True:
                offset -= size
                data_slice = data.get_bytes(offset, size)
                size = yield data_slice, addr + offset, data_slice.length

    @classmethod
    def _zero_objects(cls, addr, size, memory=None, **kwargs):
        data = claripy.BVV(0, size * memory.state.arch.byte_width if memory is not None else 8)
        return cls._decompose_objects(addr, data, "Iend_BE", memory=memory, **kwargs)
