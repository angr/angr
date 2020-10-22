import claripy
import typing

from angr.storage.memory_object import SimMemoryObject

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
        pass

    @classmethod
    def _decompose_objects(cls, addr, data, endness, **kwargs):
        """
        A bidirectional generator. No idea if this is overengineered. Usage is that you send it a size to use
        and it yields an object to store for the next n bytes.
        """
        pass

    @classmethod
    def _zero_objects(cls, addr, size, **kwargs):
        """
        Like decompose objects, but with a size to zero-fill instead of explicit data
        """
        pass

    @classmethod
    def _force_store_cooperation(cls, addr, data, size, endness, **kwargs):
        if data is not None:
            sub_gen = cls._decompose_objects(addr, data, endness, **kwargs)
        else:
            sub_gen = cls._zero_objects(addr, size, **kwargs)

        next(sub_gen)
        sub_data = sub_gen.send(size)
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
    def _compose_objects(cls, objects: typing.List[typing.List[typing.Tuple[int, SimMemoryObject]]], size, endness=None,
                         memory=None, **kwargs):
        c_objects = []
        for objlist in objects:
            for element in objlist:
                if not c_objects or element[1] is not c_objects[-1][1]:
                    c_objects.append(element)

        mask = (1 << memory.state.arch.bits) - 1
        elements = [o.bytes_at(
                a,
                ((c_objects[i+1][0] - a) & mask) if i != len(c_objects)-1 else ((c_objects[0][0] + size - a) & mask),
                endness=endness)
            for i, (a, o) in enumerate(c_objects)]
        if len(elements) == 0:
            # nothing is read out
            return claripy.BVV(0, 0)
        if len(elements) == 1:
            return elements[0]

        if endness == 'Iend_LE':
            elements = list(reversed(elements))

        return elements[0].concat(*elements[1:])

    @classmethod
    def _decompose_objects(cls, addr, data, endness, memory=None, page_addr=0, **kwargs):
        # the generator model is definitely overengineered here but wouldn't be if we were working with raw BVs
        cur_addr = addr + page_addr
        memory_object = SimMemoryObject(data, cur_addr, endness,
                                        byte_width=memory.state.arch.byte_width if memory is not None else 8)
        size = yield
        while True:
            cur_addr += size
            size = yield memory_object

    @classmethod
    def _zero_objects(cls, addr, size, memory=None, **kwargs):
        data = claripy.BVV(0, size*memory.state.arch.byte_width if memory is not None else 8)
        return cls._decompose_objects(addr, data, 'Iend_BE', memory=memory, **kwargs)


class BasicClaripyCooperation(CooperationBase):
    """
    Mix this (along with PageBase) into a storage class which supports loading and storing claripy bitvectors and it
    will be able to work as a page in the paged memory model.
    """
    @classmethod
    def _compose_objects(cls, objects, size, endness, **kwargs):
        if endness == 'Iend_LE':
            objects = reversed(objects)

        return claripy.Concat(*objects)

    @classmethod
    def _decompose_objects(cls, addr, data, endness, memory=None, **kwargs):
        if endness == 'Iend_BE':
            size = yield
            offset = 0
            while True:
                data_slice = data.get_bytes(offset, size)
                offset += size
                size = yield data_slice
        else:
            size = yield
            offset = len(data) // (memory.state.arch.byte_width if memory is not None else 8)
            while True:
                offset -= size
                data_slice = data.get_bytes(offset, size)
                size = yield data_slice

    @classmethod
    def _zero_objects(cls, addr, size, memory=None, **kwargs):
        data = claripy.BVV(0, size*memory.state.arch.byte_width if memory is not None else 8)
        return cls._decompose_objects(addr, data, 'Iend_BE', memory=memory, **kwargs)
