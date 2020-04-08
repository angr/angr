import claripy
from sortedcontainers import SortedDict

from . import PageBase
from .cooperation import MemoryObjectMixin, SimMemoryObject

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
        def get_object(start):
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
                cur_val = get_object(subaddr)
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

    def store(self, addr, data, size=None, endness=None, memory=None, page_addr=None, cooperate=False, **kwargs):
        if not cooperate:
            data = self._force_store_cooperation(addr, data, size, endness, memory=memory, **kwargs)

        if data.object.op == 'BVV':
            # mark range as symbolic
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

    def concrete_load(self, addr, size, **kwargs):
        return memoryview(self.concrete_data)[addr:addr+size], memoryview(self.symbolic_bitmap)[addr:addr+size]
