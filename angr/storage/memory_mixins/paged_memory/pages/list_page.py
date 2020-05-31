from typing import Optional, List

from . import PageBase
from angr.storage.memory_object import SimMemoryObject
from .cooperation import MemoryObjectMixin


class ListPage(MemoryObjectMixin, PageBase):
    def __init__(self, memory=None, content=None, sinkhole=None, **kwargs):
        super().__init__(**kwargs)

        self.content: List[Optional[SimMemoryObject]] = content
        if content is None:
            if memory is not None:
                self.content = [None] * memory.page_size  # TODO: this isn't the best

        self.sinkhole: Optional[SimMemoryObject] = sinkhole

    def copy(self, memo):
        o = super().copy(memo)
        o.content = list(self.content)
        o.sinkhole = self.sinkhole
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
        new_ast = self._default_value(global_start_addr, size, name='%s_%x' % (memory.id, global_start_addr), key=(self.category, global_start_addr), memory=memory, **kwargs)
        new_item = SimMemoryObject(new_ast, global_start_addr, endness=endness, byte_width=memory.state.arch.byte_width if memory is not None else 8)
        for subaddr in range(global_start_addr - page_addr, addr):
            self.content[subaddr] = new_item
        result[-1] = (global_start_addr, new_item)

    def store(self, addr, data, size=None, endness=None, memory=None, cooperate=False, **kwargs):
        if not cooperate:
            data = self._force_store_cooperation(addr, data, size, endness, memory=memory, **kwargs)

        if size == len(self.content) and addr == 0:
            self.sinkhole = data
            self.content = [None]*len(self.content)
        else:
            for subaddr in range(addr, addr + size):
                self.content[subaddr] = data

    def merge(self, others: List['ListPage'], merge_conditions, common_ancestor=None):
        raise NotImplementedError()
