import logging

import claripy

from .memory import SimMemory
from .symbolic_memory import SimSymbolicMemory

l = logging.getLogger("simuvex.plugins.abstract_memory")

class SimAbstractMemory(SimMemory):
    '''
    This is an implementation of the abstract store in paper [TODO].
    '''
    def __init__(self, backer=None, memory_id="mem"):
        SimMemory.__init__(self)

        self._regions = {}

        self._memory_id = memory_id

        if backer is not None:
            for region, backer_dict in backer.items():
                region_memory = SimSymbolicMemory(backer=backer_dict,
                                                  memory_id=region,
                                                  uninitialized_read_callback=self.default_read)
                region_memory.set_state(self.state)
                self._regions[region] = region_memory

    def set_state(self, state):
        '''
        Overriding the SimStatePlugin.set_state() method
        :param state:
        :return:
        '''
        self.state = state
        for k, v in self._regions.items():
            v.set_state(state)

    def store(self, addr, data, key=None, condition=None, fallback=None):
        assert type(key) is str

        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key,
                                              uninitialized_read_callback=self.default_read)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        self._regions[key].store(addr, data, condition, fallback)

    def load(self, addr, size, key=None, condition=None, fallback=None):
        assert type(key) is str

        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key,
                                              uninitialized_read_callback=self.default_read)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        return self._regions[key].load(addr, size, condition, fallback)

    def copy(self):
        '''
        Make a copy of this SimAbstractMemory object
        :return:
        '''
        am = SimAbstractMemory(memory_id=self._memory_id)
        for region, mem in self._regions.items():
            am._regions[region] = mem.copy()

        return am

    @staticmethod
    def default_read(mem_id, addr, bits):
        l.debug("Create a default value for region %s, address 0x%08x", mem_id, addr)

        return claripy.get_claripy().StridedInterval(bits=bits,
                                                     stride=1,
                                                     lower_bound=0,
                                                     upper_bound=0)
