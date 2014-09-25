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
                                                  memory_id=region)
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

    def store(self, key, addr, data, condition=None, fallback=None):
        assert type(key) is str

        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        self._regions[key].store(addr, data, condition, fallback)

    def load(self, key, addr, size, condition=None, fallback=None):
        assert type(key) is str

        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key)
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

    def merge(self, others, merge_flag, flag_values):
        '''
        Merge this guy with another SimAbstractMemory instance
        :param others:
        :param merge_flag:
        :param flag_values:
        :return:
        '''
        for o in others:
            assert type(o) is SimAbstractMemory

            for region, mem in o._regions.items():
                if region in self._regions:
                    self._regions[region].merge([mem], merge_flag, flag_values)
                else:
                    self._regions[region] = mem

        # We have no constraints to return!
        return []