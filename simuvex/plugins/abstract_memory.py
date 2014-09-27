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

    # FIXME: symbolic_length is also a hack!
    def store(self, addr, data, key=None, condition=None, fallback=None, symbolic_length=None, strategy=None, limit=None):
        if key is not None:
            raise DeprecationWarning('"key" is deprecated.')

        assert symbolic_length is None
        assert strategy is None
        assert limit is None

        addr = addr._model
        assert type(addr) is claripy.vsa.ValueSet

        for region, addr_si in addr.items():
            # TODO: We only store to the min addr. Is this acceptable?
            self._store(addr_si.min, data, region)

        # No constraints are generated...
        return []

    def _store(self, addr, data, key):
        assert type(key) is str

        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        self._regions[key].store(addr, data, strategy=None, limit=None)

    # FIXME: Hack: The strategy and limit should not be there. Remove it as soon as Yan is back to work.
    def load(self, addr, size, key=None, condition=None, fallback=None, strategy=None, limit=None):
        if key is not None:
            raise DeprecationWarning('"key" is deprecated.')

        assert strategy is None
        assert limit is None

        addr = addr._model
        assert type(addr) in { claripy.vsa.ValueSet, claripy.BVV }

        if type(addr) is claripy.BVV:
            addr = self.state.se.ValueSet(region="global", bits=self.state.arch.bits, val=addr.value)._model

        val = None

        for region, addr_si in addr.items():
            new_val = self._load(addr_si.min, size, region)
            if val is None:
                val = new_val
            else:
                val = val.merge(new_val)

        return val

    def _load(self, addr, size, key):
        assert type(key) is str

        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        return self._regions[key].load(addr, size, condition=None, fallback=None)

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        if type(addr) is claripy.E:
            addr = addr._model

        if type(addr) is claripy.bv.BVV:
            addr = self.state.se.ValueSet(region="global", bits=self.state.arch.bits, val=addr.value)._model

        assert type(addr) is claripy.vsa.ValueSet

        # TODO: For now we are only finding in one regions!
        for region, si in addr.items():
            return self._regions[region].find(addr=si.min, what=what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default)

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