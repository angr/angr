import logging

import claripy

from .memory import SimMemory
from .symbolic_memory import SimSymbolicMemory

l = logging.getLogger("simuvex.plugins.abstract_memory")

class SimAbstractMemory(SimMemory):
    '''
    This is an implementation of the abstract store in paper [TODO].

    Some differences:
    # For stack variables, we map the absolute stack address to each region so
      that we can effectively trace stack accesses. When tracing into a new
      function, you should call set_stack_address_mapping() to create a new mapping.
      When exiting from a function, you should cancel the previous mapping by
      calling unset_stack_address_mapping().
      Currently this is only used for stack!
    '''
    def __init__(self, backer=None, memory_id="mem"):
        SimMemory.__init__(self)

        self._regions = {}
        self._stack_address_to_region = []

        self._memory_id = memory_id

        if backer is not None:
            for region, backer_dict in backer.items():
                region_memory = SimSymbolicMemory(backer=backer_dict,
                                                  memory_id=region)
                region_memory.set_state(self.state)
                self._regions[region] = region_memory

    def stack_id(self, function_address):
        return 'stack_0x%08x' % function_address

    def set_stack_address_mapping(self, abs_addr, region_id):
        for address, region in self._stack_address_to_region:
            if address < abs_addr:
                self._stack_address_to_region.remove((address, region))

        self._stack_address_to_region.append((abs_addr, region_id))

    def unset_stack_address_mapping(self, abs_addr, region_id):
        pos = self._stack_address_to_region.index((abs_addr, region_id))

        self._stack_address_to_region = self._stack_address_to_region[0 : pos]

    def _normalize_address(self, region, addr):
        '''
        If this is a stack address, we convert it to a correct region and address
        :param addr: Absolute address
        :return: a tuple of (region_id, normalized_address)
        '''
        if region.startswith('stack'):
            pos = 0
            for i in xrange(len(self._stack_address_to_region) - 1, 0, -1):
                if self._stack_address_to_region[i][0] > addr:
                    pos = i
                    break
            new_region = self._stack_address_to_region[pos][1]
            new_addr = addr - self._stack_address_to_region[pos][0]
            l.debug('%s 0x%08x is normalized to %s %08x, region base addr is 0x%08x', region, addr, new_region, new_addr, self._stack_address_to_region[pos][0])
            return (new_region, new_addr) # TODO: Is it OK to return a negative address?
        else:
            return (region, addr)

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
            normalized_region, normalized_addr = self._normalize_address(region, addr_si.min)
            self._store(normalized_addr, data, normalized_region)

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
            normalized_region, normalized_addr = self._normalize_address(region, addr_si.min)
            new_val = self._load(normalized_addr, size, normalized_region)
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

        # TODO: For now we are only finding in one region!
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
        am._stack_address_to_region = self._stack_address_to_region[::]
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