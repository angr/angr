import logging
from collections import defaultdict

import claripy

from .memory import SimMemory
from .symbolic_memory import SimSymbolicMemory

l = logging.getLogger("simuvex.plugins.abstract_memory")

class MemoryRegion(object):
    def __init__(self, id, state, init_memory=True, backer_dict=None):
        self._id = id
        self._state = state
        # This is a map from tuple (basicblock_key, stmt_id) to
        # AbstractLocation objects
        self._alocs = {}

        if init_memory:
            if backer_dict is None:
                self._memory = SimSymbolicMemory(memory_id=id)
            else:
                self._memory = SimSymbolicMemory(backer=backer_dict,
                                                 memory_id=id)

            self._memory.set_state(state)

    @property
    def id(self):
        return self._id

    @property
    def memory(self):
        return self._memory

    @property
    def state(self):
        return self._state

    def set_state(self, state):
        self._state = state
        self._memory.set_state(state)

    def copy(self):
        r = MemoryRegion(self._id, self.state, init_memory=False)
        r._memory = self.memory.copy()
        r._alocs = self._alocs.copy()
        return r

    def store(self, addr, data, bbl_addr, stmt_id):
        if bbl_addr is not None and stmt_id is not None:
            aloc_id = (bbl_addr, stmt_id)
            if aloc_id not in self._alocs:
                self._alocs[aloc_id] = self.state.se.AbstractLocation(bbl_addr,
                                                                      stmt_id,
                                                                      self.id,
                                                                      addr,
                                                                      len(data) / 8)

                return self.memory.store(addr, data)
            else:
                import ipdb; ipdb.set_trace()
                self._alocs[aloc_id].update(addr, len(data) / 8)
                return self.memory.store_with_merge(addr, data)

    def load(self, addr, size, bbl_addr, stmt_id):
        #if bbl_addr is not None and stmt_id is not None:

        return self.memory.load(addr, size)

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
        self._stack_region_to_address = {}
        self._stack_size = None

        self._memory_id = memory_id

        if backer is not None:
            for region, backer_dict in backer.items():
                self._regions[region] = MemoryRegion(region, self.state,
                                               init_memory=True,
                                               backer_dict=backer_dict)

    def stack_id(self, function_address):
        return 'stack_0x%x' % function_address

    def set_stack_size(self, size):
        self._stack_size = size

    def set_stack_address_mapping(self, abs_addr, region_id):
        for address, region in self._stack_address_to_region:
            if address < abs_addr:
                self._stack_address_to_region.remove((address, region))
                del self._stack_region_to_address[region]

        self._stack_address_to_region.append((abs_addr, region_id))
        self._stack_region_to_address[region_id] = abs_addr

    def unset_stack_address_mapping(self, abs_addr, region_id):
        pos = self._stack_address_to_region.index((abs_addr, region_id))
        self._stack_address_to_region = self._stack_address_to_region[0 : pos]

        del self._stack_region_to_address[region_id]

    def _normalize_address(self, region, addr):
        '''
        If this is a stack address, we convert it to a correct region and address
        :param addr: Absolute address
        :return: a tuple of (region_id, normalized_address)
        '''
        stack_base = self._stack_address_to_region[0][0]

        if region.startswith('stack'):
            addr += self._stack_region_to_address[region]

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
            if addr == 0:
                import ipdb; ipdb.set_trace()
            l.debug("Got address %s 0x%x", region, addr)
            if addr < stack_base and \
                addr > stack_base - self._stack_size:
                return self._normalize_address('stack_initial', addr - stack_base)
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
    def store(self, addr, data, size=None, key=None, condition=None, fallback=None, bbl_addr=None, stmt_id=None):
        if key is not None:
            raise DeprecationWarning('"key" is deprecated.')

        addr = addr._model
        assert type(addr) is claripy.vsa.ValueSet

        for region, addr_si in addr.items():
            # TODO: We only store to the min addr. Is this acceptable?
            normalized_region, normalized_addr = self._normalize_address(region, addr_si.min)
            self._store(normalized_addr, data, normalized_region, bbl_addr, stmt_id)

        # No constraints are generated...
        return []

    def _store(self, addr, data, key, bbl_addr, stmt_id):
        assert type(key) is str

        if key not in self._regions:
            self._regions[key] = MemoryRegion(key, state=self.state)

        self._regions[key].store(addr, data, bbl_addr, stmt_id)

    def load(self, addr, size, key=None, condition=None, fallback=None, bbl_addr=None, stmt_id=None):
        if key is not None:
            raise DeprecationWarning('"key" is deprecated.')

        addr = addr._model
        assert type(addr) in { claripy.vsa.ValueSet, claripy.BVV }

        if type(addr) is claripy.BVV:
            addr = self.state.se.ValueSet(region="global", bits=self.state.arch.bits, val=addr.value)._model

        val = None

        for region, addr_si in addr.items():
            normalized_region, normalized_addr = self._normalize_address(region, addr_si.min)
            new_val = self._load(normalized_addr, size, normalized_region, bbl_addr, stmt_id)
            if val is None:
                val = new_val
            else:
                val = val.merge(new_val)

        return val

    def _load(self, addr, size, key, bbl_addr, stmt_id):
        assert type(key) is str

        if key not in self._regions:
            self._regions[key] = MemoryRegion(key, self.state, bbl_addr, stmt_id)

        return self._regions[key].load(addr, size, bbl_addr, stmt_id)

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        if type(addr) is claripy.E:
            addr = addr._model

        if type(addr) is claripy.bv.BVV:
            addr = self.state.se.ValueSet(region="global", bits=self.state.arch.bits, val=addr.value)._model

        assert type(addr) is claripy.vsa.ValueSet

        # TODO: For now we are only finding in one region!
        for region, si in addr.items():
            return self._regions[region].memory.find(start=si.min, what=what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default)

    def copy(self):
        '''
        Make a copy of this SimAbstractMemory object
        :return:
        '''
        am = SimAbstractMemory(memory_id=self._memory_id)
        for region_id, region in self._regions.items():
            am._regions[region_id] = region.copy()
        am._stack_address_to_region = self._stack_address_to_region[::]
        am._stack_region_to_address = self._stack_region_to_address.copy()
        am._stack_size = self._stack_size
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

            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    self._regions[region_id].merge([region], merge_flag, flag_values)
                else:
                    self._regions[region_id] = region

        # We have no constraints to return!
        return []