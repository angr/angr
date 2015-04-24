import logging

import claripy

from ..storage.memory import SimMemory
from .symbolic_memory import SimSymbolicMemory

l = logging.getLogger("simuvex.plugins.abstract_memory")

WRITE_TARGETS_LIMIT = 200

class MemoryRegion(object):
    def __init__(self, id, state, is_stack=False, related_function_addr=None, init_memory=True, backer_dict=None): #pylint:disable=redefined-builtin,unused-argument
        self._id = id
        self._state = state
        self._is_stack = id.startswith('stack_') # TODO: Fix it
        self._related_function_addr = related_function_addr
        # This is a map from tuple (basicblock_key, stmt_id) to
        # AbstractLocation objects
        self._alocs = { }

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

    @property
    def alocs(self):
        return self._alocs

    @property
    def is_stack(self):
        return self._is_stack

    @property
    def related_function_addr(self):
        return self._related_function_addr

    def addrs_for_name(self, name):
        return self.memory.addrs_for_name(name)

    def set_state(self, state):
        self._state = state
        self._memory.set_state(state)

    def copy(self):
        r = MemoryRegion(self._id, self.state,
                         is_stack=self._is_stack,
                         related_function_addr=self._related_function_addr,
                         init_memory=False)
        r._memory = self.memory.copy()
        r._alocs = self._alocs.copy()
        return r

    def store(self, addr, data, bbl_addr, stmt_id, ins_addr):
        if ins_addr is not None:
            #aloc_id = (bbl_addr, stmt_id)
            aloc_id = ins_addr
            if aloc_id not in self._alocs:
                self._alocs[aloc_id] = self.state.se.AbstractLocation(bbl_addr,
                                                                      stmt_id,
                                                                      self.id,
                                                                      region_offset=addr,
                                                                      size=len(data) / 8)
                return self.memory.store(addr, data)
            else:
                if self._alocs[aloc_id].update(addr, len(data) / 8):
                    return self.memory.store(addr, data)
                else:
                    return self.memory.store_with_merge(addr, data)
        else:
            return self.memory.store(addr, data)

    def load(self, addr, size, bbl_addr, stmt_idx, ins_addr): #pylint:disable=unused-argument
        #if bbl_addr is not None and stmt_id is not None:
        return self.memory.load(addr, size)

    def merge(self, others, merge_flag, flag_values):
        merging_occurred = False

        for other_region in others:
            # Merge alocs
            for aloc_id, aloc in other_region.alocs.iteritems():
                if aloc_id not in self.alocs:
                    self.alocs[aloc_id] = aloc.copy()
                    merging_occurred = True
                else:
                    # Update it
                    merging_occurred |= self.alocs[aloc_id].merge(aloc)

            # Merge memory
            merging_result, _ = self.memory.merge([other_region.memory], merge_flag, flag_values)

            merging_occurred |= merging_result

        return merging_occurred

    def widen(self, others, merge_flag, flag_values):
        widening_occurred = False

        for other_region in others:
            for aloc_id, aloc in other_region.alocs.iteritems():
                if aloc_id not in self.alocs:
                    self.alocs[aloc_id] = aloc.copy()
                    widening_occurred = True
                else:
                    widening_occurred |= self.alocs[aloc_id].merge(aloc)

            # Widen the values inside memory
            widening_result = self.memory.widen([ other_region.memory ], merge_flag, flag_values)

            widening_occurred |= widening_result

        return widening_occurred

    def __contains__(self, addr):
        return addr in self.memory

    def dbg_print(self, indent=0):
        '''
        Print out debugging information
        '''
        print "%sA-locs:" % (" " * indent)
        for aloc_id, aloc in self._alocs.items():
            print "%s<0x%x> %s" % (" " * (indent + 2), aloc_id, aloc)

        print "%sMemory:" % (" " * indent)
        self.memory.dbg_print(indent=indent + 2)

class SimAbstractMemory(SimMemory): #pylint:disable=abstract-method
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
        self.id = self._memory_id

        if backer is not None:
            for region, backer_dict in backer.items():
                self._regions[region] = MemoryRegion(region, self.state,
                                               init_memory=True,
                                               backer_dict=backer_dict)

    @property
    def regions(self):
        return self._regions

    def stack_id(self, function_address): #pylint:disable=no-self-use
        return 'stack_0x%x' % function_address

    def set_stack_size(self, size):
        self._stack_size = size

    def set_stack_address_mapping(self, abs_addr, region_id, function_address):
        for address, region, func_addr in self._stack_address_to_region:
            if address < abs_addr:
                self._stack_address_to_region.remove((address, region, func_addr))
                if region in self._stack_region_to_address: del self._stack_region_to_address[region]

        self._stack_address_to_region.append((abs_addr, region_id, function_address))
        self._stack_region_to_address[region_id] = abs_addr

    def unset_stack_address_mapping(self, abs_addr, region_id, function_address):
        pos = self._stack_address_to_region.index((abs_addr, region_id, function_address))
        self._stack_address_to_region = self._stack_address_to_region[0 : pos]

        if region_id in self._stack_region_to_address: del self._stack_region_to_address[region_id]

    def _normalize_address(self, region, addr):
        '''
        If this is a stack address, we convert it to a correct region and address
        :param addr: Absolute address
        :return: a tuple of (region_id, normalized_address, is_stack, related_function_addr)
        '''
        if not self._stack_address_to_region:
            return (region, addr, False, None)

        stack_base = self._stack_address_to_region[0][0]

        if region.startswith('stack'):
            addr += self._stack_region_to_address[region]

            pos = 0
            for i in xrange(len(self._stack_address_to_region) - 1, 0, -1):
                if self._stack_address_to_region[i][0] >= addr:
                    pos = i
                    break
            new_region = self._stack_address_to_region[pos][1]
            new_addr = addr - self._stack_address_to_region[pos][0]
            related_function_addr = self._stack_address_to_region[pos][2]
            l.debug('%s 0x%08x is normalized to %s %08x, region base addr is 0x%08x', region, addr, new_region, new_addr, self._stack_address_to_region[pos][0])
            return (new_region, new_addr, True, related_function_addr) # TODO: Is it OK to return a negative address?
        else:
            l.debug("Got address %s 0x%x", region, addr)
            if addr < stack_base and \
                addr > stack_base - self._stack_size:
                return self._normalize_address(self._stack_address_to_region[0][1], addr - stack_base)
            else:
                return (region, addr, False, None)

    def set_state(self, state):
        '''
        Overriding the SimStatePlugin.set_state() method
        :param state:
        :return:
        '''
        self.state = state
        for _,v in self._regions.items():
            v.set_state(state)

    def normalize_address(self, addr, is_write=False):
        if type(addr) in (int, long):
            addr = self.state.se.BVV(addr, self.state.arch.bits)

        addr = addr.model
        addr_with_regions = self._normalize_address_type(addr)
        addresses = [ ]

        for region, addr_si in addr_with_regions.items():
            if is_write:
                concrete_addrs = addr_si.eval(WRITE_TARGETS_LIMIT)
                if len(concrete_addrs) == WRITE_TARGETS_LIMIT:
                    self.state.log.add_event('mem', message='too many targets to write to. address = %s' % addr_si)
            else:
                concrete_addrs = addr_si.eval(WRITE_TARGETS_LIMIT)
                if len(concrete_addrs) == WRITE_TARGETS_LIMIT:
                    self.state.log.add_event('mem', message='too many targets to read from. address = %s' % addr_si)

            for c in concrete_addrs:
                normalized_region, normalized_addr, is_stack, related_function_addr = \
                    self._normalize_address(region, c)

                addresses.append((normalized_region, normalized_addr, is_stack, related_function_addr))

        return addresses

    def _normalize_address_type(self, addr): #pylint:disable=no-self-use
        if isinstance(addr, claripy.BVV):
            # That's a global address
            addr = claripy.vsa.ValueSet(region='global', bits=addr.bits, val=addr.value)

            return addr
        elif isinstance(addr, claripy.vsa.StridedInterval):
            l.warning('Converting an SI to address. This may implies an imprecise analysis (e.g. skipping functions) or a bug/"feature" in the program itself.')
            # We'll convert as best as we can do...
            if len(addr.eval(20)) == 20:
                l.warning('Returning more than 20 addresses - Unconstrained write?')
                addr = claripy.vsa.ValueSet(region='global', bits=addr.bits, val=addr.min)
            else:
                addr = claripy.vsa.ValueSet(region='global', bits=addr.bits, val=addr.min)
            return addr
        elif isinstance(addr, claripy.vsa.ValueSet):
            return addr
        elif isinstance(addr, claripy.vsa.IfProxy):
            # Get two addresses and combine them
            combined_addr = addr.trueexpr.union(addr.falseexpr)
            return combined_addr
        else:
            raise SimMemoryError('Unsupported address type %s' % type(addr))

    # FIXME: symbolic_length is also a hack!
    def _store(self, addr, data, size=None, condition=None, fallback=None):
        addresses = self.normalize_address(addr, is_write=True)

        for normalized_region, normalized_addr, is_stack, related_function_addr in addresses:
                self._do_store(normalized_addr, data, normalized_region,
                            is_stack=is_stack, related_function_addr=related_function_addr)

        # No constraints are generated...
        return [ ]

    def _do_store(self, addr, data, key, is_stack=False, related_function_addr=None):
        if type(key) is not str:
            raise Exception('Incorrect type %s of region_key' % type(key))
        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self._regions[key] = MemoryRegion(key, is_stack=is_stack,
                                              related_function_addr=related_function_addr,
                                              state=self.state)

        self._regions[key].store(addr, data, bbl_addr, stmt_id, ins_addr)

    def _load(self, addr, size, condition=None, fallback=None):
        addresses = self.normalize_address(addr, is_write=False)

        if isinstance(size, claripy.A) and isinstance(size.model, ValueSet):
            # raise Exception('Unsupported type %s for size' % type(size.model))
            # FIXME: don't pretend to read something out...
            return self.state.se.Unconstrained('invalid_read_0x%x' % self.state.ins_addr, 32), [True]

        val = None
        for normalized_region, normalized_addr, is_stack, related_function_addr in addresses:
            new_val = self._do_load(normalized_addr, size, normalized_region,
                                 is_stack=is_stack, related_function_addr=related_function_addr)[0]
            if val is None:
                val = new_val
            else:
                val = val.union(new_val)

        return val, [True]

    def _do_load(self, addr, size, key, is_stack=False, related_function_addr=None):
        if type(key) is not str:
            raise Exception('Incorrect type %s of region_key' % type(key))

        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self._regions[key] = MemoryRegion(key, state=self.state,
                                              is_stack=is_stack, related_function_addr=related_function_addr)

        return self._regions[key].load(addr, size, bbl_addr, stmt_id, ins_addr)

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        if type(addr) in (int, long):
            addr = self.state.se.BVV(addr, self.state.arch.bits)

        addr = self._normalize_address_type(addr.model)

        # TODO: For now we are only finding in one region!
        for region, si in addr.items():
            return self._regions[region].memory.find(si.min, what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default)

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
        merging_occurred = False

        for o in others:
            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    merging_occurred |= self._regions[region_id].merge([region], merge_flag, flag_values)
                else:
                    merging_occurred = True
                    self._regions[region_id] = region

        # We have no constraints to return!
        return merging_occurred, []

    def widen(self, others, merge_flag, flag_values):

        widening_occurred = False

        for o in others:
            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    widening_occurred |= self._regions[region_id].widen([ region ], merge_flag, flag_values)
                else:
                    widening_occurred = True
                    self._regions[region_id] = region

        return widening_occurred, [ ]

    def __contains__(self, dst):
        if type(dst) in (int, long):
            dst = self.state.se.BVV(dst, self.state.arch.bits).model

        addrs = self._normalize_address_type(dst)


        for region, addr in addrs.items():
            normalized_region, normalized_addr, _, _ = \
                self._normalize_address(region, addr.min)

            return normalized_addr in self.regions[normalized_region]

        return False

    def dbg_print(self):
        '''
        Print out debugging information
        '''
        for regionid, region in self.regions.items():
            print "Region [%s]:" % regionid
            region.dbg_print(indent=2)

from ..s_errors import SimMemoryError
from claripy.vsa import ValueSet
