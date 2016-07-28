import logging
import copy
from itertools import count

import claripy
from claripy.vsa import ValueSet, RegionAnnotation

from ..storage.memory import SimMemory, AddressWrapper, MemoryStoreRequest, RegionMap
from ..s_errors import SimMemoryError
from ..s_options import KEEP_MEMORY_READS_DISCRETE, AVOID_MULTIVALUED_READS
from .symbolic_memory import SimSymbolicMemory
from ..s_action_object import _raw_ast

l = logging.getLogger("simuvex.plugins.abstract_memory")

WRITE_TARGETS_LIMIT = 2048
READ_TARGETS_LIMIT = 4096

#pylint:disable=unidiomatic-typecheck

invalid_read_ctr = count()

class MemoryRegion(object):
    def __init__(self, id, state, is_stack=False, related_function_addr=None, init_memory=True, backer_dict=None, endness=None): #pylint:disable=redefined-builtin,unused-argument
        self._endness = endness
        self._id = id
        self._state = state
        self._is_stack = id.startswith('stack_') # TODO: Fix it
        self._related_function_addr = related_function_addr
        # This is a map from tuple (basicblock_key, stmt_id) to
        # AbstractLocation objects
        self._alocs = { }

        if init_memory:
            if backer_dict is None:
                self._memory = SimSymbolicMemory(memory_id=id, endness=self._endness, abstract_backer=True)
            else:
                self._memory = SimSymbolicMemory(memory_backer=backer_dict, memory_id=id, endness=self._endness, abstract_backer=True)

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

    def get_abstract_locations(self, addr, size):
        """
        Get a list of abstract locations that is within the range of [addr, addr + size]

        This implementation is pretty slow. But since this method won't be called frequently, we can live with the bad
        implementation for now.

        :param addr:    Starting address of the memory region.
        :param size:    Size of the memory region, in bytes.
        :return:        A list of covered AbstractLocation objects, or an empty list if there is none.
        """

        ret = [ ]
        for aloc in self._alocs.itervalues():
            for seg in aloc.segments:
                if seg.offset >= addr and seg.offset < addr + size:
                    ret.append(aloc)
                    break

        return ret

    def addrs_for_name(self, name):
        return self.memory.addrs_for_name(name)

    def set_state(self, state):
        self._state = state
        self._memory.set_state(state)

    def copy(self):
        r = MemoryRegion(self._id, self.state,
                         is_stack=self._is_stack,
                         related_function_addr=self._related_function_addr,
                         init_memory=False, endness=self._endness)
        r._memory = self.memory.copy()
        r._alocs = copy.deepcopy(self._alocs)
        return r

    def store(self, request, bbl_addr, stmt_id, ins_addr):
        if ins_addr is not None:
            #aloc_id = (bbl_addr, stmt_id)
            aloc_id = ins_addr
        else:
            # It comes from a SimProcedure. We'll use bbl_addr as the aloc_id
            aloc_id = bbl_addr

        if aloc_id not in self._alocs:
            self._alocs[aloc_id] = self.state.se.AbstractLocation(bbl_addr,
                                                                  stmt_id,
                                                                  self.id,
                                                                  region_offset=request.addr,
                                                                  size=len(request.data) / 8)
            return self.memory._store(request)
        else:
            if self._alocs[aloc_id].update(request.addr, len(request.data) / 8):
                return self.memory._store(request)
            else:
                #return self.memory._store_with_merge(request)
                return self.memory._store(request)

    def load(self, addr, size, bbl_addr, stmt_idx, ins_addr): #pylint:disable=unused-argument
        #if bbl_addr is not None and stmt_id is not None:
        return self.memory.load(addr, size, inspect=False)

    def _merge_alocs(self, other_region):
        """
        Helper function for merging.
        """
        merging_occurred = False
        for aloc_id, aloc in other_region.alocs.iteritems():
            if aloc_id not in self.alocs:
                self.alocs[aloc_id] = aloc.copy()
                merging_occurred = True
            else:
                # Update it
                merging_occurred |= self.alocs[aloc_id].merge(aloc)
        return merging_occurred

    def merge(self, others, merge_conditions):
        merging_occurred = False
        for other_region in others:
            merging_occurred |= self._merge_alocs(other_region)
            merging_occurred |= self.memory.merge([other_region.memory], merge_conditions)
        return merging_occurred

    def widen(self, others):
        widening_occurred = False
        for other_region in others:
            widening_occurred |= self._merge_alocs(other_region)
            widening_occurred |= self.memory.widen([ other_region.memory ])
        return widening_occurred

    def __contains__(self, addr):
        return addr in self.memory

    def was_written_to(self, addr):
        return self.memory.was_written_to(addr)

    def dbg_print(self, indent=0):
        """
        Print out debugging information
        """
        print "%sA-locs:" % (" " * indent)
        for aloc_id, aloc in self._alocs.items():
            print "%s<0x%x> %s" % (" " * (indent + 2), aloc_id, aloc)

        print "%sMemory:" % (" " * indent)
        self.memory.dbg_print(indent=indent + 2)

class SimAbstractMemory(SimMemory): #pylint:disable=abstract-method
    """
    This is an implementation of the abstract store in paper [TODO].

    Some differences:
    # For stack variables, we map the absolute stack address to each region so
      that we can effectively trace stack accesses. When tracing into a new
      function, you should call set_stack_address_mapping() to create a new mapping.
      When exiting from a function, you should cancel the previous mapping by
      calling unset_stack_address_mapping().
      Currently this is only used for stack!
    """
    def __init__(self, memory_backer=None, memory_id="mem", endness=None):
        SimMemory.__init__(self, endness=endness)

        self._regions = {}
        self._stack_region_map = RegionMap(True)
        self._generic_region_map = RegionMap(False)
        self._stack_size = None

        self._memory_id = memory_id
        self.id = self._memory_id

        if memory_backer is not None:
            for region, backer_dict in memory_backer.items():
                self._regions[region] = MemoryRegion(region, self.state,
                                               init_memory=True,
                                               backer_dict=backer_dict,
                                               endness=self.endness)

    @property
    def regions(self):
        return self._regions

    def _region_base(self, region):
        """
        Get the base address of a memory region.

        :param str region: ID of the memory region
        :return: Address of the memory region
        :rtype: int
        """

        if region == 'global':
            region_base_addr = 0
        elif region.startswith('stack_'):
            region_base_addr = self._stack_region_map.absolutize(region, 0)
        else:
            region_base_addr = self._generic_region_map.absolutize(region, 0)

        return region_base_addr

    def stack_id(self, function_address):
        """
        Return a memory region ID for a function. If the default region ID exists in the region mapping, an integer
        will appended to the region name. In this way we can handle recursive function calls, or a function that
        appears more than once in the call frame.

        This also means that `stack_id()` should only be called when creating a new stack frame for a function. You are
        not supposed to call this function every time you want to map a function address to a stack ID.

        :param int function_address: Address of the function.
        :return: ID of the new memory region.
        :rtype; str
        """

        region_id = 'stack_0x%x' % function_address

        # deduplication
        region_ids = self._stack_region_map.region_ids
        if region_id not in region_ids:
            return region_id
        else:
            for i in xrange(0, 2000):
                new_region_id = region_id + '_%d' % i
                if new_region_id not in region_ids:
                    return new_region_id
            raise SimMemoryError('Cannot allocate region ID for function %#08x - recursion too deep' % function_address)



    def set_stack_size(self, size):
        self._stack_size = size

    def set_stack_address_mapping(self, absolute_address, region_id, related_function_address=None):
        self._stack_region_map.map(absolute_address, region_id, related_function_address=related_function_address)

    def unset_stack_address_mapping(self, absolute_address, region_id, function_address):  # pylint:disable=unused-argument
        self._stack_region_map.unmap_by_address(absolute_address)

    def _normalize_address(self, region_id, relative_address, target_region=None):
        """
        If this is a stack address, we convert it to a correct region and address

        :param region_id: a string indicating which region the address is relative to
        :param relative_address: an address that is relative to the region parameter
        :param target_region: the ideal target region that address is normalized to. None means picking the best fit.
        :return: an AddressWrapper object
        """
        if self._stack_region_map.is_empty and self._generic_region_map.is_empty:
            # We don't have any mapped region right now
            return AddressWrapper(region_id, 0, relative_address, False, None)

        # We wanna convert this address to an absolute address first
        if region_id.startswith('stack_'):
            absolute_address = self._stack_region_map.absolutize(region_id, relative_address)

        else:
            absolute_address = self._generic_region_map.absolutize(region_id, relative_address)

        stack_base = self._stack_region_map.stack_base

        if (relative_address <= stack_base and
                relative_address > stack_base - self._stack_size) or \
                (target_region is not None and target_region.startswith('stack_')):
            # The absolute address seems to be in the stack region.
            # Map it to stack
            new_region_id, new_relative_address, related_function_addr = self._stack_region_map.relativize(
                absolute_address,
                target_region_id=target_region
            )

            return AddressWrapper(new_region_id, self._region_base(new_region_id), new_relative_address, True,
                                  related_function_addr
                                  )

        else:
            new_region_id, new_relative_address, related_function_addr = self._generic_region_map.relativize(
                absolute_address,
                target_region_id=target_region
            )

            return AddressWrapper(new_region_id, self._region_base(new_region_id), new_relative_address, False, None)

    def set_state(self, state):
        """
        Overriding the SimStatePlugin.set_state() method

        :param state: A SimState object
        :return: None
        """
        self.state = state
        for _,v in self._regions.items():
            v.set_state(state)

    def normalize_address(self, addr, is_write=False, convert_to_valueset=False, target_region=None): #pylint:disable=arguments-differ
        """
        Convert a ValueSet object into a list of addresses.

        :param addr: A ValueSet object (which describes an address)
        :param is_write: Is this address used in a write or not
        :param convert_to_valueset: True if you want to have a list of ValueSet instances instead of AddressWrappers,
                                    False otherwise
        :param target_region: Which region to normalize the address to. To leave the decision to SimuVEX, set it to None
        :return: A list of AddressWrapper or ValueSet objects
        """

        if type(addr) in (int, long):
            addr = self.state.se.BVV(addr, self.state.arch.bits)

        addr_with_regions = self._normalize_address_type(addr)
        address_wrappers = [ ]

        for region, addr_si in addr_with_regions:
            if is_write:
                concrete_addrs = addr_si.eval(WRITE_TARGETS_LIMIT)
                if len(concrete_addrs) == WRITE_TARGETS_LIMIT:
                    self.state.log.add_event('mem', message='too many targets to write to. address = %s' % addr_si)
            else:
                concrete_addrs = addr_si.eval(READ_TARGETS_LIMIT)
                if len(concrete_addrs) == READ_TARGETS_LIMIT:
                    self.state.log.add_event('mem', message='too many targets to read from. address = %s' % addr_si)

            for c in concrete_addrs:
                aw = self._normalize_address(region, c, target_region=target_region)
                address_wrappers.append(aw)

        if convert_to_valueset:
            return [ i.to_valueset(self.state) for i in address_wrappers ]

        else:
            return address_wrappers

    def _normalize_address_type(self, addr): #pylint:disable=no-self-use
        """
        Convert address of different types to a list of mapping between region IDs and offsets (strided intervals).

        :param claripy.ast.Base addr: Address to convert
        :return: A list of mapping between region IDs and offsets.
        :rtype: dict
        """

        addr_e = _raw_ast(addr)

        if isinstance(addr_e, (claripy.bv.BVV, claripy.vsa.StridedInterval, claripy.vsa.ValueSet)):
            raise SimMemoryError('_normalize_address_type() does not take claripy models.')

        if isinstance(addr_e, claripy.ast.Base):
            if not isinstance(addr_e._model_vsa, ValueSet):
                # Convert it to a ValueSet first by annotating it
                addr_e = addr_e.annotate(RegionAnnotation('global', 0, addr_e._model_vsa))

            return addr_e._model_vsa.items()

        else:
            raise SimMemoryError('Unsupported address type %s' % type(addr_e))

    # FIXME: symbolic_length is also a hack!
    def _store(self, req):
        address_wrappers = self.normalize_address(req.addr, is_write=True, convert_to_valueset=False)
        req.actual_addresses = [ ]
        req.fallback_values = [ ]
        req.symbolic_sized_values = [ ]
        req.conditional_values = [ ]
        req.simplified_values = [ ]
        req.stored_values = [ ]

        for aw in address_wrappers:
            r = self._do_store(aw.address, req.data, aw.region, req.endness,
                  is_stack=aw.is_on_stack, related_function_addr=aw.function_address)

            if r.completed:
                req.completed = True

                req.actual_addresses.append(aw.to_valueset(self.state))
                req.constraints.extend(r.constraints)
                req.fallback_values.extend(r.fallback_values)
                req.symbolic_sized_values.extend(r.symbolic_sized_values)
                req.conditional_values.extend(r.conditional_values)
                req.simplified_values.extend(r.simplified_values)
                req.stored_values.extend(r.stored_values)

        # No constraints are generated...
        return req

    def _do_store(self, addr, data, key, endness, is_stack=False, related_function_addr=None):
        if type(key) is not str:
            raise Exception('Incorrect type %s of region_key' % type(key))
        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self._regions[key] = MemoryRegion(
                key,
                self.state,
                is_stack=is_stack,
                related_function_addr=related_function_addr,
                endness=self.endness
            )

        r = MemoryStoreRequest(addr, data=data, endness=endness)
        self._regions[key].store(r, bbl_addr, stmt_id, ins_addr)

        return r

    def _load(self, addr, size, condition=None, fallback=None):
        address_wrappers = self.normalize_address(addr, is_write=False)

        if isinstance(size, claripy.ast.BV) and isinstance(size._model_vsa, ValueSet):
            # raise Exception('Unsupported type %s for size' % type(size._model_vsa))
            l.warning('_load(): size %s is a ValueSet. Something is wrong.', size)
            if self.state.scratch.ins_addr is not None:
                var_name = 'invalid_read_%d_%#x' % (
                    invalid_read_ctr.next(),
                    self.state.scratch.ins_addr
                )
            else:
                var_name = 'invalid_read_%d_None' % invalid_read_ctr.next()

            return address_wrappers, self.state.se.Unconstrained(var_name, 32), [True]

        val = None

        if len(address_wrappers) > 1 and AVOID_MULTIVALUED_READS in self.state.options:
            val = self.state.se.Unconstrained('unconstrained_read', size * 8)
            return address_wrappers, val, [True]

        for aw in address_wrappers:
            new_val = self._do_load(aw.address, size, aw.region,
                                 is_stack=aw.is_on_stack, related_function_addr=aw.function_address)

            if val is None:
                if KEEP_MEMORY_READS_DISCRETE in self.state.options:
                    val = self.state.se.DSIS(to_conv=new_val, max_card=100000)
                else:
                    val = new_val
            else:
                val = val.union(new_val)

        return address_wrappers, val, [True]

    def _do_load(self, addr, size, key, is_stack=False, related_function_addr=None):
        if type(key) is not str:
            raise Exception('Incorrect type %s of region_key' % type(key))

        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self._regions[key] = MemoryRegion(key, state=self.state, is_stack=is_stack, related_function_addr=related_function_addr, endness=self.endness)

        return self._regions[key].load(addr, size, bbl_addr, stmt_id, ins_addr)

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1):
        if type(addr) in (int, long):
            addr = self.state.se.BVV(addr, self.state.arch.bits)

        addr = self._normalize_address_type(addr)

        # TODO: For now we are only finding in one region!
        for region, si in addr:
            si = self.state.se.SI(to_conv=si)
            r, s, i = self._regions[region].memory.find(si, what, max_search=max_search,
                                                        max_symbolic_bytes=max_symbolic_bytes, default=default,
                                                        step=step
                                                        )
            # Post process r so that it's still a ValueSet variable

            region_base_addr = self._region_base(region)

            r = self.state.se.ValueSet(r.size(), region, region_base_addr, r._model_vsa)

            return r, s, i

    def get_segments(self, addr, size):
        """
        Get a segmented memory region based on AbstractLocation information available from VSA.

        Here are some assumptions to make this method fast:
            - The entire memory region [addr, addr + size] is located within the same MemoryRegion
            - The address 'addr' has only one concrete value. It cannot be concretized to multiple values.

        :param addr: An address
        :param size: Size of the memory area in bytes
        :return: An ordered list of sizes each segment in the requested memory region
        """

        address_wrappers = self.normalize_address(addr, is_write=False)
        # assert len(address_wrappers) > 0

        aw = address_wrappers[0]
        region_id = aw.region

        if region_id in self.regions:
            region = self.regions[region_id]
            alocs = region.get_abstract_locations(aw.address, size)

            # Collect all segments and sort them
            segments = [ ]
            for aloc in alocs:
                segments.extend(aloc.segments)
            segments = sorted(segments, key=lambda x: x.offset)

            # Remove all overlapping segments
            processed_segments = [ ]
            last_seg = None
            for seg in segments:
                if last_seg is None:
                    last_seg = seg
                    processed_segments.append(seg)
                else:
                    # Are they overlapping?
                    if seg.offset >= last_seg.offset and seg.offset <= last_seg.offset + size:
                        continue
                    processed_segments.append(seg)

            # Make it a list of sizes
            sizes = [ ]
            next_pos = aw.address
            for seg in processed_segments:
                if seg.offset > next_pos:
                    gap = seg.offset - next_pos
                    assert gap > 0
                    sizes.append(gap)
                    next_pos += gap
                if seg.size + next_pos > aw.address + size:
                    sizes.append(aw.address + size - next_pos)
                    next_pos += aw.address + size - next_pos
                else:
                    sizes.append(seg.size)
                    next_pos += seg.size

            if len(sizes) == 0:
                return [ size ]
            return sizes
        else:
            # The region doesn't exist. Then there is only one segment!
            return [ size ]

    def copy(self):
        """
        Make a copy of this SimAbstractMemory object
        :return:
        """
        am = SimAbstractMemory(memory_id=self._memory_id, endness=self.endness)
        for region_id, region in self._regions.items():
            am._regions[region_id] = region.copy()
        am._stack_region_map = self._stack_region_map.copy()
        am._generic_region_map = self._generic_region_map.copy()
        am._stack_size = self._stack_size
        return am

    def merge(self, others, merge_conditions):
        """
        Merge this guy with another SimAbstractMemory instance
        """
        merging_occurred = False

        for o in others:
            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    merging_occurred |= self._regions[region_id].merge([region], merge_conditions)
                else:
                    merging_occurred = True
                    self._regions[region_id] = region

        return merging_occurred

    def widen(self, others):
        widening_occurred = False
        for o in others:
            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    widening_occurred |= self._regions[region_id].widen([ region ])
                else:
                    widening_occurred = True
                    self._regions[region_id] = region

        return widening_occurred

    def __contains__(self, dst):
        if type(dst) in (int, long):
            dst = self.state.se.BVV(dst, self.state.arch.bits)

        addrs = self._normalize_address_type(dst)


        for region, addr in addrs:
            address_wrapper = self._normalize_address(region, addr.min)

            return address_wrapper.address in self.regions[address_wrapper.region]

        return False

    def was_written_to(self, dst):

        if type(dst) in (int, long):
            dst = self.state.se.BVV(dst, self.state.arch.bits)

        addrs = self._normalize_address_type(dst)

        for region, addr in addrs:
            address_wrapper = self._normalize_address(region, addr.min)

            return self.regions[address_wrapper.region].was_written_to(address_wrapper.address)

        return False

    def dbg_print(self):
        """
        Print out debugging information
        """
        for region_id, region in self.regions.items():
            print "Region [%s]:" % region_id
            region.dbg_print(indent=2)
