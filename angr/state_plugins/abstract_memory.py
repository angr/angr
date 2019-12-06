import logging
import copy
from itertools import count

import claripy
from claripy.vsa import ValueSet, RegionAnnotation

from ..storage.memory import SimMemory, AddressWrapper, MemoryStoreRequest
from ..errors import SimMemoryError, SimAbstractMemoryError
from ..sim_options import KEEP_MEMORY_READS_DISCRETE, AVOID_MULTIVALUED_READS, REGION_MAPPING, \
    CONSERVATIVE_READ_STRATEGY, CONSERVATIVE_WRITE_STRATEGY, HYBRID_SOLVER, APPROXIMATE_FIRST
from .symbolic_memory import SimSymbolicMemory
from ..state_plugins.sim_action_object import _raw_ast


l = logging.getLogger(name=__name__)

WRITE_TARGETS_LIMIT = 2048
READ_TARGETS_LIMIT = 4096

#pylint:disable=unidiomatic-typecheck

invalid_read_ctr = count()

class MemoryRegion:
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
        for aloc in self._alocs.values():
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

    @SimMemory.memo
    def copy(self, memo):
        r = MemoryRegion(self._id, self.state,
                         is_stack=self._is_stack,
                         related_function_addr=self._related_function_addr,
                         init_memory=False, endness=self._endness)
        r._memory = self.memory.copy(memo)
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
            self._alocs[aloc_id] = self.state.solver.AbstractLocation(bbl_addr,
                                                                  stmt_id,
                                                                  self.id,
                                                                  region_offset=request.addr,
                                                                  size=len(request.data) // self.state.arch.byte_width)
            return self.memory._store(request)
        else:
            if self._alocs[aloc_id].update(request.addr, len(request.data) // self.state.arch.byte_width):
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
        for aloc_id, aloc in other_region.alocs.items():
            if aloc_id not in self.alocs:
                self.alocs[aloc_id] = aloc.copy()
                merging_occurred = True
            else:
                # Update it
                merging_occurred |= self.alocs[aloc_id].merge(aloc)
        return merging_occurred

    def merge(self, others, merge_conditions, common_ancestor=None):
        merging_occurred = False
        for other_region in others:
            merging_occurred |= self._merge_alocs(other_region)
            merging_occurred |= self.memory.merge(
                [other_region.memory], merge_conditions, common_ancestor=common_ancestor
            )
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
        print("%sA-locs:" % (" " * indent))
        for aloc_id, aloc in self._alocs.items():
            print("%s<0x%x> %s" % (" " * (indent + 2), aloc_id, aloc))

        print("%sMemory:" % (" " * indent))
        self.memory.dbg_print(indent=indent + 2)

class SimAbstractMemory(SimMemory): #pylint:disable=abstract-method
    """
    This is an implementation of the abstract store in paper [TODO].

    Some differences:

        - For stack variables, we map the absolute stack address to each region so
          that we can effectively trace stack accesses. When tracing into a new
          function, you should call set_stack_address_mapping() to create a new mapping.
          When exiting from a function, you should cancel the previous mapping by
          calling unset_stack_address_mapping().
          Currently this is only used for stack!
    """
    def __init__(self, memory_backer=None, memory_id="mem", endness=None, stack_region_map=None,
                 generic_region_map=None):
        SimMemory.__init__(self,
                           endness=endness,
                           stack_region_map=stack_region_map,
                           generic_region_map=generic_region_map,
                           )

        self._regions = {}
        self._stack_size = None

        self._memory_id = memory_id
        self.id = self._memory_id

        # Since self.state is None at this time (self.state will be set to the real SimState instance later when
        # self.set_state() is called), we just save the backer argument to a temporary variable, and then initialize it
        # later in self.set_state() method.
        self._temp_backer = memory_backer

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

    def set_stack_size(self, size):
        self._stack_size = size

    def create_region(self, key, state, is_stack, related_function_addr, endness, backer_dict=None):
        """
        Create a new MemoryRegion with the region key specified, and store it to self._regions.

        :param key: a string which is the region key
        :param state: the SimState instance
        :param bool is_stack: Whether this memory region is on stack. True/False
        :param related_function_addr: Which function first creates this memory region. Just for reference.
        :param endness: The endianness.
        :param backer_dict: The memory backer object.
        :return: None
        """

        self._regions[key] = MemoryRegion(key,
                                          state=state,
                                          is_stack=is_stack,
                                          related_function_addr=related_function_addr,
                                          endness=endness,
                                          backer_dict=backer_dict,
                                          )

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

        if stack_base - self._stack_size < relative_address <= stack_base and \
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

        # Sanity check
        if REGION_MAPPING not in state.options:
            # add REGION_MAPPING into state.options
            l.warning('Option "REGION_MAPPING" must be enabled when using SimAbstractMemory as the memory model. '
                      'The option is added to state options as a courtesy.'
                      )
            state.options.add(REGION_MAPPING)

        SimMemory.set_state(self, state)

        for _,v in self._regions.items():
            v.set_state(state)

        # Delayed initialization of backer argument from __init__
        if self._temp_backer is not None:
            for region, backer_dict in self._temp_backer.items():
                self._regions[region] = MemoryRegion(region, self.state,
                                                     init_memory=True,
                                                     backer_dict=backer_dict,
                                                     endness=self.endness
                                                     )
            self._temp_backer = None

    def normalize_address(self, addr, is_write=False, convert_to_valueset=False, target_region=None, condition=None): #pylint:disable=arguments-differ
        """
        Convert a ValueSet object into a list of addresses.

        :param addr: A ValueSet object (which describes an address)
        :param is_write: Is this address used in a write or not
        :param convert_to_valueset: True if you want to have a list of ValueSet instances instead of AddressWrappers,
                                    False otherwise
        :param target_region: Which region to normalize the address to. To leave the decision to SimuVEX, set it to None
        :return: A list of AddressWrapper or ValueSet objects
        """
        targets_limit = WRITE_TARGETS_LIMIT if is_write else READ_TARGETS_LIMIT

        if type(addr) is not int:
            for constraint in self.state.solver.constraints:
                if getattr(addr, 'variables', set()) & constraint.variables:
                    addr = self._apply_condition_to_symbolic_addr(addr, constraint)

        # Apply the condition if necessary
        if condition is not None:
            addr = self._apply_condition_to_symbolic_addr(addr, condition)

        if type(addr) is int:
            addr = self.state.solver.BVV(addr, self.state.arch.bits)

        addr_with_regions = self._normalize_address_type(addr)
        address_wrappers = [ ]

        for region, addr_si in addr_with_regions:
            concrete_addrs = addr_si.eval(targets_limit)

            if len(concrete_addrs) == targets_limit and HYBRID_SOLVER in self.state.options:
                exact = True if APPROXIMATE_FIRST not in self.state.options else None
                solutions = self.state.solver.eval_upto(addr, targets_limit, exact=exact)

                if len(solutions) < len(concrete_addrs):
                    concrete_addrs = [addr_si.intersection(s).eval(1)[0] for s in solutions]

            if len(concrete_addrs) == targets_limit:
                self.state.history.add_event('mem', message='concretized too many targets. address = %s' % addr_si)

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
            raise SimAbstractMemoryError('Unsupported address type %s' % type(addr_e))

    # FIXME: symbolic_length is also a hack!
    def _store(self, req):
        address_wrappers = self.normalize_address(req.addr, is_write=True, convert_to_valueset=False)
        if len(address_wrappers) == WRITE_TARGETS_LIMIT and CONSERVATIVE_WRITE_STRATEGY in self.state.options:
            return req

        req.actual_addresses = [ ]
        req.stored_values = [ ]

        for aw in address_wrappers:
            r = self._do_store(aw.address, req.data, aw.region, req.endness,
                  is_stack=aw.is_on_stack, related_function_addr=aw.function_address)

            if r.completed:
                req.completed = True

                req.actual_addresses.append(aw.to_valueset(self.state))
                req.constraints.extend(r.constraints)
                req.stored_values.extend(r.stored_values)

        # No constraints are generated...
        return req

    def _do_store(self, addr, data, key, endness, is_stack=False, related_function_addr=None):
        if type(key) is not str:
            raise Exception('Incorrect type %s of region_key' % type(key))
        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self.create_region(key, self.state, is_stack, related_function_addr, self.endness)

        r = MemoryStoreRequest(addr, data=data, endness=endness)
        self._regions[key].store(r, bbl_addr, stmt_id, ins_addr)

        return r

    def _load(self, addr, size, condition=None, fallback=None,
            inspect=True, events=True, ret_on_segv=False):
        address_wrappers = self.normalize_address(addr, is_write=False, condition=condition)

        if isinstance(size, claripy.ast.BV) and isinstance(size._model_vsa, ValueSet):
            # raise Exception('Unsupported type %s for size' % type(size._model_vsa))
            l.warning('_load(): size %s is a ValueSet. Something is wrong.', size)
            if self.state.scratch.ins_addr is not None:
                var_name = 'invalid_read_%d_%#x' % (
                    next(invalid_read_ctr),
                    self.state.scratch.ins_addr
                )
            else:
                var_name = 'invalid_read_%d_None' % next(invalid_read_ctr)

            return address_wrappers, self.state.solver.Unconstrained(var_name, 32), [True]

        val = None

        if (len(address_wrappers) > 1 and AVOID_MULTIVALUED_READS in self.state.options) or \
                (len(address_wrappers) == READ_TARGETS_LIMIT and CONSERVATIVE_READ_STRATEGY in self.state.options):
            val = self.state.solver.Unconstrained('unconstrained_read', size * self.state.arch.byte_width)
            return address_wrappers, val, [True]

        for aw in address_wrappers:
            new_val = self._do_load(aw.address, size, aw.region,
                                    is_stack=aw.is_on_stack,
                                    related_function_addr=aw.function_address,
                                    )

            if val is None:
                if KEEP_MEMORY_READS_DISCRETE in self.state.options:
                    val = self.state.solver.DSIS(to_conv=new_val, max_card=100000)
                else:
                    val = new_val
            else:
                val = val.union(new_val)

        if val is None:
            # address_wrappers is empty - we cannot concretize the address in static mode.
            # ensure val is not None
            val = self.state.solver.Unconstrained('invalid_read_%d_%d' % (next(invalid_read_ctr), size),
                                                  size * self.state.arch.byte_width)

        return address_wrappers, val, [True]

    def _do_load(self, addr, size, key, is_stack=False, related_function_addr=None):
        if type(key) is not str:
            raise Exception('Incorrect type %s of region_key' % type(key))

        bbl_addr, stmt_id, ins_addr = self.state.scratch.bbl_addr, self.state.scratch.stmt_idx, self.state.scratch.ins_addr

        if key not in self._regions:
            self.create_region(key, self.state, is_stack, related_function_addr, self.endness)

        return self._regions[key].load(addr, size, bbl_addr, stmt_id, ins_addr)

    def _apply_condition_to_symbolic_addr(self, addr, condition):

        _, converted = self.state.solver.constraint_to_si(condition)
        for original_expr, constrained_expr in converted:
            addr = addr.replace(original_expr, constrained_expr)
        return addr

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True,
                      disable_actions=False):
        src_memory = self if src_memory is None else src_memory
        dst_memory = self if dst_memory is None else dst_memory

        max_size = self.state.solver.max_int(size)
        if max_size == 0:
            return None, [ ]

        data = src_memory.load(src, max_size, inspect=inspect, disable_actions=disable_actions)
        dst_memory.store(dst, data, size=size, condition=condition, inspect=inspect, disable_actions=disable_actions)
        return data

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1,
             disable_actions=False, inspect=True, chunk_size=None):
        if type(addr) is int:
            addr = self.state.solver.BVV(addr, self.state.arch.bits)

        addr = self._normalize_address_type(addr)

        # TODO: For now we are only finding in one region!
        for region, si in addr:
            si = self.state.solver.SI(to_conv=si)
            r, s, i = self._regions[region].memory.find(si, what, max_search=max_search,
                                                        max_symbolic_bytes=max_symbolic_bytes, default=default,
                                                        step=step
                                                        )
            # Post process r so that it's still a ValueSet variable

            region_base_addr = self._region_base(region)

            r = self.state.solver.ValueSet(r.size(), region, region_base_addr, r._model_vsa)

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


            if not sizes:
                return [ size ]
            return sizes
        else:
            # The region doesn't exist. Then there is only one segment!
            return [ size ]

    @SimMemory.memo
    def copy(self, memo):
        """
        Make a copy of this SimAbstractMemory object
        :return:
        """
        am = SimAbstractMemory(
            memory_id=self._memory_id,
            endness=self.endness,
            stack_region_map=self._stack_region_map,
            generic_region_map=self._generic_region_map
        )
        for region_id, region in self._regions.items():
            am._regions[region_id] = region.copy(memo)
        am._stack_size = self._stack_size
        return am

    def merge(self, others, merge_conditions, common_ancestor=None):
        """
        Merge this guy with another SimAbstractMemory instance
        """
        merging_occurred = False

        for o in others:
            for region_id, region in o._regions.items():
                if region_id in self._regions:
                    merging_occurred |= self._regions[region_id].merge(
                        [region], merge_conditions, common_ancestor=common_ancestor
                    )
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
        if type(dst) is int:
            dst = self.state.solver.BVV(dst, self.state.arch.bits)

        addrs = self._normalize_address_type(dst)

        for region, addr in addrs:
            address_wrapper = self._normalize_address(region, addr.min)

            return address_wrapper.address in self.regions[address_wrapper.region]

        return False

    def map_region(self, addr, length, permissions, init_zero=False): # pylint: disable=no-self-use,unused-argument
        """
        Map a number of pages at address `addr` with permissions `permissions`.
        :param addr: address to map the pages at
        :param length: length in bytes of region to map, will be rounded upwards to the page size
        :param permissions: AST of permissions to map, will be a bitvalue representing flags
        :param init_zero: Initialize page with zeros
        """
        l.warning('map_region() is not yet supported by SimAbstractMmeory.')

    def unmap_region(self, addr, length): # pylint: disable=no-self-use,unused-argument
        """
        Unmap a number of pages at address `addr`
        :param addr: address to unmap the pages at
        :param length: length in bytes of region to map, will be rounded upwards to the page size
        """
        l.warning('unmap_region() is not yet supported by SimAbstractMmeory.')

    def was_written_to(self, dst):

        if type(dst) is int:
            dst = self.state.solver.BVV(dst, self.state.arch.bits)

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
            print("Region [%s]:" % region_id)
            region.dbg_print(indent=2)


from ..sim_state import SimState
SimState.register_default('abs_memory', SimAbstractMemory)
