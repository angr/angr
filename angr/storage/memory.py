import logging
import claripy
from sortedcontainers import SortedDict
from archinfo.arch_arm import is_arm_arch
from ..state_plugins.plugin import SimStatePlugin


l = logging.getLogger(name=__name__)

stn_map = { 'st%d' % n: n for n in range(8) }
tag_map = { 'tag%d' % n: n for n in range(8) }

DUMMY_SYMBOLIC_READ_VALUE = 0xc0deb4be


class AddressWrapper(object):
    """
    AddressWrapper is used in SimAbstractMemory, which provides extra meta information for an address (or a ValueSet
    object) that is normalized from an integer/BVV/StridedInterval.
    """

    def __init__(self, region, region_base_addr, address, is_on_stack, function_address):
        """
        Constructor for the class AddressWrapper.

        :param str region:             Name of the memory regions it belongs to.
        :param int region_base_addr:   Base address of the memory region
        :param address:                An address (not a ValueSet object).
        :param bool is_on_stack:       Whether this address is on a stack region or not.
        :param int function_address:   Related function address (if any).
        """
        self.region = region
        self.region_base_addr = region_base_addr
        self.address = address
        self.is_on_stack = is_on_stack
        self.function_address = function_address

    def __hash__(self):
        return hash((self.region, self.address))

    def __eq__(self, other):
        return self.region == other.region and self.address == other.address

    def __repr__(self):
        return "<%s> %s" % (self.region, hex(self.address))

    def to_valueset(self, state):
        """
        Convert to a ValueSet instance

        :param state: A state
        :return: The converted ValueSet instance
        """
        return state.solver.VS(state.arch.bits, self.region, self.region_base_addr, self.address)

class RegionDescriptor(object):
    """
    Descriptor for a memory region ID.
    """
    def __init__(self, region_id, base_address, related_function_address=None):
        self.region_id = region_id
        self.base_address = base_address
        self.related_function_address = related_function_address

    def __repr__(self):
        return "<%s - %#x>" % (
            self.region_id,
            self.related_function_address if self.related_function_address is not None else 0
        )

class RegionMap(object):
    """
    Mostly used in SimAbstractMemory, RegionMap stores a series of mappings between concrete memory address ranges and
    memory regions, like stack frames and heap regions.
    """

    def __init__(self, is_stack):
        """
        Constructor

        :param is_stack:    Whether this is a region map for stack frames or not. Different strategies apply for stack
                            regions.
        """
        self.is_stack = is_stack

        # A sorted list, which maps stack addresses to region IDs
        self._address_to_region_id = SortedDict()
        # A dict, which maps region IDs to memory address ranges
        self._region_id_to_address = { }

    #
    # Properties
    #

    def __repr__(self):
        return "RegionMap<%s>" % (
            "S" if self.is_stack else "H"
        )

    @property
    def is_empty(self):
        return len(self._address_to_region_id) == 0

    @property
    def stack_base(self):
        if not self.is_stack:
            raise SimRegionMapError('Calling "stack_base" on a non-stack region map.')

        return next(self._address_to_region_id.irange(reverse=True))

    @property
    def region_ids(self):
        return self._region_id_to_address.keys()

    #
    # Public methods
    #

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        r = RegionMap(is_stack=self.is_stack)

        # A shallow copy should be enough, since we never modify any RegionDescriptor object in-place
        r._address_to_region_id = self._address_to_region_id.copy()
        r._region_id_to_address = self._region_id_to_address.copy()

        return r

    def map(self, absolute_address, region_id, related_function_address=None):
        """
        Add a mapping between an absolute address and a region ID. If this is a stack region map, all stack regions
        beyond (lower than) this newly added regions will be discarded.

        :param absolute_address:            An absolute memory address.
        :param region_id:                   ID of the memory region.
        :param related_function_address:    A related function address, mostly used for stack regions.
        """

        if self.is_stack:
            # Sanity check
            if not region_id.startswith('stack_'):
                raise SimRegionMapError('Received a non-stack memory ID "%d" in a stack region map' % region_id)

            # Remove all stack regions that are lower than the one to add
            while True:
                try:
                    addr = next(self._address_to_region_id.irange(maximum=absolute_address, reverse=True))
                    descriptor = self._address_to_region_id[addr]
                    # Remove this mapping
                    del self._address_to_region_id[addr]
                    # Remove this region ID from the other mapping
                    del self._region_id_to_address[descriptor.region_id]
                except StopIteration:
                    break

        else:
            if absolute_address in self._address_to_region_id:
                descriptor = self._address_to_region_id[absolute_address]
                # Remove this mapping
                del self._address_to_region_id[absolute_address]
                del self._region_id_to_address[descriptor.region_id]

        # Add this new region mapping
        desc = RegionDescriptor(
            region_id,
            absolute_address,
            related_function_address=related_function_address
        )

        self._address_to_region_id[absolute_address] = desc
        self._region_id_to_address[region_id] = desc

    def unmap_by_address(self, absolute_address):
        """
        Removes a mapping based on its absolute address.

        :param absolute_address: An absolute address
        """

        desc = self._address_to_region_id[absolute_address]
        del self._address_to_region_id[absolute_address]
        del self._region_id_to_address[desc.region_id]

    def absolutize(self, region_id, relative_address):
        """
        Convert a relative address in some memory region to an absolute address.

        :param region_id:           The memory region ID
        :param relative_address:    The relative memory offset in that memory region
        :return:                    An absolute address if converted, or an exception is raised when region id does not
                                    exist.
        """

        if region_id == 'global':
            # The global region always bases 0
            return relative_address

        if region_id not in self._region_id_to_address:
            raise SimRegionMapError('Non-existent region ID "%s"' % region_id)

        base_address = self._region_id_to_address[region_id].base_address
        return base_address + relative_address

    def relativize(self, absolute_address, target_region_id=None):
        """
        Convert an absolute address to the memory offset in a memory region.

        Note that if an address belongs to heap region is passed in to a stack region map, it will be converted to an
        offset included in the closest stack frame, and vice versa for passing a stack address to a heap region.
        Therefore you should only pass in address that belongs to the same category (stack or non-stack) of this region
        map.

        :param absolute_address:    An absolute memory address
        :return:                    A tuple of the closest region ID, the relative offset, and the related function
                                    address.
        """

        if target_region_id is None:
            if self.is_stack:
                # Get the base address of the stack frame it belongs to
                base_address = next(self._address_to_region_id.irange(minimum=absolute_address, reverse=False))

            else:
                try:
                    base_address = next(self._address_to_region_id.irange(maximum=absolute_address, reverse=True))

                except StopIteration:
                    # Not found. It belongs to the global region then.
                    return 'global', absolute_address, None

            descriptor = self._address_to_region_id[base_address]

        else:
            if target_region_id == 'global':
                # Just return the absolute address
                return 'global', absolute_address, None

            if target_region_id not in self._region_id_to_address:
                raise SimRegionMapError('Trying to relativize to a non-existent region "%s"' % target_region_id)

            descriptor = self._region_id_to_address[target_region_id]
            base_address = descriptor.base_address

        return descriptor.region_id, absolute_address - base_address, descriptor.related_function_address

class MemoryStoreRequest(object):
    """
    A MemoryStoreRequest is used internally by SimMemory to track memory request data.
    """

    def __init__(self, addr, data=None, size=None, condition=None, endness=None):
        self.addr = addr
        self.data = data
        self.size = size
        self.condition = condition
        self.endness = endness

        # was this store done?
        self.completed = False

        # stuff that's determined during handling
        self.actual_addresses = None
        self.constraints = [ ]

        self.stored_values = None

    def _adjust_condition(self, state):
        self.condition = state._adjust_condition(self.condition)


class SimMemory(SimStatePlugin):
    """
    Represents the memory space of the process.
    """
    def __init__(self, endness=None, abstract_backer=None, stack_region_map=None, generic_region_map=None):
        SimStatePlugin.__init__(self)
        self.id = None
        self.endness = "Iend_BE" if endness is None else endness

        # Boolean or None. Indicates whether this memory is internally used inside SimAbstractMemory
        self._abstract_backer = abstract_backer

        #
        # These are some performance-critical thresholds
        #

        # The maximum range of a normal write operation. If an address range is greater than this number,
        # SimMemory will simply concretize it to a single value. Note that this is only relevant when
        # the "symbolic" concretization strategy is enabled for writes.
        self._write_address_range = 128
        self._write_address_range_approx = 128

        # The maximum range of a symbolic read address. If an address range is greater than this number,
        # SimMemory will simply concretize it.
        self._read_address_range = 1024
        self._read_address_range_approx = 1024

        # The maximum size of a symbolic-sized operation. If a size maximum is greater than this number,
        # SimMemory will constrain it to this number. If the size minimum is greater than this
        # number, a SimMemoryLimitError is thrown.
        self._maximum_symbolic_size = 8 * 1024
        self._maximum_symbolic_size_approx = 4*1024

        # Same, but for concrete writes
        self._maximum_concrete_size = 0x1000000

        # Save those arguments first. Since self.state is empty at this moment, we delay the initialization of region
        # maps until set_state() is called.
        self._temp_stack_region_map = stack_region_map
        self._temp_generic_region_map = generic_region_map

        self._stack_region_map = None
        self._generic_region_map = None

    @property
    def category(self):
        """
        Return the category of this SimMemory instance. It can be one of the three following categories: reg, mem,
        or file.
        """

        if self.id in ('reg', 'mem'):
            return self.id

        elif self._abstract_backer:
            return 'mem'

        elif self.id.startswith('file'):
            return 'file'

        else:
            raise SimMemoryError('Unknown SimMemory category for memory_id "%s"' % self.id)

    @property
    def variable_key_prefix(self):
        s = self.category
        if s == 'file':
            return (s, self.id)
        return (s,)

    def set_state(self, state):
        """
        Call the set_state method in SimStatePlugin class, and then perform the delayed initialization.

        :param state: The SimState instance
        """
        SimStatePlugin.set_state(self, state)

        # Delayed initialization
        stack_region_map, generic_region_map = self._temp_stack_region_map, self._temp_generic_region_map

        if stack_region_map or generic_region_map:
            # Inherited from its parent
            self._stack_region_map = stack_region_map.copy()
            self._generic_region_map = generic_region_map.copy()

        else:
            if not self._abstract_backer and o.REGION_MAPPING in self.state.options:
                # Only the top-level SimMemory instance can have region maps.
                self._stack_region_map = RegionMap(True)
                self._generic_region_map = RegionMap(False)

            else:
                self._stack_region_map = None
                self._generic_region_map = None

    def _resolve_location_name(self, name, is_write=False):

        # Delayed load so SimMemory does not rely on SimEngines
        from angr.engines.vex.claripy.ccall import _get_flags

        if self.category == 'reg':
            if self.state.arch.name in ('X86', 'AMD64'):
                if name in stn_map:
                    return (((stn_map[name] + self.load('ftop')) & 7) << 3) + self.state.arch.registers['fpu_regs'][0], 8
                elif name in tag_map:
                    return ((tag_map[name] + self.load('ftop')) & 7) + self.state.arch.registers['fpu_tags'][0], 1
                elif name in ('flags', 'eflags', 'rflags'):
                    # we tweak the state to convert the vex condition registers into the flags register
                    if not is_write: # this work doesn't need to be done if we're just gonna overwrite it
                        self.store('cc_dep1', _get_flags(self.state))
                    self.store('cc_op', 0) # OP_COPY
                    return self.state.arch.registers['cc_dep1'][0], self.state.arch.bytes
            if is_arm_arch(self.state.arch):
                if name == 'flags':
                    if not is_write:
                        self.store('cc_dep1', _get_flags(self.state))
                    self.store('cc_op', 0)
                    return self.state.arch.registers['cc_dep1'][0], self.state.arch.bytes

            return self.state.arch.registers[name]
        elif name[0] == '*':
            return self.state.registers.load(name[1:]), None
        else:
            raise SimMemoryError("Trying to address memory with a register name.")

    def _convert_to_ast(self, data_e, size_e=None):
        """
        Make an AST out of concrete @data_e
        """
        if type(data_e) is bytes:
            # Convert the string into a BVV, *regardless of endness*
            bits = len(data_e) * self.state.arch.byte_width
            data_e = self.state.solver.BVV(data_e, bits)
        elif type(data_e) is int:
            data_e = self.state.solver.BVV(data_e, size_e*self.state.arch.byte_width if size_e is not None
                                       else self.state.arch.bits)
        else:
            data_e = data_e.raw_to_bv()

        return data_e

    def set_stack_address_mapping(self, absolute_address, region_id, related_function_address=None):
        """
        Create a new mapping between an absolute address (which is the base address of a specific stack frame) and a
        region ID.

        :param absolute_address: The absolute memory address.
        :param region_id: The region ID.
        :param related_function_address: Related function address.
        """
        if self._stack_region_map is None:
            raise SimMemoryError('Stack region map is not initialized.')
        self._stack_region_map.map(absolute_address, region_id, related_function_address=related_function_address)

    def unset_stack_address_mapping(self, absolute_address):
        """
        Remove a stack mapping.

        :param absolute_address: An absolute memory address, which is the base address of the stack frame to destroy.
        """
        if self._stack_region_map is None:
            raise SimMemoryError('Stack region map is not initialized.')
        self._stack_region_map.unmap_by_address(absolute_address)

    def stack_id(self, function_address):
        """
        Return a memory region ID for a function. If the default region ID exists in the region mapping, an integer
        will appended to the region name. In this way we can handle recursive function calls, or a function that
        appears more than once in the call frame.

        This also means that `stack_id()` should only be called when creating a new stack frame for a function. You are
        not supposed to call this function every time you want to map a function address to a stack ID.

        :param int function_address: Address of the function.
        :return: ID of the new memory region.
        :rtype: str
        """
        region_id = 'stack_0x%x' % function_address

        # deduplication
        region_ids = self._stack_region_map.region_ids
        if region_id not in region_ids:
            return region_id
        else:
            for i in range(0, 2000):
                new_region_id = region_id + '_%d' % i
                if new_region_id not in region_ids:
                    return new_region_id
            raise SimMemoryError('Cannot allocate region ID for function %#08x - recursion too deep' % function_address)

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False):
        """
        Stores content into memory.

        :param addr:        A claripy expression representing the address to store at.
        :param data:        The data to store (claripy expression or something convertable to a claripy expression).
        :param size:        A claripy expression representing the size of the data to store.

        The following parameters are optional.

        :param condition:       A claripy expression representing a condition if the store is conditional.
        :param add_constraints: Add constraints resulting from the merge (default: True).
        :param endness:         The endianness for the data.
        :param action:          A SimActionData to fill out with the final written value and constraints.
        :param bool inspect:    Whether this store should trigger SimInspect breakpoints or not.
        :param bool disable_actions: Whether this store should avoid creating SimActions or not. When set to False,
                                     state options are respected.
        """

        _inspect = inspect and self.state.supports_inspect

        if priv is not None: self.state.scratch.push_priv(priv)

        addr_e = _raw_ast(addr)
        data_e = _raw_ast(data)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        add_constraints = True if add_constraints is None else add_constraints

        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr, is_write=True)
            addr = named_addr
            addr_e = addr
            if size is None:
                size = named_size
                size_e = size

        if isinstance(data_e, str):
            data_e = data_e.encode()
            l.warning("Storing unicode string encoded as utf-8. Did you mean to use a bytestring?")

        # store everything as a BV
        data_e = self._convert_to_ast(data_e, size_e if isinstance(size_e, int) else None)

        # zero extend if size is greater than len(data_e)
        stored_size = size_e*self.state.arch.byte_width if isinstance(size_e, int) else self.state.arch.bits
        if size_e is not None and self.category == 'reg' and len(data_e) < stored_size:
            data_e = data_e.zero_extend(stored_size - len(data_e))

        if type(size_e) is int:
            size_e = self.state.solver.BVV(size_e, self.state.arch.bits)
        elif size_e is None:
            size_e = self.state.solver.BVV(data_e.size() // self.state.arch.byte_width, self.state.arch.bits)

        if endness is None:
            endness = self.endness

        if len(data_e) % self.state.arch.byte_width != 0:
            raise SimMemoryError("Attempting to store non-byte data to memory")
        if not size_e.symbolic and (len(data_e) < size_e*self.state.arch.byte_width).is_true():
            raise SimMemoryError("Provided data is too short for this memory store")

        if _inspect:
            if self.category == 'reg':
                self.state._inspect(
                    'reg_write',
                    BP_BEFORE,
                    reg_write_offset=addr_e,
                    reg_write_length=size_e,
                    reg_write_expr=data_e,
                    reg_write_condition=condition_e,
                    reg_write_endness=endness,
                )
                addr_e = self.state._inspect_getattr('reg_write_offset', addr_e)
                size_e = self.state._inspect_getattr('reg_write_length', size_e)
                data_e = self.state._inspect_getattr('reg_write_expr', data_e)
                condition_e = self.state._inspect_getattr('reg_write_condition', condition_e)
                endness = self.state._inspect_getattr('reg_write_endness', endness)
            elif self.category == 'mem':
                self.state._inspect(
                    'mem_write',
                    BP_BEFORE,
                    mem_write_address=addr_e,
                    mem_write_length=size_e,
                    mem_write_expr=data_e,
                    mem_write_condition=condition_e,
                    mem_write_endness=endness,
                )
                addr_e = self.state._inspect_getattr('mem_write_address', addr_e)
                size_e = self.state._inspect_getattr('mem_write_length', size_e)
                data_e = self.state._inspect_getattr('mem_write_expr', data_e)
                condition_e = self.state._inspect_getattr('mem_write_condition', condition_e)
                endness = self.state._inspect_getattr('mem_write_endness', endness)

        # if the condition is false, bail
        if condition_e is not None and self.state.solver.is_false(condition_e):
            if priv is not None: self.state.scratch.pop_priv()
            return

        if (
            o.UNDER_CONSTRAINED_SYMEXEC in self.state.options and
            isinstance(addr_e, claripy.ast.Base) and
            addr_e.uninitialized and
            addr_e.uc_alloc_depth is not None
        ):
            self._constrain_underconstrained_index(addr_e)

        request = MemoryStoreRequest(addr_e, data=data_e, size=size_e, condition=condition_e, endness=endness)
        try:
            self._store(request) #will use state_plugins/symbolic_memory.py
        except SimSegfaultError as e:
            e.original_addr = addr_e
            raise

        if _inspect:
            if self.category == 'reg': self.state._inspect('reg_write', BP_AFTER)
            elif self.category == 'mem': self.state._inspect('mem_write', BP_AFTER)
            # tracer uses address_concretization_add_constraints
            add_constraints = self.state._inspect_getattr('address_concretization_add_constraints', add_constraints)

        if add_constraints and len(request.constraints) > 0:
            self.state.add_constraints(*request.constraints)

        if not disable_actions:
            if request.completed and o.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:
                ref_size = size * self.state.arch.byte_width if size is not None else data_e.size()
                region_type = self.category
                if region_type == 'file':
                    # Special handling for files to keep compatibility
                    # We may use some refactoring later
                    region_type = self.id
                action = SimActionData(self.state, region_type, 'write', addr=addr_e, data=data_e, size=ref_size,
                                       condition=condition
                                       )
                self.state.history.add_action(action)

            if request.completed and action is not None:
                action.actual_addrs = request.actual_addresses
                action.actual_value = action._make_object(request.stored_values[0]) # TODO
                if len(request.constraints) > 0:
                    action.added_constraints = action._make_object(self.state.solver.And(*request.constraints))
                else:
                    action.added_constraints = action._make_object(self.state.solver.true)

        if priv is not None: self.state.scratch.pop_priv()

    def _store(self, _request):
        raise NotImplementedError()

    def store_cases(self, addr, contents, conditions, fallback=None, add_constraints=None, endness=None, action=None):
        """
        Stores content into memory, conditional by case.

        :param addr:            A claripy expression representing the address to store at.
        :param contents:        A list of bitvectors, not necessarily of the same size. Use None to denote an empty
                                write.
        :param conditions:      A list of conditions. Must be equal in length to contents.

        The following parameters are optional.

        :param fallback:        A claripy expression representing what the write should resolve to if all conditions
                                evaluate to false (default: whatever was there before).
        :param add_constraints: Add constraints resulting from the merge (default: True)
        :param endness:         The endianness for contents as well as fallback.
        :param action:          A SimActionData to fill out with the final written value and constraints.
        :type action:           SimActionData
        """

        if fallback is None and all(c is None for c in contents):
            l.debug("Avoiding an empty write.")
            return

        addr_e = _raw_ast(addr)
        contents_e = _raw_ast(contents)
        conditions_e = _raw_ast(conditions)
        fallback_e = _raw_ast(fallback)

        max_bits = max(c.length for c in contents_e if isinstance(c, claripy.ast.Bits)) \
            if fallback is None else fallback.length

        # if fallback is not provided by user, load it from memory
        # remember to specify the endianness!
        fallback_e = self.load(addr, max_bits//self.state.arch.byte_width, add_constraints=add_constraints, endness=endness) \
            if fallback_e is None else fallback_e

        req = self._store_cases(addr_e, contents_e, conditions_e, fallback_e, endness=endness)
        add_constraints = self.state._inspect_getattr('address_concretization_add_constraints', add_constraints)
        if add_constraints:
            self.state.add_constraints(*req.constraints)

        if req.completed and o.AUTO_REFS in self.state.options and action is None:
            region_type = self.category
            if region_type == 'file':
                # Special handling for files to keep compatibility
                # We may use some refactoring later
                region_type = self.id
            action = SimActionData(self.state, region_type, 'write', addr=addr_e, data=req.stored_values[-1],
                                   size=max_bits, condition=self.state.solver.Or(*conditions), fallback=fallback
                                   )
            self.state.history.add_action(action)

        if req.completed and action is not None:
            action.actual_addrs = req.actual_addresses
            action.actual_value = action._make_object(req.stored_values[-1])
            action.added_constraints = action._make_object(self.state.solver.And(*req.constraints)
                                                           if len(req.constraints) > 0 else self.state.solver.true)

    def _store_cases(self, addr, contents, conditions, fallback, endness=None):
        extended_contents = [ ]
        for c in contents:
            if c is None:
                c = fallback
            else:
                need_bits = fallback.length - c.length
                if need_bits > 0:
                    c = c.concat(fallback[need_bits-1:0])
            extended_contents.append(c)

        case_constraints = { }
        for c,g in zip(extended_contents, conditions):
            if c not in case_constraints:
                case_constraints[c] = [ ]
            case_constraints[c].append(g)

        unique_contents = [ ]
        unique_constraints = [ ]
        for c,g in case_constraints.items():
            unique_contents.append(c)
            unique_constraints.append(self.state.solver.Or(*g))

        if len(unique_contents) == 1 and unique_contents[0] is fallback:
            req = MemoryStoreRequest(addr, data=fallback, endness=endness)
            return self._store(req)
        else:
            simplified_contents = [ ]
            simplified_constraints = [ ]
            for c,g in zip(unique_contents, unique_constraints):
                simplified_contents.append(self.state.solver.simplify(c))
                simplified_constraints.append(self.state.solver.simplify(g))
            cases = zip(simplified_constraints, simplified_contents)
            #cases = zip(unique_constraints, unique_contents)

            ite = self.state.solver.simplify(self.state.solver.ite_cases(cases, fallback))
            req = MemoryStoreRequest(addr, data=ite, endness=endness)
            return self._store(req)

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False):
        """
        Loads size bytes from dst.

        :param addr:             The address to load from.
        :param size:            The size (in bytes) of the load.
        :param condition:       A claripy expression representing a condition for a conditional load.
        :param fallback:        A fallback value if the condition ends up being False.
        :param add_constraints: Add constraints resulting from the merge (default: True).
        :param action:          A SimActionData to fill out with the constraints.
        :param endness:         The endness to load with.
        :param bool inspect:    Whether this store should trigger SimInspect breakpoints or not.
        :param bool disable_actions: Whether this store should avoid creating SimActions or not. When set to False,
                                     state options are respected.
        :param bool ret_on_segv: Whether returns the memory that is already loaded before a segmentation fault is triggered. The default is False.

        There are a few possible return values. If no condition or fallback are passed in,
        then the return is the bytes at the address, in the form of a claripy expression.
        For example:

            <A BVV(0x41, 32)>

        On the other hand, if a condition and fallback are provided, the value is conditional:

            <A If(condition, BVV(0x41, 32), fallback)>
        """

        _inspect = inspect and self.state.supports_inspect

        add_constraints = True if add_constraints is None else add_constraints

        addr_e = _raw_ast(addr)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        fallback_e = _raw_ast(fallback)

        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr)
            addr = named_addr
            addr_e = addr
            if size is None:
                size = named_size
                size_e = size

        if size is None:
            size = self.state.arch.bits // self.state.arch.byte_width
            size_e = size

        endness = self.endness if endness is None else endness

        if _inspect:
            if self.category == 'reg':
                self.state._inspect('reg_read', BP_BEFORE, reg_read_offset=addr_e, reg_read_length=size_e,
                                    reg_read_condition=condition_e, reg_read_endness=endness,
                                    )
                addr_e = self.state._inspect_getattr("reg_read_offset", addr_e)
                size_e = self.state._inspect_getattr("reg_read_length", size_e)
                condition_e = self.state._inspect_getattr("reg_read_condition", condition_e)
                endness = self.state._inspect_getattr("reg_read_endness", endness)

            elif self.category == 'mem':
                self.state._inspect('mem_read', BP_BEFORE, mem_read_address=addr_e, mem_read_length=size_e,
                                    mem_read_condition=condition_e, mem_read_endness=endness,
                                    )
                addr_e = self.state._inspect_getattr("mem_read_address", addr_e)
                size_e = self.state._inspect_getattr("mem_read_length", size_e)
                condition_e = self.state._inspect_getattr("mem_read_condition", condition_e)
                endness = self.state._inspect_getattr('mem_read_endness', endness)

        if (
            o.UNDER_CONSTRAINED_SYMEXEC in self.state.options and
            isinstance(addr_e, claripy.ast.Base) and
            addr_e.uninitialized and
            addr_e.uc_alloc_depth is not None
        ):
            self._constrain_underconstrained_index(addr_e)

        try:
            a,r,c = self._load(addr_e, size_e, condition=condition_e, fallback=fallback_e, inspect=_inspect,
                               events=not disable_actions, ret_on_segv=ret_on_segv)
        except SimSegfaultError as e:
            e.original_addr = addr_e
            raise
        if _inspect:
            # tracer uses address_concretization_add_constraints to overwrite the add_constraints value
            # TODO: Make this logic less arbitrary
            add_constraints = self.state._inspect_getattr('address_concretization_add_constraints', add_constraints)
        if add_constraints and c:
            self.state.add_constraints(*c)

        if (self.category == 'mem' and o.SIMPLIFY_MEMORY_READS in self.state.options) or \
           (self.category == 'reg' and o.SIMPLIFY_REGISTER_READS in self.state.options):  # pylint:disable=too-many-boolean-expressions
            l.debug("simplifying %s read...", self.category)
            r = self.state.simplify(r)

        if not self._abstract_backer and \
                o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options and \
                self.state.uninitialized_access_handler is not None and \
                (r.op == 'Reverse' or r.op == 'BVV') and \
                getattr(r._model_vsa, 'uninitialized', False):
            normalized_addresses = self.normalize_address(addr)
            if len(normalized_addresses) > 0 and type(normalized_addresses[0]) is AddressWrapper:
                normalized_addresses = [ (aw.region, aw.address) for aw in normalized_addresses ]
            self.state.uninitialized_access_handler(self.category, normalized_addresses, size, r, self.state.scratch.bbl_addr, self.state.scratch.stmt_idx)

        # the endianess
        if endness == "Iend_LE":
            r = r.reversed

        if _inspect:
            if self.category == 'mem':
                self.state._inspect('mem_read', BP_AFTER, mem_read_expr=r)
                r = self.state._inspect_getattr("mem_read_expr", r)

            elif self.category == 'reg':
                self.state._inspect('reg_read', BP_AFTER, reg_read_expr=r)
                r = self.state._inspect_getattr("reg_read_expr", r)

        if not disable_actions:
            if o.AST_DEPS in self.state.options and self.category == 'reg':
                r = SimActionObject(r, reg_deps=frozenset((addr,)))

            if o.AUTO_REFS in self.state.options and action is None:
                ref_size = size * self.state.arch.byte_width if size is not None else r.size()
                region_type = self.category
                if region_type == 'file':
                    # Special handling for files to keep compatibility
                    # We may use some refactoring later
                    region_type = self.id
                action = SimActionData(self.state, region_type, 'read', addr=addr, data=r, size=ref_size,
                                       condition=condition, fallback=fallback)
                self.state.history.add_action(action)

            if action is not None:
                action.actual_addrs = a
                action.added_constraints = action._make_object(self.state.solver.And(*c)
                                                               if len(c) > 0 else self.state.solver.true)

        return r

    def _constrain_underconstrained_index(self, addr_e):
        if not self.state.uc_manager.is_bounded(addr_e) or self.state.solver.max_int(addr_e) - self.state.solver.min_int( addr_e) >= self._read_address_range:
            # in under-constrained symbolic execution, we'll assign a new memory region for this address
            mem_region = self.state.uc_manager.assign(addr_e)

            # ... but only if it's not already been constrained to something!
            if self.state.solver.solution(addr_e, mem_region):
                self.state.add_constraints(addr_e == mem_region)
            l.debug('Under-constrained symbolic execution: assigned a new memory region @ %s to %s', mem_region, addr_e)

    def normalize_address(self, addr, is_write=False):  # pylint:disable=no-self-use,unused-argument
        """
        Normalize `addr` for use in static analysis (with the abstract memory model). In non-abstract mode, simply
        returns the address in a single-element list.
        """
        return [ addr ]

    def _load(self, _addr, _size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        raise NotImplementedError()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1,
             disable_actions=False, inspect=True, chunk_size=None):
        """
        Returns the address of bytes equal to 'what', starting from 'start'. Note that,  if you don't specify a default
        value, this search could cause the state to go unsat if no possible matching byte exists.

        :param addr:               The start address.
        :param what:                What to search for;
        :param max_search:          Search at most this many bytes.
        :param max_symbolic_bytes:  Search through at most this many symbolic bytes.
        :param default:             The default value, if what you're looking for wasn't found.
        :param step:                The stride that the search should use while scanning memory
        :param disable_actions:     Whether to inhibit the creation of SimActions for memory access
        :param inspect:             Whether to trigger SimInspect breakpoints

        :returns:                   An expression representing the address of the matching byte.
        """
        addr = _raw_ast(addr)
        what = _raw_ast(what)
        default = _raw_ast(default)

        if isinstance(what, bytes):
            # Convert it to a BVV
            what = claripy.BVV(what, len(what) * self.state.arch.byte_width)

        r,c,m = self._find(addr, what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default,
                           step=step, disable_actions=disable_actions, inspect=inspect, chunk_size=chunk_size)
        if o.AST_DEPS in self.state.options and self.category == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        return r,c,m

    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1,
              disable_actions=False, inspect=True, chunk_size=None):
        raise NotImplementedError()

    def copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True,
                      disable_actions=False):
        """
        Copies data within a memory.

        :param dst:         A claripy expression representing the address of the destination
        :param src:         A claripy expression representing the address of the source

        The following parameters are optional.

        :param src_memory:  Copy data from this SimMemory instead of self
        :param src_memory:  Copy data to this SimMemory instead of self
        :param size:        A claripy expression representing the size of the copy
        :param condition:   A claripy expression representing a condition, if the write should be conditional. If this
                            is determined to be false, the size of the copy will be 0.
        """
        dst = _raw_ast(dst)
        src = _raw_ast(src)
        size = _raw_ast(size)
        condition = _raw_ast(condition)

        return self._copy_contents(dst, src, size, condition=condition, src_memory=src_memory, dst_memory=dst_memory,
                                   inspect=inspect, disable_actions=disable_actions)

    def _copy_contents(self, _dst, _src, _size, condition=None, src_memory=None, dst_memory=None, inspect=True,
                      disable_actions=False):
        raise NotImplementedError()


from .. import sim_options as o
from ..state_plugins.sim_action import SimActionData
from ..state_plugins.sim_action_object import SimActionObject, _raw_ast
from ..errors import SimMemoryError, SimRegionMapError, SimSegfaultError
from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
