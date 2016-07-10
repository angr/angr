#!/usr/bin/env python

import logging

l = logging.getLogger("simuvex.storage.memory")

import claripy
from ..plugins.plugin import SimStatePlugin

stn_map = { 'st%d' % n: n for n in xrange(8) }
tag_map = { 'tag%d' % n: n for n in xrange(8) }

class AddressWrapper(object):
    """
    AddressWrapper is used in SimAbstractMemory, which provides extra meta information for an address (or a ValueSet
    object) that is normalized from an integer/BVV/StridedInterval.
    """

    def __init__(self, region, region_base_addr, address, is_on_stack, function_address):
        """
        Constructor for the class AddressWrapper.

        :param strregion:              Name of the memory regions it belongs to.
        :param int region_base_addr:   Base address of the memory region
        :param address:             An address (not a ValueSet object).
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
        return state.se.VS(state.arch.bits, self.region, self.region_base_addr, self.address)

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

        # An AVLTree, which maps stack addresses to region IDs
        self._address_to_region_id = AVLTree()
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

        return self._address_to_region_id.max_key()

    @property
    def region_ids(self):
        return self._region_id_to_address.keys()

    #
    # Public methods
    #

    def copy(self):
        r = RegionMap(is_stack=self.is_stack)

        # A shallow copy should be enough, since we never modify any RegionDescriptor object in-place
        if len(self._address_to_region_id) > 0:
            # TODO: There is a bug in bintrees 2.0.2 that prevents us from copying a non-empty AVLTree object
            # TODO: Consider submit a pull request
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
                    addr = self._address_to_region_id.floor_key(absolute_address)
                    descriptor = self._address_to_region_id[addr]
                    # Remove this mapping
                    del self._address_to_region_id[addr]
                    # Remove this region ID from the other mapping
                    del self._region_id_to_address[descriptor.region_id]
                except KeyError:
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
                base_address = self._address_to_region_id.ceiling_key(absolute_address)

            else:
                try:
                    base_address = self._address_to_region_id.floor_key(absolute_address)

                except KeyError:
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

        self.fallback_values = None
        self.symbolic_sized_values = None
        self.conditional_values = None
        self.simplified_values = None
        self.stored_values = None

    def _adjust_condition(self, state):
        self.condition = state._adjust_condition(self.condition)


class SimMemory(SimStatePlugin):
    """
    Represents the memory space of the process.
    """
    def __init__(self, endness=None, abstract_backer=None):
        SimStatePlugin.__init__(self)
        self.id = None
        self.endness = "Iend_BE" if endness is None else endness

        # Whether this memory is internally used inside SimAbstractMemory
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

    def _resolve_location_name(self, name):
        if self.category == 'reg':
            if self.state.arch.name in ('X86', 'AMD64'):
                if name in stn_map:
                    return (((stn_map[name] + self.load('ftop')) & 7) << 3) + self.state.arch.registers['fpu_regs'][0], 8
                elif name in tag_map:
                    return ((tag_map[name] + self.load('ftop')) & 7) + self.state.arch.registers['fpu_tags'][0], 1

            return self.state.arch.registers[name]
        elif name[0] == '*':
            return self.state.registers.load(name[1:]), None
        else:
            raise SimMemoryError("Trying to address memory with a register name.")

    def _convert_to_ast(self, data_e, size_e=None):
        """
        Make an AST out of concrete @data_e
        """
        if type(data_e) is str:
            # Convert the string into a BVV, *regardless of endness*
            bits = len(data_e) * 8
            data_e = self.state.se.BVV(data_e, bits)
        elif type(data_e) in (int, long):
            data_e = self.state.se.BVV(data_e, size_e*8 if size_e is not None
                                       else self.state.arch.bits)
        else:
            data_e = data_e.to_bv()

        return data_e

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None, inspect=True, priv=None):
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
        """
        if priv is not None: self.state.scratch.push_priv(priv)

        addr_e = _raw_ast(addr)
        data_e = _raw_ast(data)
        size_e = _raw_ast(size)
        condition_e = _raw_ast(condition)
        add_constraints = True if add_constraints is None else add_constraints

        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(addr)
            addr = named_addr
            addr_e = addr
            if size is None:
                size = named_size
                size_e = size

        # store everything as a BV
        data_e = self._convert_to_ast(data_e, size_e if isinstance(size_e, (int, long)) else None)

        if type(size_e) in (int, long):
            size_e = self.state.se.BVV(size_e, self.state.arch.bits)

        if inspect is True:
            if self.category == 'reg':
                self.state._inspect(
                    'reg_write',
                    BP_BEFORE,
                    reg_write_offset=addr_e,
                    reg_write_length=size_e,
                    reg_write_expr=data_e)
                addr_e = self.state._inspect_getattr('reg_write_offset', addr_e)
                size_e = self.state._inspect_getattr('reg_write_length', size_e)
                data_e = self.state._inspect_getattr('reg_write_expr', data_e)
            elif self.category == 'mem':
                self.state._inspect(
                    'mem_write',
                    BP_BEFORE,
                    mem_write_address=addr_e,
                    mem_write_length=size_e,
                    mem_write_expr=data_e,
                )
                addr_e = self.state._inspect_getattr('mem_write_address', addr_e)
                size_e = self.state._inspect_getattr('mem_write_length', size_e)
                data_e = self.state._inspect_getattr('mem_write_expr', data_e)

        # if the condition is false, bail
        if condition_e is not None and self.state.se.is_false(condition_e):
            if priv is not None: self.state.scratch.pop_priv()
            return

        if (
            o.UNDER_CONSTRAINED_SYMEXEC in self.state.options and
            isinstance(addr_e, claripy.ast.Base) and
            addr_e.uninitialized
        ):
            self._constrain_underconstrained_index(addr_e)

        request = MemoryStoreRequest(addr_e, data=data_e, size=size_e, condition=condition_e, endness=endness)
        self._store(request)

        if inspect is True:
            if self.category == 'reg': self.state._inspect('reg_write', BP_AFTER)
            if self.category == 'mem': self.state._inspect('mem_write', BP_AFTER)

        add_constraints = self.state._inspect_getattr('address_concretization_add_constraints', add_constraints)
        if add_constraints and len(request.constraints) > 0:
            self.state.add_constraints(*request.constraints)

        if request.completed and o.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:
            ref_size = size if size is not None else (data_e.size() / 8)
            region_type = self.category
            if region_type == 'file':
                # Special handling for files to keep compatibility
                # We may use some refactoring later
                region_type = self.id
            action = SimActionData(self.state, region_type, 'write', addr=addr, data=data, size=ref_size, condition=condition)
            self.state.log.add_action(action)

        if request.completed and action is not None:
            action.actual_addrs = request.actual_addresses
            action.actual_value = action._make_object(request.stored_values[0]) # TODO
            if len(request.constraints) > 0:
                action.added_constraints = action._make_object(self.state.se.And(*request.constraints))
            else:
                action.added_constraints = action._make_object(self.state.se.true)

        if priv is not None: self.state.scratch.pop_priv()

    def _store(self, request):
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
        :type action:           simuvex.s_action.SimActionData
        """

        if fallback is None and all(c is None for c in contents):
            l.debug("Avoiding an empty write.")
            return

        addr_e = _raw_ast(addr)
        contents_e = _raw_ast(contents)
        conditions_e = _raw_ast(conditions)
        fallback_e = _raw_ast(fallback)

        max_bits = max(c.length for c in contents_e if isinstance(c, claripy.ast.Bits)) if fallback is None else fallback.length

        # if fallback is not provided by user, load it from memory
        # remember to specify the endianness!
        fallback_e = self.load(addr, max_bits/8, add_constraints=add_constraints, endness=endness) if fallback_e is None else fallback_e

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
            action = SimActionData(self.state, region_type, 'write', addr=addr, data=req.stored_values[-1], size=max_bits/8, condition=self.state.se.Or(*conditions), fallback=fallback)
            self.state.log.add_action(action)

        if req.completed and action is not None:
            action.actual_addrs = req.actual_addresses
            action.actual_value = action._make_object(req.stored_values[-1])
            action.added_constraints = action._make_object(self.state.se.And(*req.constraints) if len(req.constraints) > 0 else self.state.se.true)

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
            unique_constraints.append(self.state.se.Or(*g))

        if len(unique_contents) == 1 and unique_contents[0] is fallback:
            req = MemoryStoreRequest(addr, data=fallback, endness=endness)
            return self._store(req)
        else:
            simplified_contents = [ ]
            simplified_constraints = [ ]
            for c,g in zip(unique_contents, unique_constraints):
                simplified_contents.append(self.state.se.simplify(c))
                simplified_constraints.append(self.state.se.simplify(g))
            cases = zip(simplified_constraints, simplified_contents)
            #cases = zip(unique_constraints, unique_contents)

            ite = self.state.se.simplify(self.state.se.ite_cases(cases, fallback))
            req = MemoryStoreRequest(addr, data=ite, endness=endness)
            return self._store(req)

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None, inspect=True):
        """
        Loads size bytes from dst.

        :param dst:             The address to load from.
        :param size:            The size (in bytes) of the load.
        :param condition:       A claripy expression representing a condition for a conditional load.
        :param fallback:        A fallback value if the condition ends up being False.
        :param add_constraints: Add constraints resulting from the merge (default: True).
        :param action:          A SimActionData to fill out with the constraints.
        :param endness:         The endness to load with.

        There are a few possible return values. If no condition or fallback are passed in,
        then the return is the bytes at the address, in the form of a claripy expression.
        For example:

            <A BVV(0x41, 32)>

        On the other hand, if a condition and fallback are provided, the value is conditional:

            <A If(condition, BVV(0x41, 32), fallback)>
        """
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
            size = self.state.arch.bits / 8
            size_e = size

        if inspect is True:
            if self.category == 'reg':
                self.state._inspect('reg_read', BP_BEFORE, reg_read_offset=addr_e, reg_read_length=size_e)
                addr_e = self.state._inspect_getattr("reg_read_offset", addr_e)
                size_e = self.state._inspect_getattr("reg_read_length", size_e)

            elif self.category == 'mem':
                self.state._inspect('mem_read', BP_BEFORE, mem_read_address=addr_e, mem_read_length=size_e)
                addr_e = self.state._inspect_getattr("mem_read_address", addr_e)
                size_e = self.state._inspect_getattr("mem_read_length", size_e)

        if (
            o.UNDER_CONSTRAINED_SYMEXEC in self.state.options and
            isinstance(addr_e, claripy.ast.Base) and
            addr_e.uninitialized
        ):
            self._constrain_underconstrained_index(addr_e)

        a,r,c = self._load(addr_e, size_e, condition=condition_e, fallback=fallback_e)
        add_constraints = self.state._inspect_getattr('address_concretization_add_constraints', add_constraints)
        if add_constraints and c:
            self.state.add_constraints(*c)

        if (self.category == 'mem' and o.SIMPLIFY_MEMORY_READS in self.state.options) or \
           (self.category == 'reg' and o.SIMPLIFY_REGISTER_READS in self.state.options):
            l.debug("simplifying %s read...", self.category)
            r = self.state.simplify(r)

        if not self._abstract_backer and \
                o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options and \
                self.state.uninitialized_access_handler is not None and \
                (r.op == 'Reverse' or r.op == 'I') and \
                hasattr(r._model_vsa, 'uninitialized') and \
                r._model_vsa.uninitialized:
            normalized_addresses = self.normalize_address(addr)
            if len(normalized_addresses) > 0 and type(normalized_addresses[0]) is AddressWrapper:
                normalized_addresses = [ (aw.region, aw.address) for aw in normalized_addresses ]
            self.state.uninitialized_access_handler(self.category, normalized_addresses, size, r, self.state.scratch.bbl_addr, self.state.scratch.stmt_idx)

        # the endianess
        endness = self.endness if endness is None else endness
        if endness == "Iend_LE":
            r = r.reversed

        if inspect is True:
            if self.category == 'mem':
                self.state._inspect('mem_read', BP_AFTER, mem_read_expr=r)
                r = self.state._inspect_getattr("mem_read_expr", r)

            elif self.category == 'reg':
                self.state._inspect('reg_read', BP_AFTER, reg_read_expr=r)
                r = self.state._inspect_getattr("reg_read_expr", r)

        if o.AST_DEPS in self.state.options and self.category == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        if o.AUTO_REFS in self.state.options and action is None:
            ref_size = size if size is not None else (r.size() / 8)
            region_type = self.category
            if region_type == 'file':
                # Special handling for files to keep compatibility
                # We may use some refactoring later
                region_type = self.id
            action = SimActionData(self.state, region_type, 'read', addr=addr, data=r, size=ref_size, condition=condition, fallback=fallback)
            self.state.log.add_action(action)

        if action is not None:
            action.actual_addrs = a
            action.added_constraints = action._make_object(self.state.se.And(*c) if len(c) > 0 else self.state.se.true)

        return r

    def _constrain_underconstrained_index(self, addr_e):
        if not self.state.uc_manager.is_bounded(addr_e) or self.state.se.max_int(addr_e) - self.state.se.min_int( addr_e) >= self._read_address_range:
            # in under-constrained symbolic execution, we'll assign a new memory region for this address
            mem_region = self.state.uc_manager.assign(addr_e)

            # ... but only if it's not already been constrained to something!
            if self.state.se.solution(addr_e, mem_region):
                self.state.add_constraints(addr_e == mem_region)
            l.debug('Under-constrained symbolic execution: assigned a new memory region @ %s to %s', mem_region, addr_e)

    def normalize_address(self, addr, is_write=False): #pylint:disable=no-self-use,unused-argument
        """
        Normalize `addr` for use in static analysis (with the abstract memory model). In non-abstract mode, simply
        returns the address in a single-element list.
        """
        return [ addr ]

    def _load(self, addr, size, condition=None, fallback=None):
        raise NotImplementedError()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1):
        """
        Returns the address of bytes equal to 'what', starting from 'start'. Note that,  if you don't specify a default
        value, this search could cause the state to go unsat if no possible matching byte exists.

        :param start:               The start address.
        :param what:                What to search for;
        :param max_search:          Search at most this many bytes.
        :param max_symbolic_bytes:  Search through at most this many symbolic bytes.
        :param default:             The default value, if what you're looking for wasn't found.

        :returns:                   An expression representing the address of the matching byte.
        """
        addr = _raw_ast(addr)
        what = _raw_ast(what)
        default = _raw_ast(default)

        if isinstance(what, str):
            # Convert it to a BVV
            what = claripy.BVV(what, len(what) * 8)

        r,c,m = self._find(addr, what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default,
                           step=step)
        if o.AST_DEPS in self.state.options and self.category == 'reg':
            r = SimActionObject(r, reg_deps=frozenset((addr,)))

        return r,c,m

    def _find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1):
        raise NotImplementedError()

    def copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None):
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

        return self._copy_contents(dst, src, size, condition=condition, src_memory=src_memory, dst_memory=dst_memory)

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None):
        raise NotImplementedError()

from bintrees import AVLTree
from .. import s_options as o
from ..s_action import SimActionData
from ..s_action_object import SimActionObject, _raw_ast
from ..s_errors import SimMemoryError, SimRegionMapError
from ..plugins.inspect import BP_BEFORE, BP_AFTER
