import logging
import claripy
from sortedcontainers import SortedDict
from archinfo.arch_arm import is_arm_arch
from ..state_plugins.plugin import SimStatePlugin


l = logging.getLogger(name=__name__)

class SimMemory(SimStatePlugin):
    """
    Represents the memory space of the process.
    """
    def __init__(self, endness="Iend_BE"):
        super().__init__()
        self.id = None
        self.endness = "Iend_BE" if endness is None else endness

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
        :param bool inspect:    Whether this store should trigger SimInspect breakpoints or not.
        :param bool disable_actions: Whether this store should avoid creating SimActions or not. When set to False,
                                     state options are respected.
        """

        add_constraints = True if add_constraints is None else add_constraints

        if endness is None:
            endness = self.endness

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

        if inspect and self.state.supports_inspect:
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

        add_constraints = True if add_constraints is None else add_constraints

        endness = self.endness if endness is None else endness

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
        if inspect and self.state.supports_inspect:
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

    def copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True, disable_actions=False):
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

        raise NotImplementedError()


from .. import sim_options as o
from ..state_plugins.sim_action import SimActionData
from ..state_plugins.sim_action_object import SimActionObject, _raw_ast
from ..errors import SimMemoryError, SimRegionMapError, SimSegfaultError
from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
