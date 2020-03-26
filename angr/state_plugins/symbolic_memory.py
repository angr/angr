from collections import defaultdict

import logging
import itertools
import string

l = logging.getLogger(name=__name__)

import claripy

from angr.errors import SimValueError
from ..storage.memory import SimMemory, DUMMY_SYMBOLIC_READ_VALUE
from ..storage.paged_memory import SimPagedMemory
from ..storage.memory_object import SimMemoryObject
from ..sim_state_options import SimStateOptions
from ..misc.ux import once

DEFAULT_MAX_SEARCH = 8

class MultiwriteAnnotation(claripy.Annotation):
    @property
    def eliminatable(self):
        return False
    @property
    def relocateable(self):
        return True

def _multiwrite_filter(mem, ast): #pylint:disable=unused-argument
    # this is a huge hack, but so is the whole multiwrite crap
    return any(isinstance(a, MultiwriteAnnotation) for a in ast._uneliminatable_annotations)

class SimSymbolicMemory(SimMemory): #pylint:disable=abstract-method
    _CONCRETIZATION_STRATEGIES = [ 'symbolic', 'symbolic_approx', 'any', 'any_approx', 'max', 'max_approx',
                                   'symbolic_nonzero', 'symbolic_nonzero_approx', 'norepeats' ]
    _SAFE_CONCRETIZATION_STRATEGIES = [ 'symbolic', 'symbolic_approx' ]

    def __init__(
        self, memory_backer=None, permissions_backer=None, mem=None, memory_id="mem",
        endness=None, abstract_backer=False, check_permissions=None,
        read_strategies=None, write_strategies=None, stack_region_map=None, generic_region_map=None
    ):
        SimMemory.__init__(self,
                           endness=endness,
                           abstract_backer=abstract_backer,
                           stack_region_map=stack_region_map,
                           generic_region_map=generic_region_map
                           )
        self.id = memory_id

        if check_permissions is None:
            check_permissions = self.category == 'mem'
        self.mem = SimPagedMemory(
            memory_backer=memory_backer,
            permissions_backer=permissions_backer,
            check_permissions=check_permissions
        ) if mem is None else mem

        # set up the strategies
        self.read_strategies = read_strategies
        self.write_strategies = write_strategies


    #
    # Lifecycle management
    #

    @SimMemory.memo
    def copy(self, _):
        """
        Return a copy of the SimMemory.
        """
        #l.debug("Copying %d bytes of memory with id %s." % (len(self.mem), self.id))
        c = type(self)(
            mem=self.mem.branch(),
            memory_id=self.id,
            endness=self.endness,
            abstract_backer=self._abstract_backer,
            read_strategies=[ s.copy() for s in self.read_strategies ],
            write_strategies=[ s.copy() for s in self.write_strategies ],
            stack_region_map=self._stack_region_map,
            generic_region_map=self._generic_region_map
        )

        return c

    #
    # Merging stuff
    #

    def _changes_to_merge(self, others):
        changed_bytes = set()

        for o in others:  # pylint:disable=redefined-outer-name
            changed_bytes |= self.changed_bytes(o)

        return changed_bytes

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        """
        Merge this SimMemory with the other SimMemory
        """

        changed_bytes = self._changes_to_merge(others)

        l.info("Merging %d bytes", len(changed_bytes))
        l.info("... %s has changed bytes %s", self.id, changed_bytes)

        self.read_strategies = self._merge_strategies(self.read_strategies, *[
            o.read_strategies for o in others
        ])
        self.write_strategies = self._merge_strategies(self.write_strategies, *[
            o.write_strategies for o in others
        ])
        merged_bytes = self._merge(others, changed_bytes, merge_conditions=merge_conditions)

        return len(merged_bytes) > 0

    @staticmethod
    def _merge_strategies(*strategy_lists):
        if len(set(len(sl) for sl in strategy_lists)) != 1:
            raise SimMergeError("unable to merge memories with amounts of strategies")

        merged_strategies = [ ]
        for strategies in zip(*strategy_lists):
            if len(set(s.__class__ for s in strategies)) != 1:
                raise SimMergeError("unable to merge memories with different types of strategies")

            unique = list(set(strategies))
            if len(unique) > 1:
                unique[0].merge(unique[1:])
            merged_strategies.append(unique[0])
        return merged_strategies

    def widen(self, others):
        changed_bytes = self._changes_to_merge(others)
        l.info("Memory %s widening bytes %s", self.id, changed_bytes)
        self._merge(others, changed_bytes, is_widening=True)
        return len(changed_bytes) > 0

    def _merge(self, others, changed_bytes, merge_conditions=None, is_widening=False):
        all_memories = [self] + others
        if merge_conditions is None:
            merge_conditions = [ None ] * len(all_memories)

        merged_to = None
        merged_objects = set()
        merged_bytes = set()
        for b in sorted(changed_bytes):
            if merged_to is not None and not b >= merged_to:
                l.info("merged_to = %d ... already merged byte 0x%x", merged_to, b)
                continue
            l.debug("... on byte 0x%x", b)

            memory_objects = []
            unconstrained_in = []

            # first get a list of all memory objects at that location, and
            # all memories that don't have those bytes
            for sm, fv in zip(all_memories, merge_conditions):
                if b in sm.mem:
                    l.info("... present in %s", fv)
                    memory_objects.append((sm.mem[b], fv))
                else:
                    l.info("... not present in %s", fv)
                    unconstrained_in.append((sm, fv))

            mos = set(mo for mo,_ in memory_objects)
            mo_bases = set(mo.base for mo, _ in memory_objects)
            mo_lengths = set(mo.length for mo, _ in memory_objects)

            if not unconstrained_in and not (mos - merged_objects):
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and not unconstrained_in:
                our_mo = self.mem[b]
                to_merge = [(mo.object, fv) for mo, fv in memory_objects]

                # Update `merged_to`
                mo_base = list(mo_bases)[0]
                merged_to = mo_base + list(mo_lengths)[0]

                merged_val = self._merge_values(
                    to_merge, memory_objects[0][0].length, is_widening=is_widening
                )

                if options.ABSTRACT_MEMORY in self.state.options:
                    # merge check for abstract memory
                    if not to_merge[0][0].uninitialized and self.state.solver.backends.vsa.identical(merged_val, to_merge[0][0]):
                        continue

                # do the replacement
                new_object = self.mem.replace_memory_object(our_mo, merged_val)
                merged_objects.add(new_object)
                merged_objects.update(mos)

                merged_bytes.add(b)

            else:
                # get the size that we can merge easily. This is the minimum of
                # the size of all memory objects and unallocated spaces.
                min_size = min([mo.length - (b - mo.base) for mo, _ in memory_objects])
                for um, _ in unconstrained_in:
                    for i in range(0, min_size):
                        if b + i in um:
                            min_size = i
                            break
                merged_to = b + min_size
                l.info("... determined minimum size of %d", min_size)

                # Now, we have the minimum size. We'll extract/create expressions of that
                # size and merge them
                extracted = [(mo.bytes_at(b, min_size), fv) for mo, fv in memory_objects] if min_size != 0 else []
                created = [
                    (self.get_unconstrained_bytes("merge_uc_%s_%x" % (uc.id, b), min_size * self.state.arch.byte_width), fv) for
                    uc, fv in unconstrained_in
                ]
                to_merge = extracted + created

                merged_val = self._merge_values(to_merge, min_size, is_widening=is_widening)

                if options.ABSTRACT_MEMORY in self.state.options:
                    # merge check for abstract memory
                    if (not unconstrained_in or not unconstrained_in[0][0] is self) \
                            and self.state.solver.backends.vsa.identical(merged_val, to_merge[0][0]):
                        continue

                self.store(b, merged_val, endness='Iend_BE', inspect=False)  # do not convert endianness again

                merged_bytes.add(b)

        return merged_bytes

    def set_state(self, state):
        super(SimSymbolicMemory, self).set_state(state)
        self.mem.state = state._get_weakref()

        if self.state is not None:
            if self.read_strategies is None:
                self._create_default_read_strategies()
            if self.write_strategies is None:
                self._create_default_write_strategies()

    def _create_default_read_strategies(self):
        self.read_strategies = [ ]
        if options.APPROXIMATE_MEMORY_INDICES in self.state.options:
            # first, we try to resolve the read address by approximation
            self.read_strategies.append(
                concretization_strategies.SimConcretizationStrategyRange(1024, exact=False),
            )

        # then, we try symbolic reads, with a maximum width of a kilobyte
        self.read_strategies.append(
            concretization_strategies.SimConcretizationStrategyRange(1024)
        )

        if options.CONSERVATIVE_READ_STRATEGY not in self.state.options:
            # finally, we concretize to any one solution
            self.read_strategies.append(
                concretization_strategies.SimConcretizationStrategyAny(),
            )

    def _create_default_write_strategies(self):
        self.write_strategies = [ ]
        if options.APPROXIMATE_MEMORY_INDICES in self.state.options:
            if options.SYMBOLIC_WRITE_ADDRESSES not in self.state.options:
                # we try to resolve a unique solution by approximation
                self.write_strategies.append(
                    concretization_strategies.SimConcretizationStrategySingle(exact=False),
                )
            else:
                # we try a solution range by approximation
                self.write_strategies.append(
                    concretization_strategies.SimConcretizationStrategyRange(128, exact=False)
                )

        if options.SYMBOLIC_WRITE_ADDRESSES in self.state.options:
            # we try to find a range of values
            self.write_strategies.append(
                concretization_strategies.SimConcretizationStrategyRange(128)
            )
        else:
            # we try to find a range of values, but only for ASTs annotated with the multiwrite annotation
            self.write_strategies.append(concretization_strategies.SimConcretizationStrategyRange(
                128,
                filter=_multiwrite_filter
            ))

        # finally, we just grab the maximum solution
        if options.CONSERVATIVE_WRITE_STRATEGY not in self.state.options:
            self.write_strategies.append(
                concretization_strategies.SimConcretizationStrategyMax()
            )

    #
    # Symbolicizing!
    #

    def make_symbolic(self, name, addr, length=None):
        """
        Replaces `length` bytes starting at `addr` with a symbolic variable named name. Adds a constraint equaling that
        symbolic variable to the value previously at `addr`, and returns the variable.
        """
        l.debug("making %s bytes symbolic", length)

        if isinstance(addr, str):
            addr, length = self.state.arch.registers[addr]
        else:
            if length is None:
                raise Exception("Unspecified length!")

        r = self.load(addr, length)

        v = self.get_unconstrained_bytes(name, r.size())
        self.store(addr, v)
        self.state.add_constraints(r == v)
        l.debug("... eq constraints: %s", r == v)
        return v

    #
    # Address concretization
    #

    def _resolve_size_range(self, size):
        if not self.state.solver.symbolic(size):
            i = self.state.solver.eval(size)
            if i > self._maximum_concrete_size:
                raise SimMemoryLimitError("Concrete size %d outside of allowable limits" % i)
            return i, i

        if options.APPROXIMATE_MEMORY_SIZES in self.state.options:
            max_size_approx = self.state.solver.max_int(size, exact=True)
            min_size_approx = self.state.solver.min_int(size, exact=True)

            if max_size_approx < self._maximum_symbolic_size_approx:
                return min_size_approx, max_size_approx

        max_size = self.state.solver.max_int(size)
        min_size = self.state.solver.min_int(size)

        if min_size > self._maximum_symbolic_size:
            self.state.history.add_event('memory_limit', message="Symbolic size %d outside of allowable limits" % min_size, size=size)
            if options.BEST_EFFORT_MEMORY_STORING not in self.state.options:
                raise SimMemoryLimitError("Symbolic size %d outside of allowable limits" % min_size)
            else:
                min_size = self._maximum_symbolic_size

        return min_size, min(max_size, self._maximum_symbolic_size)

    #
    # Concretization strategies
    #

    def _apply_concretization_strategies(self, addr, strategies, action):
        """
        Applies concretization strategies on the address until one of them succeeds.
        """

        # we try all the strategies in order
        for s in strategies:
            # first, we trigger the SimInspect breakpoint and give it a chance to intervene
            e = addr
            self.state._inspect(
                'address_concretization', BP_BEFORE, address_concretization_strategy=s,
                address_concretization_action=action, address_concretization_memory=self,
                address_concretization_expr=e, address_concretization_add_constraints=True
            )
            s = self.state._inspect_getattr('address_concretization_strategy', s)
            e = self.state._inspect_getattr('address_concretization_expr', addr)

            # if the breakpoint None'd out the strategy, we skip it
            if s is None:
                continue

            # let's try to apply it!
            try:
                a = s.concretize(self, e)
            except SimUnsatError:
                a = None

            # trigger the AFTER breakpoint and give it a chance to intervene
            self.state._inspect(
                'address_concretization', BP_AFTER,
                address_concretization_result=a
            )
            a = self.state._inspect_getattr('address_concretization_result', a)

            # return the result if not None!
            if a is not None:
                return a

        # well, we tried
        raise SimMemoryAddressError(
            "Unable to concretize address for %s with the provided strategies." % action
        )

    def concretize_write_addr(self, addr, strategies=None):
        """
        Concretizes an address meant for writing.

            :param addr:            An expression for the address.
            :param strategies:      A list of concretization strategies (to override the default).
            :returns:               A list of concrete addresses.
        """

        if isinstance(addr, int):
            return [ addr ]
        elif not self.state.solver.symbolic(addr):
            return [ self.state.solver.eval(addr) ]

        strategies = self.write_strategies if strategies is None else strategies
        return self._apply_concretization_strategies(addr, strategies, 'store')

    def concretize_read_addr(self, addr, strategies=None):
        """
        Concretizes an address meant for reading.

            :param addr:            An expression for the address.
            :param strategies:      A list of concretization strategies (to override the default).
            :returns:               A list of concrete addresses.
        """

        if isinstance(addr, int):
            return [ addr ]
        elif not self.state.solver.symbolic(addr):
            return [ self.state.solver.eval(addr) ]

        strategies = self.read_strategies if strategies is None else strategies
        return self._apply_concretization_strategies(addr, strategies, 'load')

    def normalize_address(self, addr, is_write=False):
        return self.concretize_read_addr(addr)

    #
    # Memory reading
    #

    def _fill_missing(self, addr, num_bytes, inspect=True, events=True):
        if self.category == 'reg':
            name = "reg_%s" % (self.state.arch.translate_register_name(addr))
        else:
            name = "%s_%x" % (self.id, addr)
        all_missing = [
            self.get_unconstrained_bytes(
                name,
                min(self.mem._page_size, num_bytes)*self.state.arch.byte_width,
                source=i,
                inspect=inspect,
                events=events,
                key=self.variable_key_prefix + (addr,),
                eternal=False) # :(
            for i in range(addr, addr+num_bytes, self.mem._page_size)
        ]
        if all_missing:
            is_mem = self.category == 'mem' and \
                    options.ZERO_FILL_UNCONSTRAINED_MEMORY not in self.state.options and \
                    options.SYMBOL_FILL_UNCONSTRAINED_MEMORY not in self.state.options
            is_reg = self.category == 'reg' and \
                    options.ZERO_FILL_UNCONSTRAINED_REGISTERS not in self.state.options and \
                    options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS not in self.state.options
            if is_mem or is_reg:
                if once('mem_fill_warning'):
                    l.warning("The program is accessing memory or registers with an unspecified value. "
                        "This could indicate unwanted behavior.")
                    l.warning("angr will cope with this by generating an unconstrained symbolic variable and continuing. "
                        "You can resolve this by:")
                    l.warning("1) setting a value to the initial state")
                    l.warning("2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, "
                        "to make unknown regions hold null")
                    l.warning("3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, "
                        "to suppress these messages.")

                if is_mem:
                    refplace_str = "unknown"
                    if not self.state._ip.symbolic:
                        refplace_int = self.state.solver.eval(self.state._ip)
                        refplace_int_s = "%#x" % refplace_int
                        if self.state.project:
                            refplace_str = self.state.project.loader.describe_addr(refplace_int)
                    else:
                        refplace_int_s = repr(self.state._ip)
                    l.warning("Filling memory at %#x with %d unconstrained bytes referenced from %s (%s)", addr, num_bytes, refplace_int_s, refplace_str)
                else:
                    if addr == self.state.arch.ip_offset:
                        refplace_int_s = "0"
                        refplace_str = "symbolic"
                    else:
                        refplace_str = "unknown"
                        if not self.state._ip.symbolic:
                            refplace_int = self.state.solver.eval(self.state._ip)
                            refplace_int_s = "%#x" % refplace_int
                            if self.state.project:
                                refplace_str = self.state.project.loader.describe_addr(refplace_int)
                        else:
                            refplace_int_s = repr(self.state._ip)
                    reg_str = self.state.arch.translate_register_name(addr, size=num_bytes)
                    l.warning("Filling register %s with %d unconstrained bytes referenced from %s (%s)", reg_str, num_bytes, refplace_int_s, refplace_str)

        # this is an optimization to ensure most operations in the future will deal with leaf ASTs (instead of reversed
        # ASTs)
        if self.category == 'reg' and self.state.arch.register_endness == 'Iend_LE':
            all_missing = [ a.reversed for a in all_missing ]
        elif self.category == 'file':
            # file data has to be big-endian
            pass
        elif self.category != 'reg' and self.state.arch.memory_endness == 'Iend_LE':
            # endianness of memory data
            all_missing = [ a.reversed for a in all_missing ]
        b = self.state.solver.Concat(*all_missing) if len(all_missing) > 1 else all_missing[0]

        if events:
            self.state.history.add_event('uninitialized', memory_id=self.id, addr=addr, size=num_bytes)
        default_mo = SimMemoryObject(b, addr, byte_width=self.state.arch.byte_width)
        self.state.scratch.push_priv(True)
        self.mem.store_memory_object(default_mo, overwrite=False)
        self.state.scratch.pop_priv()
        return default_mo

    def _read_from(self, addr, num_bytes, inspect=True, events=True, ret_on_segv=False):
        items = self.mem.load_objects(addr, num_bytes, ret_on_segv=ret_on_segv)

        # optimize the case where we have a single object return
        if len(items) == 1 and items[0][1].includes(addr) and items[0][1].includes(addr + num_bytes - 1):
            return items[0][1].bytes_at(addr, num_bytes)

        segments = [ ]
        last_missing = addr + num_bytes - 1
        for mo_addr,mo in reversed(items):
            if not mo.includes(last_missing):
                # add missing bytes
                start_addr = mo.last_addr + 1
                length = last_missing - mo.last_addr
                fill_mo = self._fill_missing(start_addr, length, inspect=inspect, events=events)
                segments.append(fill_mo.bytes_at(start_addr, length).reversed)
                last_missing = mo.last_addr

            # add the normal segment
            segments.append(mo.bytes_at(mo_addr, last_missing - mo_addr + 1))
            last_missing = mo_addr - 1

        # handle missing bytes at the beginning
        if last_missing != addr - 1:
            start_addr = addr
            end_addr = last_missing - addr + 1
            fill_mo = self._fill_missing(start_addr, end_addr, inspect=inspect, events=events)
            segments.append(fill_mo.bytes_at(start_addr, end_addr))

        # reverse the segments to put them in the right order
        segments.reverse()

        # and combine
        if len(segments) > 1:
            r = segments[0].concat(*segments[1:])
        elif len(segments) == 1:
            r = segments[0]
        else:
            r = self.state.solver.BVV(0, 0)
        return r

    def _load(self, dst, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        if self.state.solver.symbolic(size):
            l.warning("Concretizing symbolic length. Much sad; think about implementing.")

        # for now, we always load the maximum size
        _,max_size = self._resolve_size_range(size)
        if options.ABSTRACT_MEMORY not in self.state.options and self.state.solver.symbolic(size):
            self.state.add_constraints(size == max_size, action=True)

        if max_size == 0:
            self.state.history.add_event('memory_limit', message="0-length read")

        size = max_size
        if self.state.solver.symbolic(dst) and options.AVOID_MULTIVALUED_READS in self.state.options:
            return [ ], self.get_unconstrained_bytes("symbolic_read_unconstrained", size*self.state.arch.byte_width), [ ]

        # get a concrete set of read addresses
        try:
            addrs = self.concretize_read_addr(dst)
        except SimMemoryError:
            if options.CONSERVATIVE_READ_STRATEGY in self.state.options:
                return [ ], self.get_unconstrained_bytes(
                    "symbolic_read_unconstrained", size*self.state.arch.byte_width
                ), [ ]
            else:
                raise

        constraint_options = [ ]

        if len(addrs) == 1:
            # It's not an conditional reaed
            constraint_options.append(dst == addrs[0])
            read_value = self._read_from(addrs[0], size, inspect=inspect, events=events)
        else:
            read_value = DUMMY_SYMBOLIC_READ_VALUE  # it's a sentinel value and should never be touched

            for a in addrs:
                read_value = self.state.solver.If(dst == a, self._read_from(a, size, inspect=inspect, events=events),
                                              read_value)
                constraint_options.append(dst == a)

        if len(constraint_options) > 1:
            load_constraint = [ self.state.solver.Or(*constraint_options) ]
        elif not self.state.solver.symbolic(constraint_options[0]):
            load_constraint = [ ]
        else:
            load_constraint = [ constraint_options[0] ]

        if condition is not None and fallback is not None:
            read_value = self.state.solver.If(condition, read_value, fallback)
            load_constraint = [ self.state.solver.Or(self.state.solver.And(condition, *load_constraint), self.state.solver.Not(condition)) ]

        return addrs, read_value, load_constraint

    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1,
              disable_actions=False, inspect=True, chunk_size=None):
        if max_search is None:
            max_search = DEFAULT_MAX_SEARCH

        if isinstance(start, int):
            start = self.state.solver.BVV(start, self.state.arch.bits)

        constraints = [ ]
        remaining_symbolic = max_symbolic_bytes
        seek_size = len(what)//self.state.arch.byte_width
        symbolic_what = self.state.solver.symbolic(what)

        l.debug("Search for %d bytes in a max of %d...", seek_size, max_search)

        chunk_start = 0
        if chunk_size is None:
            chunk_size = max(0x100, seek_size + 0x80)

        chunk = self.load(start, chunk_size, endness="Iend_BE",
                          disable_actions=disable_actions, inspect=inspect)

        cases = [ ]
        match_indices = [ ]
        offsets_matched = [ ] # Only used in static mode
        byte_width = self.state.arch.byte_width
        no_singlevalue_opt = options.SYMBOLIC_MEMORY_NO_SINGLEVALUE_OPTIMIZATIONS in self.state.options
        cond_prefix = [ ]

        if options.MEMORY_FIND_STRICT_SIZE_LIMIT in self.state.options:
            cond_falseness_test = self.state.solver.is_false
        else:
            cond_falseness_test = lambda cond: cond.is_false()

        for i in itertools.count(step=step):
            l.debug("... checking offset %d", i)
            if i > max_search - seek_size:
                l.debug("... hit max size")
                break
            if remaining_symbolic is not None and remaining_symbolic == 0:
                l.debug("... hit max symbolic")
                break
            if i - chunk_start > chunk_size - seek_size:
                l.debug("loading new chunk")
                chunk_start += chunk_size - seek_size + 1
                chunk = self.load(start+chunk_start, chunk_size,
                                  endness="Iend_BE", ret_on_segv=True,
                                  disable_actions=disable_actions, inspect=inspect)

            chunk_off = i-chunk_start
            b = chunk[chunk_size*byte_width - chunk_off*byte_width - 1 : chunk_size*byte_width - chunk_off*byte_width - seek_size*byte_width]
            condition = b == what
            if not cond_falseness_test(condition):
                if no_singlevalue_opt and cond_prefix:
                    condition = claripy.And(*(cond_prefix + [condition]))
                cases.append([condition, claripy.BVV(i, len(start))])
                match_indices.append(i)

            if b.symbolic and no_singlevalue_opt:
                # in tracing mode, we need to make sure that all previous bytes are not equal to what
                cond_prefix.append(b != what)

            if self.state.mode == 'static':
                si = b._model_vsa
                what_si = what._model_vsa

                if isinstance(si, claripy.vsa.StridedInterval):
                    if not si.intersection(what_si).is_empty:
                        offsets_matched.append(start + i)

                    if si.identical(what_si):
                        break

                    if si.cardinality != 1:
                        if remaining_symbolic is not None:
                            remaining_symbolic -= 1
                else:
                    # Comparison with other types (like IfProxy or ValueSet) is not supported
                    if remaining_symbolic is not None:
                        remaining_symbolic -= 1

            else:
                # other modes (e.g. symbolic mode)
                if not b.symbolic and not symbolic_what and self.state.solver.eval(b) == self.state.solver.eval(what):
                    l.debug("... found concrete")
                    break
                else:
                    if b.symbolic and remaining_symbolic is not None:
                        remaining_symbolic -= 1

        if self.state.mode == 'static':
            r = self.state.solver.ESI(self.state.arch.bits)
            for off in offsets_matched:
                r = r.union(off)

            constraints = [ ]
            return r, constraints, match_indices

        else:
            if default is None:
                l.debug("... no default specified")
                default = 0
                constraints += [ self.state.solver.Or(*[ c for c,_ in cases]) ]

            #l.debug("running ite_cases %s, %s", cases, default)
            r = self.state.solver.ite_cases(cases, default - start) + start
            return r, constraints, match_indices

    def __contains__(self, dst):
        if isinstance(dst, int):
            addr = dst
        elif self.state.solver.symbolic(dst):
            l.warning("Currently unable to do SimMemory.__contains__ on symbolic variables.")
            return False
        else:
            addr = self.state.solver.eval(dst)
        return addr in self.mem

    def was_written_to(self, dst):
        if isinstance(dst, int):
            addr = dst
        elif self.state.solver.symbolic(dst):
            l.warning("Currently unable to do SimMemory.was_written_to on symbolic variables.")
            return False
        else:
            addr = self.state.solver.eval(dst)
        return self.mem.contains_no_backer(addr)

    #
    # Writes
    #

    def _store(self, req):
        l.debug("Doing a store...")
        req._adjust_condition(self.state)

        max_bytes = req.data.length//self.state.arch.byte_width

        if req.size is None:
            req.size = max_bytes

        if self.state.solver.symbolic(req.size):
            if options.AVOID_MULTIVALUED_WRITES in self.state.options:
                return req
            if options.CONCRETIZE_SYMBOLIC_WRITE_SIZES in self.state.options:
                new_size = self.state.solver.eval(req.size)
                self.state.add_constraints(req.size == new_size)
                req.size = new_size

        if self.state.solver.symbolic(req.addr) and options.AVOID_MULTIVALUED_WRITES in self.state.options:
            return req

        if not self.state.solver.symbolic(req.size) and self.state.solver.eval(req.size) > req.data.length//self.state.arch.byte_width:
            raise SimMemoryError("Not enough data for requested storage size (size: {}, data: {})".format(req.size, req.data))

        if self.state.solver.symbolic(req.size):
            self.state.add_constraints(self.state.solver.ULE(req.size, max_bytes))


        #
        # First, resolve the addresses
        #

        try:
            req.actual_addresses = sorted(self.concretize_write_addr(req.addr))
        except SimMemoryError:
            if options.CONSERVATIVE_WRITE_STRATEGY in self.state.options:
                return req
            else:
                raise

        if type(req.addr) is not int and req.addr.symbolic:
            conditional_constraint = self.state.solver.Or(*[ req.addr == a for a in req.actual_addresses ])
            if (conditional_constraint.symbolic or  # if the constraint is symbolic
                    conditional_constraint.is_false()):  # if it makes the state go unsat
                req.constraints.append(conditional_constraint)

        #
        # Prepare memory objects
        #
        # If we have only one address to write to we handle it as concrete, disregarding symbolic or not
        is_size_symbolic = self.state.solver.symbolic(req.size)
        is_addr_symbolic = self.state.solver.symbolic(req.addr)
        if not is_size_symbolic and len(req.actual_addresses) == 1:
            store_list = self._store_fully_concrete(req.actual_addresses[0], req.size, req.data, req.endness, req.condition)
        elif not is_addr_symbolic:
            store_list = self._store_symbolic_size(req.addr, req.size, req.data, req.endness, req.condition)
        elif not is_size_symbolic:
            store_list = self._store_symbolic_addr(req.addr, req.actual_addresses, req.size, req.data, req.endness, req.condition)
        else:
            store_list = self._store_fully_symbolic(req.addr, req.actual_addresses, req.size, req.data, req.endness, req.condition)

        #
        # store it!!!
        #
        req.stored_values = []
        if (self.category == 'mem' and options.SIMPLIFY_MEMORY_WRITES in self.state.options) or \
           (self.category == 'reg' and options.SIMPLIFY_REGISTER_WRITES in self.state.options):
            for store_item in store_list:
                store_item['value'] = self.state.solver.simplify(store_item['value'])

                if req.endness == "Iend_LE" or (req.endness is None and self.endness == "Iend_LE"):
                    store_item['value'] = store_item['value'].reversed

                req.stored_values.append(store_item['value'])
                self._insert_memory_object(store_item['value'], store_item['addr'], store_item['size'])
        else:
            for store_item in store_list:
                if req.endness == "Iend_LE" or (req.endness is None and self.endness == "Iend_LE"):
                    store_item['value'] = store_item['value'].reversed

                req.stored_values.append(store_item['value'])
                self._insert_memory_object(store_item['value'], store_item['addr'], store_item['size'])

        l.debug("... done")
        req.completed = True
        return req

    def _insert_memory_object(self, value, address, size):
        if self.category == 'mem':
            self.state.scratch.dirty_addrs.update(range(address, address+size))
        mo = SimMemoryObject(value, address, length=size, byte_width=self.state.arch.byte_width)
        self.mem.store_memory_object(mo)

    def _store_fully_concrete(self, address, size, data, endness, condition):
        if type(size) is not int:
            size = self.state.solver.eval(size)
        if size < data.length//self.state.arch.byte_width:
            data = data[len(data)-1:len(data)-size*self.state.arch.byte_width:]
        if condition is not None:
            try:
                original_value = self._read_from(address, size)
            except Exception as ex:
                raise ex

            if endness == "Iend_LE" or (endness is None and self.endness == "Iend_LE"):
                original_value = original_value.reversed
            conditional_value = self.state.solver.If(condition, data, original_value)
        else:
            conditional_value = data

        return [ dict(value=conditional_value, addr=address, size=size) ]


    def _store_symbolic_size(self, address, size, data, endness, condition):
        address = self.state.solver.eval(address)
        max_bytes = data.length//self.state.arch.byte_width
        original_value =  self._read_from(address, max_bytes)
        if endness == "Iend_LE" or (endness is None and self.endness == "Iend_LE"):
            original_value = original_value.reversed


        befores = original_value.chop(bits=self.state.arch.byte_width)
        afters = data.chop(bits=self.state.arch.byte_width)
        stored_value = self.state.solver.Concat(*[
            self.state.solver.If(self.state.solver.UGT(size, i), a, b)
            for i, (a, b) in enumerate(zip(afters, befores))
        ])

        conditional_value = self.state.solver.If(condition, stored_value, original_value) if condition is not None else stored_value

        return [ dict(value=conditional_value, addr=address, size=max_bytes) ]

    def _store_symbolic_addr(self, address,  addresses, size, data, endness, condition):
        size = self.state.solver.eval(size)
        segments = self._get_segments(addresses, size)

        if condition is None:
            condition = claripy.BoolV(True)

        original_values = [ self._read_from(segment['start'], segment['size']) for segment in segments ]
        if endness == "Iend_LE" or (endness is None and self.endness == "Iend_LE"):
            original_values = [ ov.reversed  for ov in original_values ]

        stored_values = []
        for segment, original_value  in zip(segments, original_values):
            conditional_value = original_value

            for opt in segment['options']:

                if endness == "Iend_LE" or (endness is None and self.endness == "Iend_LE"):
                    high = ((opt['idx']+segment['size']) * self.state.arch.byte_width)-1
                    low = opt['idx']*self.state.arch.byte_width
                else:
                    high = len(data) - 1 - (opt['idx']*self.state.arch.byte_width)
                    low = len(data) - ((opt['idx']+segment['size']) *self.state.arch.byte_width)

                data_slice = data[high:low]
                conditional_value = self.state.solver.If(self.state.solver.And(address == segment['start']-opt['idx'], condition), data_slice, conditional_value)

            stored_values.append(dict(value=conditional_value, addr=segment['start'], size=segment['size']))

        return stored_values

    def flush_pages(self, whitelist):
        flushed_regions = self.mem.flush_pages(whitelist)
        if self.state.has_plugin('unicorn'):
            for addr, length in flushed_regions:
                self.state.unicorn.uncache_region(addr, length)

    @staticmethod
    def _create_segment(addr, size, s_options, idx, segments):
        segment = dict(start=addr, size=size, options=s_options)
        segments.insert(idx, segment)

    @staticmethod
    def _split_segment(addr, segments):
        s_idx = SimSymbolicMemory._get_segment_index(addr, segments)
        segment = segments[s_idx]
        if segment['start'] == addr:
            return s_idx
        assert segment['start'] < addr < segment['start'] + segment['size']
        size_prev = addr - segment['start']
        size_next = segment['size'] - size_prev
        assert size_prev != 0 and size_next != 0
        segments.pop(s_idx)
        SimSymbolicMemory._create_segment(segment['start'], size_prev, segment['options'], s_idx, segments)
        SimSymbolicMemory._create_segment(addr, size_next, [{"idx": opt["idx"] + size_prev}
                                                            for opt in segment['options']], s_idx + 1, segments)
        return s_idx + 1

    @staticmethod
    def _add_segments_overlap(idx, addr, segments):
        for i in range(idx, len(segments)):
            segment = segments[i]
            if addr < segment['start'] + segment['size']:
                segments[i]["options"].append({"idx": segment['start'] - addr})

    @staticmethod
    def _get_segment_index(addr, segments):
        for i, segment in enumerate(segments):
            if segment['start'] <= addr < segment['start'] + segment['size']:
                return i

        return -1

    @staticmethod
    def _get_segments(addrs, size):
        segments = []
        highest = 0
        for addr in addrs:
            if addr < highest:
                idx = SimSymbolicMemory._split_segment(addr, segments)
                SimSymbolicMemory._create_segment(highest, addr + size - highest, [], len(segments), segments)
                SimSymbolicMemory._add_segments_overlap(idx, addr, segments)
            else:
                SimSymbolicMemory._create_segment(addr, size, [{'idx': 0}], len(segments), segments)
            highest = addr + size
        return segments

    def _store_fully_symbolic(self, address, addresses, size, data, endness, condition):
        stored_values = [ ]
        byte_dict = defaultdict(list)
        max_bytes = data.length//self.state.arch.byte_width

        if condition is None:
            condition = claripy.BoolV(True)

        # chop data into byte-chunks
        original_values = [self._read_from(a, max_bytes) for a in addresses]
        if endness == "Iend_LE" or (endness is None and self.endness == "Iend_LE"):
            original_values = [ ov.reversed  for ov in original_values ]
        data_bytes = data.chop(bits=self.state.arch.byte_width)

        for a, fv in zip(addresses, original_values):
            original_bytes = fv.chop(self.state.arch.byte_width)
            for index, (d_byte, o_byte) in enumerate(zip(data_bytes, original_bytes)):
                # create a dict of all all possible values for a certain address
                byte_dict[a+index].append((a, index, d_byte, o_byte))

        for byte_addr in sorted(byte_dict.keys()):
            write_list = byte_dict[byte_addr]
            # If this assertion fails something is really wrong!
            assert all(v[3] is write_list[0][3] for v in write_list)
            conditional_value = write_list[0][3]
            for a, index, d_byte, o_byte in write_list:
                # create the ast for each byte
                conditional_value = self.state.solver.If(self.state.solver.And(address == a, size > index, condition), d_byte, conditional_value)

            stored_values.append(dict(value=conditional_value, addr=byte_addr, size=1))

        return stored_values

    def _store_with_merge(self, req):
        req._adjust_condition(self.state)

        dst = req.addr
        cnt = req.data
        size = req.size
        endness = req.endness

        req.stored_values = [ ]

        if options.ABSTRACT_MEMORY not in self.state.options:
            raise SimMemoryError('store_with_merge is not supported without abstract memory.')

        l.debug("Doing a store with merging...")

        addrs = self.concretize_write_addr(dst)

        if len(addrs) == 1:
            l.debug("... concretized to 0x%x", addrs[0])
        else:
            l.debug("... concretized to %d values", len(addrs))

        if size is None:
            # Full length
            length = len(cnt)
        else:
            raise NotImplementedError()

        for addr in addrs:
            # First we load old values
            old_val = self._read_from(addr, length // self.state.arch.byte_width)
            assert isinstance(old_val, claripy.Bits)

            # FIXME: This is a big hack
            def is_reversed(o):
                if isinstance(o, claripy.Bits) and o.op == 'Reverse':
                    return True
                return False

            def can_be_reversed(o):
                om = o._model_vsa
                if isinstance(om, claripy.vsa.StridedInterval) and om.is_integer:
                    return True
                return False

            if endness == 'Iend_LE': cnt = cnt.reversed

            reverse_it = False
            if is_reversed(cnt):
                if is_reversed(old_val):
                    cnt = cnt.args[0]
                    old_val = old_val.args[0]
                    reverse_it = True
                elif can_be_reversed(old_val):
                    cnt = cnt.args[0]
                    reverse_it = True
            if isinstance(old_val, (int, claripy.bv.BVV)):
                merged_val = self.state.solver.SI(bits=len(old_val), to_conv=old_val)
            else:
                merged_val = old_val
            merged_val = merged_val.union(cnt)
            if reverse_it:
                merged_val = merged_val.reversed

            # Write the new value
            self.store(addr, merged_val, size=size)

            req.stored_values.append(merged_val)

        req.completed = True

        # TODO: revisit the following lines
        req.constraints = [ ]

        return req

    def get_unconstrained_bytes(self, name, bits, source=None, key=None, inspect=True, events=True, **kwargs):
        """
        Get some consecutive unconstrained bytes.

        :param name: Name of the unconstrained variable
        :param bits: Size of the unconstrained variable
        :param source: Where those bytes are read from. Currently it is only used in under-constrained symbolic
                    execution so that we can track the allocation depth.
        :return: The generated variable
        """

        if self.category == 'mem' and options.ZERO_FILL_UNCONSTRAINED_MEMORY in self.state.options:
            return self.state.solver.BVV(0, bits)
        elif self.category == 'reg' and options.ZERO_FILL_UNCONSTRAINED_REGISTERS in self.state.options:
            return self.state.solver.BVV(0, bits)
        elif options.SPECIAL_MEMORY_FILL in self.state.options and self.state._special_memory_filler is not None:
            return self.state._special_memory_filler(name, bits, self.state)
        else:
            if options.UNDER_CONSTRAINED_SYMEXEC in self.state.options:
                if source is not None and type(source) is int:
                    alloc_depth = self.state.uc_manager.get_alloc_depth(source)
                    kwargs['uc_alloc_depth'] = 0 if alloc_depth is None else alloc_depth + 1
            r = self.state.solver.Unconstrained(name, bits, key=key, inspect=inspect, events=events, **kwargs)
            return r

    # Unconstrain a byte
    def unconstrain_byte(self, addr, inspect=True, events=True):
        unconstrained_byte = self.get_unconstrained_bytes("%s_unconstrain_%#x" % (self.id, addr), self.state.arch.byte_width, inspect=inspect,
                                                          events=events, key=('manual_unconstrain', addr))
        self.store(addr, unconstrained_byte)

    # Replaces the differences between self and other with unconstrained bytes.
    def unconstrain_differences(self, other):
        changed_bytes = self.changed_bytes(other)
        l.debug("Will unconstrain %d %s bytes", len(changed_bytes), self.id)
        for b in changed_bytes:
            self.unconstrain_byte(b)

    @staticmethod
    def _is_uninitialized(a):
        return getattr(a._model_vsa, 'uninitialized', False)

    def _merge_values(self, to_merge, merged_size, is_widening=False):
        if options.ABSTRACT_MEMORY in self.state.options:
            if self.category == 'reg' and self.state.arch.register_endness == 'Iend_LE':
                should_reverse = True
            elif self.state.arch.memory_endness == 'Iend_LE':
                should_reverse = True
            else:
                should_reverse = False

            merged_val = to_merge[0][0]

            if should_reverse: merged_val = merged_val.reversed

            for tm,_ in to_merge[1:]:
                if should_reverse: tm = tm.reversed

                if self._is_uninitialized(tm):
                    continue
                if is_widening:
                    l.info("Widening %s %s...", merged_val, tm)
                    merged_val = merged_val.widen(tm)
                    l.info('... Widened to %s', merged_val)
                else:
                    l.info("Merging %s %s...", merged_val, tm)
                    merged_val = merged_val.union(tm)
                    l.info("... Merged to %s", merged_val)

            if should_reverse: merged_val = merged_val.reversed
        else:
            merged_val = self.state.solver.BVV(0, merged_size*self.state.arch.byte_width)
            for tm,fv in to_merge:
                merged_val = self.state.solver.If(fv, tm, merged_val)

        return merged_val

    def hex_dump(self, start, size, word_size=4, words_per_row=4, endianness="Iend_BE",
                 symbolic_char='?', unprintable_char='.', solve=False, extra_constraints=None,
                 inspect=False, disable_actions=True):
        """
        Returns a hex dump as a string. The solver, if enabled, is called once for every byte
        potentially making this function very slow. It is meant to be used mainly as a
        "visualization" for debugging.

        Warning: May read and display more bytes than `size` due to rounding. Particularly,
        if size is less than, or not a multiple of word_size*words_per_line.

        :param start: starting address from which to print
        :param size: number of bytes to display
        :param word_size: number of bytes to group together as one space-delimited unit
        :param words_per_row: number of words to display per row of output
        :param endianness: endianness to use when displaying each word (ASCII representation is unchanged)
        :param symbolic_char: the character to display when a byte is symbolic and has multiple solutions
        :param unprintable_char: the character to display when a byte is not printable
        :param solve: whether or not to attempt to solve (warning: can be very slow)
        :param extra_constraints: extra constraints to pass to the solver is solve is True
        :param inspect: whether or not to trigger SimInspect breakpoints for the memory load
        :param disable_actions: whether or not to disable SimActions for the memory load
        :return: hex dump as a string
        """
        if endianness == "Iend_BE":
            end = 1
        else:
            end = -1
        if extra_constraints is None:
            extra_constraints = []

        # round up size so that chop() works
        line_size = word_size * words_per_row
        size = size if size % line_size == 0 else size + line_size - size % line_size
        raw_mem = self.load(start, size, inspect=inspect, disable_actions=disable_actions)

        i = start
        dump_str = ""
        for line in raw_mem.chop(line_size * self.state.arch.byte_width):
            dump = "%x:" % i
            group_str = ""
            for word in line.chop(word_size * self.state.arch.byte_width):
                word_bytes = ""
                word_str = ""
                for byte_ in word.chop(self.state.arch.byte_width)[::end]:
                    byte_value = None
                    if not self.state.solver.symbolic(byte_) or solve:
                        try:
                            byte_value = self.state.solver.eval_one(
                                byte_,
                                extra_constraints=extra_constraints
                            )
                        except SimValueError:
                            pass

                    if byte_value is not None:
                        word_bytes += "%02x" % byte_value
                        if chr(byte_value) in string.printable[:-5]:
                            word_str += chr(byte_value)
                        else:
                            word_str += unprintable_char
                    else:
                        word_bytes += symbolic_char*2
                        word_str += symbolic_char
                dump += ' ' + word_bytes
                group_str += word_str[::end]  # always print ASCII representation in little-endian
            dump += ' ' + group_str
            i += line_size
            dump_str += dump + '\n'
        return dump_str

    def dbg_print(self, indent=0):
        """
        Print out debugging information.
        """
        lst = []
        more_data = False
        for i, addr in enumerate(self.mem.keys()):
            lst.append(addr)
            if i >= 20:
                more_data = True
                break

        for addr in sorted(lst):
            data = self.mem[addr]
            if isinstance(data, SimMemoryObject):
                memobj = data
                print("%s%xh: (%s)[%d]" % (" " * indent, addr, memobj, addr - memobj.base))
            else:
                print("%s%xh: <default data>" % (" " * indent, addr))
        if more_data:
            print("%s..." % (" " * indent))

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True,
                      disable_actions=False):
        src_memory = self if src_memory is None else src_memory
        dst_memory = self if dst_memory is None else dst_memory

        _,max_size = self._resolve_size_range(size)
        if max_size == 0:
            return None, [ ]

        data = src_memory.load(src, max_size, inspect=inspect, disable_actions=disable_actions)
        dst_memory.store(dst, data, size=size, condition=condition, inspect=inspect, disable_actions=disable_actions)
        return data

    #
    # Things that are actually handled by SimPagedMemory
    #

    def changed_bytes(self, other):
        """
        Gets the set of changed bytes between self and `other`.

        :param other:   The other :class:`SimSymbolicMemory`.
        :returns:       A set of differing bytes
        """
        return self.mem.changed_bytes(other.mem)

    def replace_all(self, old, new):
        """
        Replaces all instances of expression old with expression new.

        :param old: A claripy expression. Must contain at least one named variable (to make
                    to make it possible to use the name index for speedup)
        :param new: The new variable to replace it with
        """

        return self.mem.replace_all(old, new)

    def addrs_for_name(self, n):
        """
        Returns addresses that contain expressions that contain a variable
        named `n`.
        """
        return self.mem.addrs_for_name(n)

    def addrs_for_hash(self, h):
        """
        Returns addresses that contain expressions that contain a variable
        with the hash of `h`.
        """
        return self.mem.addrs_for_hash(h)

    def replace_memory_object(self, old, new_content):
        """
        Replaces the memory object 'old' with a new memory object containing
        'new_content'.

        :param old:         A SimMemoryObject (i.e., one from memory_objects_for_hash() or
                            memory_objects_for_name())
        :param new_content: the content (claripy expression) for the new memory object
        """
        return self.mem.replace_memory_object(old, new_content)

    def memory_objects_for_name(self, n):
        """
        Returns a set of SimMemoryObjects that contain expressions that contain a variable
        with the name of n. This is useful for replacing those values, in one fell swoop,
        with replace_memory_object(), even if they've been partially overwritten.
        """
        return self.mem.memory_objects_for_name(n)

    def memory_objects_for_hash(self, n):
        """
        Returns a set of SimMemoryObjects that contain expressions that contain a variable
        with the hash of h. This is useful for replacing those values, in one fell swoop,
        with replace_memory_object(), even if they've been partially overwritten.
        """
        return self.mem.memory_objects_for_hash(n)

    def permissions(self, addr, permissions=None):
        """
        Retrieve the permissions of the page at address `addr`.

        :param addr:        address to get the page permissions
        :param permissions: Integer or BVV to optionally set page permissions to
        :return:            AST representing the permissions on the page
        """
        out = self.mem.permissions(addr, permissions)
        # if unicorn is in play and we've marked a page writable, it must be uncached
        if permissions is not None and self.state.solver.is_true(permissions & 2 == 2):
            if self.state.has_plugin('unicorn'):
                p = self.mem._get_page(self.mem._page_id(addr))
                self.state.unicorn.uncache_region(p._page_addr, p._page_size)
        return out

    def map_region(self, addr, length, permissions, init_zero=False):
        """
        Map a number of pages at address `addr` with permissions `permissions`.
        :param addr: address to map the pages at
        :param length: length in bytes of region to map, will be rounded upwards to the page size
        :param permissions: AST of permissions to map, will be a bitvalue representing flags
        :param init_zero: Initialize page with zeros
        """
        l.info("Mapping [%#x, %#x] as %s", addr, addr + length - 1, permissions)
        return self.mem.map_region(addr, length, permissions, init_zero=init_zero)

    def unmap_region(self, addr, length):
        """
        Unmap a number of pages at address `addr`
        :param addr: address to unmap the pages at
        :param length: length in bytes of region to map, will be rounded upwards to the page size
        """
        if self.state.has_plugin('unicorn'):
            self.state.unicorn.uncache_region(addr, length)

        return self.mem.unmap_region(addr, length)


# Register state options
SimStateOptions.register_option("symbolic_ip_max_targets", int,
                                default=256,
                                description="The maximum number of concrete addresses a symbolic instruction pointer "
                                            "can be concretized to."
                                )
SimStateOptions.register_option("jumptable_symbolic_ip_max_targets", int,
                                default=16384,
                                description="The maximum number of concrete addresses a symbolic instruction pointer "
                                            "can be concretized to if it is part of a jump table."
                                )


from angr.sim_state import SimState
SimState.register_default('sym_memory', SimSymbolicMemory)

from ..errors import SimUnsatError, SimMemoryError, SimMemoryLimitError, SimMemoryAddressError, SimMergeError
from .. import sim_options as options
from .inspect import BP_AFTER, BP_BEFORE
from .. import concretization_strategies
