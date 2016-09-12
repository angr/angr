#!/usr/bin/env python

import logging
import itertools

l = logging.getLogger("simuvex.plugins.symbolic_memory")

import claripy
from ..storage.memory import SimMemory
from ..storage.paged_memory import SimPagedMemory
from ..storage.memory_object import SimMemoryObject

DEFAULT_MAX_SEARCH = 8

def _multiwrite_filter(mem, ast):
    return any("multiwrite" in var for var in mem.state.se.variables(ast))

class SimSymbolicMemory(SimMemory): #pylint:disable=abstract-method
    _CONCRETIZATION_STRATEGIES = [ 'symbolic', 'symbolic_approx', 'any', 'any_approx', 'max', 'max_approx',
                                   'symbolic_nonzero', 'symbolic_nonzero_approx', 'norepeats' ]
    _SAFE_CONCRETIZATION_STRATEGIES = [ 'symbolic', 'symbolic_approx' ]

    def __init__(
        self, memory_backer=None, permissions_backer=None, mem=None, memory_id="mem",
        endness=None, abstract_backer=False, check_permissions=None,
        read_strategies=None, write_strategies=None
    ):
        SimMemory.__init__(self, endness=endness, abstract_backer=abstract_backer)
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

    def copy(self):
        """
        Return a copy of the SimMemory.
        """
        #l.debug("Copying %d bytes of memory with id %s." % (len(self.mem), self.id))
        c = SimSymbolicMemory(
            mem=self.mem.branch(),
            memory_id=self.id,
            endness=self.endness,
            abstract_backer=self._abstract_backer,
            read_strategies=[ s.copy() for s in self.read_strategies ],
            write_strategies=[ s.copy() for s in self.write_strategies ],
        )

        return c

    #
    # Merging stuff
    #

    def _changes_to_merge(self, others):
        changed_bytes = set()

        for o in others:  # pylint:disable=redefined-outer-name
            changed_bytes |= self.changed_bytes(o)

        if options.FRESHNESS_ANALYSIS in self.state.options and self.state.scratch.ignored_variables is not None:
            ignored_var_changed_bytes = set()

            if self.category == 'reg':
                fresh_vars = self.state.scratch.ignored_variables.register_variables

                for v in fresh_vars:
                    offset, size = v.reg, v.size
                    ignored_var_changed_bytes |= set(xrange(offset, offset + size))

            else:
                fresh_vars = self.state.scratch.ignored_variables.memory_variables

                for v in fresh_vars:
                    # v.addr is an AddressWrapper object
                    region_id = v.addr.region
                    offset = v.addr.address
                    size = v.size

                    if region_id == self.id:
                        ignored_var_changed_bytes |= set(range(offset, offset + size))

            changed_bytes = changed_bytes - ignored_var_changed_bytes

        return changed_bytes

    def merge(self, others, merge_conditions):
        """
        Merge this SimMemory with the other SimMemory

        :param others: A list of SimMemory objects to be merged with
        :param merge_conditions:
        :return: whether merging occurred
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
        self._merge(others, changed_bytes, merge_conditions=merge_conditions)
        return len(changed_bytes) > 0

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

            if len(unconstrained_in) == 0 and len(mos - merged_objects) == 0:
                continue

            # first, optimize the case where we are dealing with the same-sized memory objects
            if len(mo_bases) == 1 and len(mo_lengths) == 1 and len(unconstrained_in) == 0:
                our_mo = self.mem[b]
                to_merge = [(mo.object, fv) for mo, fv in memory_objects]

                # Update `merged_to`
                mo_base = list(mo_bases)[0]
                merged_to = mo_base + list(mo_lengths)[0]

                merged_val = self._merge_values(
                    to_merge, memory_objects[0][0].length, is_widening=is_widening
                )

                # do the replacement
                new_object = self.mem.replace_memory_object(our_mo, merged_val)
                merged_objects.add(new_object)
                merged_objects.update(mos)
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
                    (self.get_unconstrained_bytes("merge_uc_%s_%x" % (uc.id, b), min_size * 8), fv) for
                    uc, fv in unconstrained_in
                ]
                to_merge = extracted + created

                merged_val = self._merge_values(to_merge, min_size, is_widening=is_widening)
                self.store(b, merged_val)

    def set_state(self, s):
        SimMemory.set_state(self, s)
        self.mem.state = s

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
            # we try to find a range of values, but only for things named "multiwrite"
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
        if not self.state.se.symbolic(size):
            i = self.state.se.any_int(size)
            if i > self._maximum_concrete_size:
                raise SimMemoryLimitError("Concrete size %d outside of allowable limits" % i)
            return i, i

        if options.APPROXIMATE_MEMORY_SIZES in self.state.options:
            max_size_approx = self.state.se.max_int(size, exact=True)
            min_size_approx = self.state.se.min_int(size, exact=True)

            if max_size_approx < self._maximum_symbolic_size_approx:
                return min_size_approx, max_size_approx

        max_size = self.state.se.max_int(size)
        min_size = self.state.se.min_int(size)

        if min_size > self._maximum_symbolic_size:
            self.state.log.add_event('memory_limit', message="Symbolic size %d outside of allowable limits" % min_size, size=size)
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

        if isinstance(addr, (int, long)):
            return [ addr ]
        elif not self.state.se.symbolic(addr):
            return [ self.state.se.any_int(addr) ]

        strategies = self.write_strategies if strategies is None else strategies
        return self._apply_concretization_strategies(addr, strategies, 'store')

    def concretize_read_addr(self, addr, strategies=None):
        """
        Concretizes an address meant for reading.

            :param addr:            An expression for the address.
            :param strategies:      A list of concretization strategies (to override the default).
            :returns:               A list of concrete addresses.
        """

        if isinstance(addr, (int, long)):
            return [ addr ]
        elif not self.state.se.symbolic(addr):
            return [ self.state.se.any_int(addr) ]

        strategies = self.read_strategies if strategies is None else strategies
        return self._apply_concretization_strategies(addr, strategies, 'load')

    def normalize_address(self, addr, is_write=False):
        return self.concretize_read_addr(addr)

    #
    # Memory reading
    #

    def _read_from(self, addr, num_bytes):
        the_bytes, missing, _ =  self.mem.load_bytes(addr, num_bytes)

        if len(missing) > 0:
            name = "%s_%x" % (self.id, addr)
            all_missing = [ self.get_unconstrained_bytes(name, min(self.mem._page_size, num_bytes)*8, source=i) for i in range(addr, addr+num_bytes, self.mem._page_size) ]
            if self.category == 'reg' and self.state.arch.register_endness == 'Iend_LE':
                all_missing = [ a.reversed for a in all_missing ]
            elif self.category != 'reg' and self.state.arch.memory_endness == 'Iend_LE':
                all_missing = [ a.reversed for a in all_missing ]
            b = self.state.se.Concat(*all_missing) if len(all_missing) > 1 else all_missing[0]

            self.state.log.add_event('uninitialized', memory_id=self.id, addr=addr, size=num_bytes)
            default_mo = SimMemoryObject(b, addr)
            for m in missing:
                the_bytes[m] = default_mo
            #   self.mem[addr+m] = default_mo
            self.state.scratch.push_priv(True)
            self.mem.store_memory_object(default_mo, overwrite=False)
            self.state.scratch.pop_priv()

        if 0 in the_bytes and isinstance(the_bytes[0], SimMemoryObject) and len(the_bytes) == the_bytes[0].object.length/8:
            for mo in the_bytes.itervalues():
                if mo is not the_bytes[0]:
                    break
            else:
                return the_bytes[0].object

        buf = [ ]
        buf_size = 0
        last_expr = None
        for i,e in itertools.chain(sorted(list(the_bytes.iteritems()), key=lambda x: x[0]), [(num_bytes, None)]):
            if not isinstance(e, SimMemoryObject) or e is not last_expr:
                if isinstance(last_expr, claripy.Bits):
                    buf.append(last_expr)
                    buf_size += 1
                elif isinstance(last_expr, SimMemoryObject):
                    buf.append(last_expr.bytes_at(addr+buf_size, i-buf_size))
                    buf_size = i
            last_expr = e

        if len(buf) > 1:
            r = buf[0].concat(*buf[1:])
        elif len(buf) == 1:
            r = buf[0]
        else:
            r = self.state.se.BVV(0, 0)

        return r

    def _load(self, dst, size, condition=None, fallback=None):
        if self.state.se.symbolic(size):
            l.warning("Concretizing symbolic length. Much sad; think about implementing.")

        # for now, we always load the maximum size
        _,max_size = self._resolve_size_range(size)
        if options.ABSTRACT_MEMORY not in self.state.options and self.state.se.symbolic(size):
            self.state.add_constraints(size == max_size, action=True)

        if max_size == 0:
            self.state.log.add_event('memory_limit', message="0-length read")

        size = max_size
        if self.state.se.symbolic(dst) and options.AVOID_MULTIVALUED_READS in self.state.options:
            return [ ], self.get_unconstrained_bytes("symbolic_read_" + ','.join(self.state.se.variables(dst)), size*8), [ ]

        # get a concrete set of read addresses
        try:
            addrs = self.concretize_read_addr(dst)
        except SimMemoryError:
            if options.CONSERVATIVE_READ_STRATEGY in self.state.options:
                return [ ], self.get_unconstrained_bytes(
                    "symbolic_read_" + ','.join(self.state.se.variables(dst)), size*8
                ), [ ]
            else:
                raise

        read_value = self._read_from(addrs[0], size)
        constraint_options = [ dst == addrs[0] ]

        for a in addrs[1:]:
            read_value = self.state.se.If(dst == a, self._read_from(a, size), read_value)
            constraint_options.append(dst == a)

        if len(constraint_options) > 1:
            load_constraint = [ self.state.se.Or(*constraint_options) ]
        elif not self.state.se.symbolic(constraint_options[0]):
            load_constraint = [ ]
        else:
            load_constraint = [ constraint_options[0] ]

        if condition is not None:
            read_value = self.state.se.If(condition, read_value, fallback)
            load_constraint = [ self.state.se.Or(self.state.se.And(condition, *load_constraint), self.state.se.Not(condition)) ]

        return addrs, read_value, load_constraint

    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1):
        if max_search is None:
            max_search = DEFAULT_MAX_SEARCH

        if isinstance(start, (int, long)):
            start = self.state.se.BVV(start, self.state.arch.bits)

        constraints = [ ]
        remaining_symbolic = max_symbolic_bytes
        seek_size = len(what)/8
        symbolic_what = self.state.se.symbolic(what)
        l.debug("Search for %d bytes in a max of %d...", seek_size, max_search)

        chunk_start = 0
        chunk_size = max(0x100, seek_size + 0x80)
        chunk = self.load(start, chunk_size, endness="Iend_BE")

        cases = [ ]
        match_indices = [ ]
        offsets_matched = [ ] # Only used in static mode

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
                chunk = self.load(start+chunk_start, chunk_size, endness="Iend_BE")

            chunk_off = i-chunk_start
            b = chunk[chunk_size*8 - chunk_off*8 - 1 : chunk_size*8 - chunk_off*8 - seek_size*8]
            cases.append([b == what, start + i])
            match_indices.append(i)

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
                if not b.symbolic and not symbolic_what and self.state.se.any_int(b) == self.state.se.any_int(what):
                    l.debug("... found concrete")
                    break
                else:
                    if b.symbolic and remaining_symbolic is not None:
                        remaining_symbolic -= 1

        if self.state.mode == 'static':
            r = self.state.se.ESI(self.state.arch.bits)
            for off in offsets_matched:
                r = r.union(off)

            constraints = [ ]
            return r, constraints, match_indices

        else:
            if default is None:
                l.debug("... no default specified")
                default = 0
                constraints += [ self.state.se.Or(*[ c for c,_ in cases]) ]

            #l.debug("running ite_cases %s, %s", cases, default)
            r = self.state.se.ite_cases(cases, default)
            return r, constraints, match_indices

    def __contains__(self, dst):
        if isinstance(dst, (int, long)):
            addr = dst
        elif self.state.se.symbolic(dst):
            l.warning("Currently unable to do SimMemory.__contains__ on symbolic variables.")
            return False
        else:
            addr = self.state.se.any_int(dst)
        return addr in self.mem

    def was_written_to(self, dst):
        if isinstance(dst, (int, long)):
            addr = dst
        elif self.state.se.symbolic(dst):
            l.warning("Currently unable to do SimMemory.was_written_to on symbolic variables.")
            return False
        else:
            addr = self.state.se.any_int(dst)
        return self.mem.contains_no_backer(addr)

    #
    # Writes
    #

    def _store(self, req):
        l.debug("Doing a store...")
        req._adjust_condition(self.state)

        if req.size is not None and self.state.se.symbolic(req.size) and options.AVOID_MULTIVALUED_WRITES in self.state.options:
            return req

        if self.state.se.symbolic(req.addr) and options.AVOID_MULTIVALUED_WRITES in self.state.options:
            return req

        if req.size is not None and self.state.se.symbolic(req.size) and options.CONCRETIZE_SYMBOLIC_WRITE_SIZES in self.state.options:
            new_size = self.state.se.any_int(req.size)
            req.constraints.append(req.size == new_size)
            req.size = new_size

        max_bytes = len(req.data)/8

        #
        # First, resolve the addresses
        #

        try:
            req.actual_addresses = self.concretize_write_addr(req.addr)
        except SimMemoryError:
            if options.CONSERVATIVE_WRITE_STRATEGY in self.state.options:
                return req
            else:
                raise
        num_addresses = len(req.actual_addresses)

        #
        # Next, get the fallback values:
        #

        if req.condition is not None or (req.size is not None and self.state.se.symbolic(req.size)) or num_addresses > 1:
            req.fallback_values = [ self._read_from(a, max_bytes) for a in req.actual_addresses ]
            if req.endness == "Iend_LE" or (req.endness is None and self.endness == "Iend_LE"):
                req.fallback_values = [ fv.reversed for fv in req.fallback_values ]
        else:
            req.fallback_values = [ None ] * num_addresses

        #
        # Next, conditionally size it
        #

        if req.size is None:
            req.symbolic_sized_values = [ req.data ] * num_addresses
        elif self.state.se.symbolic(req.size):
            req.symbolic_sized_values = [ ]
            req.constraints += [ self.state.se.ULE(req.size, max_bytes) ]

            for fv in req.fallback_values:
                befores = fv.chop(bits=8)
                afters = req.data.chop(bits=8)
                sv = self.state.se.Concat(*[
                    self.state.se.If(self.state.se.UGT(req.size, i), a, b)
                    for i,(a,b) in enumerate(zip(afters,befores))
                ])
                req.symbolic_sized_values.append(sv)
        else:
            needed_bytes = self.state.se.any_int(req.size)
            if needed_bytes < max_bytes:
                sv = req.data[max_bytes*8-1:(max_bytes-needed_bytes)*8]
                req.symbolic_sized_values = [ sv ] * num_addresses
                req.fallback_values = [
                    (fv[max_bytes*8-1:(max_bytes-needed_bytes)*8] if fv is not None else None)
                    for fv in req.fallback_values
                ]
            #elif needed_bytes > max_bytes:
            #   raise SimMemoryError("invalid length passed to SimSymbolicMemory._store")
            else:
                req.symbolic_sized_values = [ req.data ] * num_addresses

        #
        # Next, apply the condition
        #

        req.conditional_values = [ ]
        for a,fv,sv in zip(req.actual_addresses, req.fallback_values, req.symbolic_sized_values):
            if req.condition is None and num_addresses == 1:
                cv = sv
            elif req.condition is not None and num_addresses == 1:
                cv = self.state.se.If(req.condition, sv, fv)
            elif req.condition is None and num_addresses != 1:
                cv = self.state.se.If(req.addr == a, sv, fv)
            elif req.condition is not None and num_addresses != 1:
                cv = self.state.se.If(self.state.se.And(req.addr == a, req.condition), sv, fv)

            req.conditional_values.append(cv)

        if type(req.addr) not in (int, long) and req.addr.symbolic:
            conditional_constraint = self.state.se.Or(*[ req.addr == a for a in req.actual_addresses ])
            if (conditional_constraint.symbolic or  # if the constraint is symbolic
                    conditional_constraint.is_false()):  # if it makes the state go unsat
                req.constraints.append(conditional_constraint)

        #
        # now simplify
        #

        if (self.category == 'mem' and options.SIMPLIFY_MEMORY_WRITES in self.state.options) or \
           (self.category == 'reg' and options.SIMPLIFY_REGISTER_WRITES in self.state.options):
            req.simplified_values = [ self.state.se.simplify(cv) for cv in req.conditional_values ]
        else:
            req.simplified_values = list(req.conditional_values)

        #
        # fix endness
        #

        if req.endness == "Iend_LE" or (req.endness is None and self.endness == "Iend_LE"):
            req.stored_values = [ sv.reversed for sv in req.simplified_values ]
        else:
            req.stored_values = list(req.simplified_values)

        #
        # store it!!!
        #

        for a,sv in zip(req.actual_addresses, req.stored_values):
            # here, we ensure the uuids are generated for every expression written to memory
            sv.make_uuid()
            size = len(sv)/8
            self.state.scratch.dirty_addrs.update(range(a, a+size))
            mo = SimMemoryObject(sv, a, length=size)
            self.mem.store_memory_object(mo)

        l.debug("... done")
        req.completed = True
        return req

    def _store_with_merge(self, req):
        req._adjust_condition(self.state)

        dst = req.addr
        cnt = req.data
        size = req.size
        endness = req.endness

        req.stored_values = [ ]
        req.simplified_values = [ ]
        req.symbolic_sized_values = [ ]
        req.conditional_values = [ ]

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
            old_val = self._read_from(addr, length / 8)
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
            if isinstance(old_val, (int, long, claripy.bv.BVV)):
                merged_val = self.state.se.SI(bits=len(old_val), to_conv=old_val)
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
        req.fallback_values = [ ]
        req.constraints = [ ]

        return req

    def get_unconstrained_bytes(self, name, bits, source=None):
        """
        Get some consecutive unconstrained bytes.
        :param name: Name of the unconstrained variable
        :param bits: Size of the unconstrained variable
        :param source: Where those bytes are read from. Currently it is only used in under-constrained symbolic
                    execution so that we can track the allocation depth.
        :return: The generated variable
        """

        if (self.category == 'mem' and
                options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY in self.state.options):
            # CGC binaries zero-fill the memory for any allocated region
            # Reference: (https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md)
            return self.state.se.BVV(0, bits)
        elif options.SPECIAL_MEMORY_FILL in self.state.options:
            return self.state._special_memory_filler(name, bits)
        else:
            kwargs = { }
            if options.UNDER_CONSTRAINED_SYMEXEC in self.state.options:
                if source is not None and type(source) in (int, long):
                    alloc_depth = self.state.uc_manager.get_alloc_depth(source)
                    kwargs['uc_alloc_depth'] = 0 if alloc_depth is None else alloc_depth + 1
            r = self.state.se.Unconstrained(name, bits, **kwargs)
            return r

    # Unconstrain a byte
    def unconstrain_byte(self, addr):
        unconstrained_byte = self.get_unconstrained_bytes("%s_unconstrain_0x%x" % (self.id, addr), 8)
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
            merged_val = self.state.se.BVV(0, merged_size*8)
            for tm,fv in to_merge:
                l.debug("In merge: %s if flag is %s", tm, fv)
                merged_val = self.state.se.If(fv, tm, merged_val)

        return merged_val

    def concrete_parts(self):
        """
        Return a dict containing the concrete values in memory.
        """
        d = { }
        for k,v in self.mem.iteritems():
            if not self.state.se.symbolic(v):
                d[k] = self.state.se.simplify(v)

        return d

    def dbg_print(self, indent=0):
        """
        Print out debugging information.
        """
        lst = []
        more_data = False
        for i, addr in enumerate(self.mem.iterkeys()):
            lst.append(addr)
            if i >= 20:
                more_data = True
                break

        for addr in sorted(lst):
            data = self.mem[addr]
            if isinstance(data, SimMemoryObject):
                memobj = data
                print "%s%xh: (%s)[%d]" % (" " * indent, addr, memobj, addr - memobj.base)
            else:
                print "%s%xh: <default data>" % (" " * indent, addr)
        if more_data:
            print "%s..." % (" " * indent)

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None):
        src_memory = self if src_memory is None else src_memory
        dst_memory = self if dst_memory is None else dst_memory

        _,max_size = self._resolve_size_range(size)
        if max_size == 0:
            return None, [ ]

        data = src_memory.load(src, max_size)
        dst_memory.store(dst, data, size=size, condition=condition)
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

    def permissions(self, addr):
        """
        Retrieve the permissions of the page at address `addr`.

        :param addr: address to get the page permissions
        :return: AST representing the permissions on the page
        """
        return self.mem.permissions(addr)

    def map_region(self, addr, length, permissions):
        """
        Map a number of pages at address `addr` with permissions `permissions`.
        :param addr: address to map the pages at
        :param length: length in bytes of region to map, will be rounded upwards to the page size
        :param permissions: AST of permissions to map, will be a bitvalue representing flags
        """
        return self.mem.map_region(addr, length, permissions)

    def unmap_region(self, addr, length):
        """
        Unmap a number of pages at address `addr`
        :param addr: address to unmap the pages at
        :param length: length in bytes of region to map, will be rounded upwards to the page size
        """
        return self.mem.unmap_region(addr, length)

SimSymbolicMemory.register_default('memory', SimSymbolicMemory)
SimSymbolicMemory.register_default('registers', SimSymbolicMemory)
from ..s_errors import SimUnsatError, SimMemoryError, SimMemoryLimitError, SimMemoryAddressError, SimMergeError
from .. import s_options as options
from .inspect import BP_AFTER, BP_BEFORE
from .. import concretization_strategies
