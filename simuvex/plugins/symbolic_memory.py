#!/usr/bin/env python

import logging
import cooldict
import itertools

l = logging.getLogger("simuvex.plugins.symbolic_memory")

import claripy
from .memory import SimMemory

class SimMemoryObject(object):
    '''
    A MemoryObjectRef instance is a reference to a byte or several bytes in
    a specific object in SimSymbolicMemory. It is only used inside
    SimSymbolicMemory class.
    '''
    def __init__(self, object, base, length=None): #pylint:disable=redefined-builtin
        if not isinstance(object, claripy.A):
            raise SimMemoryError('memory can only store claripy Expression')

        self._base = base
        self._object = object
        self._length = object.size()/8 if length is None else length

    def size(self):
        return self._length * 8

    def __len__(self):
        return self.size()

    @property
    def base(self):
        return self._base

    @property
    def length(self):
        return self._length

    @property
    def object(self):
        return self._object

    def bytes_at(self, addr, length):
        if addr == self.base and length == self.length:
            return self.object

        obj_size = self.size()
        left = obj_size - (addr-self.base)*8 - 1
        right = left - length*8 + 1
        return self.object[left:right]

    def __eq__(self, other):
        return self._object.identical(other._object) and self._base == other._base and hash(self._length) == hash(other._length)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        if type(self.object) is claripy.A:
            return "%s" % (self.object.model)
        else:
            return "%s" % (self.object)

class SimSymbolicMemory(SimMemory):
    def __init__(self, backer=None, name_mapping=None, hash_mapping=None, memory_id="mem", repeat_min=None, repeat_constraints=None, repeat_expr=None):
        SimMemory.__init__(self)
        if backer is None:
            backer = cooldict.BranchingDict()

        if not isinstance(backer, cooldict.BranchingDict):
            backer = cooldict.BranchingDict(backer)

        self.mem = backer
        self.id = memory_id

        # for the norepeat stuff
        self._repeat_constraints = [ ] if repeat_constraints is None else repeat_constraints
        self._repeat_expr = repeat_expr
        self._repeat_granularity = 0x10000
        self._repeat_min = 0x13370000 if repeat_min is None else repeat_min

        # default strategies
        self._default_read_strategy = ['symbolic', 'any']
        self._read_address_range = 1024
        self._maximum_symbolic_read_size = 128

        self._default_write_strategy = [ 'norepeats',  'any' ]
        self._write_length_range = 1
        self._write_address_range = 1

        self._default_symbolic_write_strategy = [ 'symbolic_nonzero', 'any' ]
        self._symbolic_write_address_range = 17

        # reverse mapping
        self._name_mapping = cooldict.BranchingDict() if name_mapping is None else name_mapping
        self._hash_mapping = cooldict.BranchingDict() if hash_mapping is None else hash_mapping
        self._updated_mappings = set()

    #
    # Mappings
    #

    def addrs_for_name(self, n):
        '''
        Returns a set of addresses that contain expressions that contain a variable
        named n.
        '''
        if n in self._name_mapping: return set(self._name_mapping[n])
        else: return set()

    def addrs_for_hash(self, h):
        '''
        Returns a set of addresses that contain expressions that contain a variable
        with the hash of h.
        '''
        if h in self._hash_mapping: return set(self._hash_mapping[h])
        else: return set()

    def memory_objects_for_name(self, n):
        '''
        Returns a set of SimMemoryObjects that contain expressions that contain a variable
        with the name of n. This is useful for replacing those values, in one fell swoop,
        with replace_memory_object(), even if they've been partially overwritten.
        '''
        if n in self._name_mapping: return set([ self.mem[i] for i in self.addrs_for_name(n)])
        else: return set()

    def memory_objects_for_hash(self, n):
        '''
        Returns a set of SimMemoryObjects that contain expressions that contain a variable
        with the hash of h. This is useful for replacing those values, in one fell swoop,
        with replace_memory_object(), even if they've been partially overwritten.
        '''
        if n in self._name_mapping: return set([ self.mem[i] for i in self.addrs_for_hash(n)])
        else: return set()

    #
    # Memory object management
    #

    def replace_memory_object(self, old, new_content):
        '''
        Replaces the memory object 'old' with a new memory object containing
        'new_content'.

            @param old: a SimMemoryObject (i.e., one from memory_objects_for_hash() or
                        memory_objects_for_name())
            @param new_content: the content (claripy expression) for the new memory object
        '''

        if old.object.size() != new_content.size():
            raise SimMemoryError("memory objects can only be replaced by the same length content")

        new = SimMemoryObject(new_content, old.base)
        for b in range(old.base, old.base+old.length):
            try:
                if b not in self.mem or self.mem[b] is not old:
                    continue

                if isinstance(new.object, claripy.A):
                    self._update_mappings(b, new.object)
                self.mem[b] = new
            except KeyError:
                pass

    #
    # Symbolicizing!
    #

    def make_symbolic(self, addr, length, name):
        '''
        Replaces length bytes, starting at addr, with a symbolic variable named
        name. Adds a constraint equaling that symbolic variable to the value
        previously at addr, and returns the variable.
        '''
        l.debug("making %s bytes symbolic", length)

        r, read_constraints = self.load(addr, length)
        l.debug("... read constraints: %s", read_constraints)
        self.state.add_constraints(*read_constraints)

        v = self.state.BV(name, r.size())
        write_constraints = self.store(addr, v)
        self.state.add_constraints(*write_constraints)
        l.debug("... write constraints: %s", write_constraints)
        self.state.add_constraints(r == v)
        l.debug("... eq constraints: %s", r == v)
        return v

    #
    # Address concretization
    #

    def _concretize_strategy(self, v, s, limit, cache):
        r = None
        #if s == "norepeats_simple":
        #   if self.state.se.solution(v, self._repeat_min):
        #       l.debug("... trying super simple method.")
        #       r = [ self._repeat_min ]
        #       self._repeat_min += self._repeat_granularity
        #elif s == "norepeats_range":
        #   l.debug("... trying ranged simple method.")
        #   r = [ self.state.se.any_int(v, extra_constraints = [ v > self._repeat_min, v < self._repeat_min + self._repeat_granularity ]) ]
        #   self._repeat_min += self._repeat_granularity
        #elif s == "norepeats_min":
        #   l.debug("... just getting any value.")
        #   r = [ self.state.se.any_int(v, extra_constraints = [ v > self._repeat_min ]) ]
        #   self._repeat_min = r[0] + self._repeat_granularity
        if s == "norepeats":
            if self._repeat_expr is None:
                self._repeat_expr = self.state.BV("%s_repeat" % self.id, self.state.arch.bits)

            c = self.state.se.any_int(v, extra_constraints=self._repeat_constraints + [ v == self._repeat_expr ])
            self._repeat_constraints.append(self._repeat_expr != c)
            r = [ c ]
        elif s == "symbolic":
            # if the address concretizes to less than the threshold of values, try to keep it symbolic
            mx = self.state.se.max_int(v)
            mn = self.state.se.min_int(v)

            cache['max'] = mx
            cache['min'] = mn
            cache['solutions'].add(mx)
            cache['solutions'].add(mn)

            l.debug("... range is (%d, %d)", mn, mx)
            if mx - mn < limit:
                l.debug("... generating %d addresses", limit)
                r = self.state.se.any_n_int(v, limit)
                l.debug("... done")
        elif s == "symbolic_nonzero":
            # if the address concretizes to less than the threshold of values, try to keep it symbolic
            mx = self.state.se.max_int(v, extra_constraints=[v != 0])
            mn = self.state.se.min_int(v, extra_constraints=[v != 0])

            cache['max'] = mx
            cache['solutions'].add(mx)
            cache['solutions'].add(mn)

            l.debug("... range is (%d, %d)", mn, mx)
            if mx - mn < limit:
                l.debug("... generating %d addresses", limit)
                r = self.state.se.any_n_int(v, limit)
                l.debug("... done")
        elif s == "any":
            r = [ cache['solutions'].__iter__().next() ]

        return r, cache

    def _concretize_addr(self, v, strategy, limit):
        # if there's only one option, let's do it
        if not self.state.se.symbolic(v):
            l.debug("... concrete value")
            return [ self.state.se.any_int(v) ]

        if not self.state.satisfiable():
            raise SimMemoryError("Trying to concretize with unsat constraints.")

        l.debug("... concretizing address with limit %d", limit)

        cache = { }
        cache['solutions'] = { self.state.se.any_int(v) }

        for s in strategy:
            l.debug("... trying strategy %s", s)
            try:
                result, cache = self._concretize_strategy(v, s, limit, cache)
                if result is not None:
                    return result
                else:
                    l.debug("... failed (with None)")
            except SimUnsatError:
                l.debug("... failed (with exception)")
                continue

        raise SimMemoryError("Unable to concretize address with the provided strategy.")

    def concretize_write_addr(self, addr, strategy=None, limit=None):
        if type(addr) in {int, long}:
            return [addr]

        #l.debug("concretizing addr: %s with variables", addr.variables)
        if strategy is None:
            if any([ "multiwrite" in c for c in self.state.se.variables(addr) ]):
                l.debug("... defaulting to symbolic write!")
                strategy = self._default_symbolic_write_strategy
                limit = self._symbolic_write_address_range if limit is None else limit
            else:
                l.debug("... defaulting to concrete write!")
                strategy = self._default_write_strategy
                limit = self._write_address_range if limit is None else limit
        limit = self._write_address_range if limit is None else limit

        return self._concretize_addr(addr, strategy=strategy, limit=limit)

    def concretize_read_addr(self, addr, strategy=None, limit=None):
        '''
        Concretizes an address meant for reading.

            @param addr: an expression for the address
            @param strategy: the strategy to use for concretization
            @param limit: how many concrete values to limit the concretization to

            @returns a list of concrete addresses
        '''
        if type(addr) in {int, long}:
            return [addr]
        strategy = self._default_read_strategy if strategy is None else strategy
        limit = self._read_address_range if limit is None else limit

        return self._concretize_addr(addr, strategy=strategy, limit=limit)

    def _read_from(self, addr, num_bytes):
        missing = [ ]
        the_bytes = { }
        for i in range(0, num_bytes):
            try:
                b = self.mem[addr+i]
                if type(b) in (int, long, str):
                    b = self.state.BVV(b, 8)
                the_bytes[i] = b
            except KeyError:
                missing.append(i)

        if len(missing) > 0:
            name = "%s_%x" % (self.id, addr)
            b = self.state.se.Unconstrained(name, num_bytes*8)
            default_mo = SimMemoryObject(b, addr)
            for m in missing:
                the_bytes[m] = default_mo
                self._update_mappings(addr+m, default_mo.object)
                self.mem[addr+m] = default_mo

        buf = [ ]
        buf_size = 0
        last_expr = None
        for i,e in the_bytes.items() + [(num_bytes, None)]:
            if type(e) is not SimMemoryObject or e is not last_expr:
                if isinstance(last_expr, claripy.A):
                    buf.append(last_expr)
                    buf_size += 1
                elif type(last_expr) is SimMemoryObject:
                    buf.append(last_expr.bytes_at(addr+buf_size, i-buf_size))
                    buf_size = i
            last_expr = e

        if len(buf) > 1:
            r = self.state.se.Concat(*buf)
        else:
            r = buf[0]
        return r

    def load(self, dst, size, condition=None, fallback=None, bbl_addr=None, stmt_id=None):
        '''
        Loads size bytes from dst.

            @param dst: the address to load from
            @param size: the size (in bytes) of the load
            @param condition: a claripy expression representing a condition for a conditional load
            @param fallback: a fallback value if the condition ends up being False
            @bbl_addr: TODO
            @stmt_id: TODO

        There are a few possible return values. If no condition or fallback are passed in,
        then the return is the bytes at the address, in the form of a claripy expression.
        For example:

            <A BVV(0x41, 32)>

        On the other hand, if a condition and fallback are provided, the value is conditional:

            <A If(condition, BVV(0x41, 32), fallback)>
        '''

        if type(size) in (int, long):
            size = self.state.BVV(size, self.state.arch.bits)

        if self.state.se.symbolic(size):
            l.warning("Concretizing symbolic length. Much sad; think about implementing.")
            size_int = self.state.se.max_int(size, extra_constraints=[self.state.se.ULE(size, self._maximum_symbolic_read_size)])
            self.state.add_constraints(size == size_int)
            size = self.state.BVV(size_int, self.state.arch.bits)

        # get a concrete set of read addresses
        addrs = self.concretize_read_addr(dst)
        size = self.state.se.any_int(size)

        read_value = self._read_from(addrs[0], size)
        constraint_options = [ dst == addrs[0] ]

        for a in addrs[1:]:
            read_value = self.state.se.If(dst == a, self._read_from(a, size), read_value)
            constraint_options.append(dst == a)

        if len(constraint_options) > 1:
            load_constraint = self.state.se.Or(*constraint_options)
        else:
            load_constraint = constraint_options[0]

        if condition is not None:
            read_value = self.state.se.If(condition, read_value, fallback)
            load_constraint = self.state.se.Or(self.state.se.And(condition, load_constraint), self.state.se.Not(condition))

        return read_value, [ load_constraint ]

    def find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'. Note that,
        if you don't specify a default value, this search could cause the state to go
        unsat if no possible matching byte exists.

            @param start: the start address
            @param what: what to search for
            @param max_search: search at most this many bytes
            @param max_symbolic_bytes: search through at most this many symbolic bytes
            @param default: the default value, if what you're looking for wasn't found

            @returns an expression representing the address of the matching byte
        '''

        preload=True
        if type(start) in (int, long):
            start = self.state.BVV(start, self.state.arch.bits)

        constraints = [ ]
        remaining_symbolic = max_symbolic_bytes
        seek_size = len(what)/8
        symbolic_what = self.state.se.symbolic(what)
        l.debug("Search for %d bytes in a max of %d...", seek_size, max_search)

        if preload:
            all_memory = self.state.mem_expr(start, max_search, endness="Iend_BE")

        cases = [ ]
        match_indices = [ ]
        for i in itertools.count():
            l.debug("... checking offset %d", i)
            if i > max_search - seek_size:
                l.debug("... hit max size")
                break
            if remaining_symbolic is not None and remaining_symbolic == 0:
                l.debug("... hit max symbolic")
                break

            if preload:
                b = all_memory[max_search*8 - i*8 - 1 : max_search*8 - i*8 - seek_size*8]
            else:
                b = self.state.mem_expr(start + i, seek_size, endness="Iend_BE")
            cases.append([ b == what, start + i ])
            match_indices.append(i)

            if not self.state.se.symbolic(b) and not symbolic_what:
                #print "... checking", b, 'against', what
                if self.state.se.any_int(b) == self.state.se.any_int(what):
                    l.debug("... found concrete")
                    break
            else:
                if remaining_symbolic is not None:
                    remaining_symbolic -= 1

        if default is None:
            l.debug("... no default specified")
            default = 0
            constraints += [ self.state.se.Or(*[ c for c,_ in cases]) ]

        #l.debug("running ite_cases %s, %s", cases, default)
        r = self.state.se.ite_cases(cases, default)
        return r, constraints, match_indices

    def __contains__(self, dst):
        if type(dst) in (int, long):
            addr = dst
        elif self.state.se.symbolic(dst):
            try:
                addr = self._concretize_addr(dst, strategy=['allocated'], limit=1)[0]
            except SimMemoryError:
                return False
        else:
            addr = self.state.se.any_int(dst)
        return addr in self.mem

    #
    # Writes
    #

    def _mark_updated_mapping(self, d, m):
        if m in self._updated_mappings:
            return

        if m in d: d[m] = set(d[m])
        else: d[m] = set()
        self._updated_mappings.add(m)

    def _update_mappings(self, actual_addr, cnt):
        if not (options.REVERSE_MEMORY_NAME_MAP in self.state.options or
                options.REVERSE_MEMORY_HASH_MAP in self.state.options):
            return

        l.debug("Updating mappings at address 0x%x", actual_addr)

        if actual_addr in self.mem:
            l.debug("... removing old mappings")

            # remove this address for the old variables
            old_obj = self.mem[actual_addr]
            if isinstance(old_obj, SimMemoryObject):
                old_obj = old_obj.object

            if isinstance(old_obj, claripy.A):
                if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                    var_set = self.state.se.variables(old_obj)
                    for v in var_set:
                        self._mark_updated_mapping(self._name_mapping, v)
                        self._name_mapping[v].discard(actual_addr)
                        if len(self._name_mapping[v]) == 0:
                            self._name_mapping.pop(v, None)

                if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                    h = hash(old_obj)
                    self._mark_updated_mapping(self._hash_mapping, h)
                    self._hash_mapping[h].discard(actual_addr)
                    if len(self._hash_mapping[h]) == 0:
                        self._hash_mapping.pop(h, None)

        l.debug("... adding new mappings")
        if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
            # add the new variables to the mapping
            var_set = self.state.se.variables(cnt)
            for v in var_set:
                self._mark_updated_mapping(self._name_mapping, v)
                if v not in self._name_mapping:
                    self._name_mapping[v] = set()
                self._name_mapping[v].add(actual_addr)

        if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
            # add the new variables to the hash->addrs mapping
            h = hash(cnt)
            self._mark_updated_mapping(self._hash_mapping, h)
            if h not in self._hash_mapping:
                self._hash_mapping[h] = self.addrs_for_hash(h)
            self._hash_mapping[h].add(actual_addr)

    def _write_to(self, addr, cnt, size=None):
        cnt_size_bits = len(cnt)
        constraints = [ ]

        # here, we ensure the uuids are generated for every expression written to memory
        cnt.make_uuid()

        mo = SimMemoryObject(cnt, addr, length=size/8 if size is not None else None)

        if size is None:
            l.debug("... full length")

            for actual_addr in range(addr, addr + mo.length):
                l.debug("... updating mappings")
                self._update_mappings(actual_addr, cnt)
                l.debug("... writing 0x%x", actual_addr)
                self.mem[actual_addr] = mo
        else:
            if options.REVERSE_MEMORY_NAME_MAP in self.state.options or options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                l.warning("TODO: figure out a precise way to do reverse references with symbolic size")

            max_size = cnt_size_bits/8
            before_bytes = self._read_from(addr, max_size)
            for possible_size in range(max_size):
                before_byte = before_bytes[cnt_size_bits - possible_size*8 - 1 : cnt_size_bits - possible_size*8 - 8]
                after_byte = cnt[cnt_size_bits - possible_size*8 - 1 : cnt_size_bits - possible_size*8 - 8]
                new_byte = self.state.se.If(self.state.se.UGT(size, possible_size), after_byte, before_byte)
                self._write_to(addr + possible_size, new_byte)

            constraints += [ self.state.se.ULE(size, cnt_size_bits/8) ]

        return constraints

    def replace_all(self, old, new):
        '''
        Replaces all instances of expression old with expression new.

            @param old: a claripy expression. Must contain at least one named variable (to make
                        to make it possible to use the name index for speedup)
            @param new: the new variable to replace it with
        '''

        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options:
            raise SimMemoryError("replace_all is not doable without a reverse name mapping. Please add simuvex.o.REVERSE_MEMORY_NAME_MAP to the state options")

        if not isinstance(old, claripy.A) or not isinstance(new, claripy.A):
            raise SimMemoryError("old and new arguments to replace_all() must be claripy.A objects")

        if len(old.variables) == 0:
            raise SimMemoryError("old argument to replace_all() must have at least one named variable")

        memory_objects = set()
        for v in old.variables:
            memory_objects.update(self.memory_objects_for_name(v))

        for mo in memory_objects:
            self.replace_memory_object(mo, mo.object.replace(old, new))

    def store(self, dst, cnt, size=None, condition=None, fallback=None, bbl_addr=None, stmt_id=None): #pylint:disable=unused-argument
        l.debug("Doing a store...")

        addrs = self.concretize_write_addr(dst)
        if len(addrs) == 1:
            l.debug("... concretized to 0x%x", addrs[0])
            constraint = [ dst == addrs[0] ]
        else:
            l.debug("... concretized to %d values", len(addrs))
            constraint = [ self.state.se.Or(*[ dst == a for a in addrs ])  ]

        if len(addrs) == 1:
            c = self._write_to(addrs[0], cnt, size=size)
            constraint += c
        else:
            l.debug("... many writes")
            if size is None:
                length_expr = len(cnt)/8 # pylint:disable=maybe-no-member
            else:
                length_expr = size

            for a in addrs:
                ite_length = self.state.se.If(dst == a, length_expr, self.state.BVV(0))
                c = self._write_to(a, cnt, size=ite_length)
                constraint += c

        l.debug("... done")
        return constraint

    def store_with_merge(self, dst, cnt, size=None, condition=None, fallback=None, bbl_addr=None, stmt_id=None): #pylint:disable=unused-argument
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
            assert isinstance(old_val, claripy.A)

            # FIXME: This is a big hack
            def is_reversed(o):
                if isinstance(o, claripy.A) and o.op == 'Reverse':
                    return True
                return False

            def can_be_reversed(o):
                if isinstance(o, claripy.A) and (isinstance(o.model, claripy.BVV) or \
                                     (isinstance(o.model, claripy.StridedInterval) and o.model.is_integer())):
                    return True
                return False

            reverse_it = False
            if is_reversed(cnt):
                if is_reversed(old_val):
                    cnt = cnt.args[0]
                    old_val = old_val.args[0]
                    reverse_it = True
                elif can_be_reversed(old_val):
                    cnt = cnt.args[0]
                    reverse_it = True
            merged_val = self.state.StridedInterval(bits=len(old_val), to_conv=old_val)
            merged_val = merged_val.union(cnt)
            if reverse_it:
                merged_val = merged_val.reversed

            # Write the new value
            self.store(addr, merged_val, size=size)

        return []

    # Return a copy of the SimMemory
    def copy(self):
        #l.debug("Copying %d bytes of memory with id %s." % (len(self.mem), self.id))
        c = SimSymbolicMemory(self.mem.branch(),
                              memory_id=self.id,
                              repeat_min=self._repeat_min,
                              repeat_constraints=self._repeat_constraints,
                              repeat_expr=self._repeat_expr,
                              name_mapping=self._name_mapping.branch(),
                              hash_mapping=self._hash_mapping.branch())
        return c

    # Gets the set of changed bytes between self and other.
    def changed_bytes(self, other):
        common_ancestor = self.mem.common_ancestor(other.mem)
        if common_ancestor == None:
            l.warning("Merging without a common ancestor. This will be very slow.")
            our_changes, our_deletions = set(self.mem.keys()), set()
            their_changes, their_deletions = set(other.mem.keys()), set()
        else:
            our_changes, our_deletions = self.mem.changes_since(common_ancestor)
            their_changes, their_deletions = other.mem.changes_since(common_ancestor)

        #both_changed = our_changes & their_changes
        #ours_changed_only = our_changes - both_changed
        #theirs_changed_only = their_changes - both_changed
        #both_deleted = their_deletions & our_deletions
        #ours_deleted_only = our_deletions - both_deleted
        #theirs_deleted_only = their_deletions - both_deleted

        candidates = our_changes | our_deletions | their_changes | their_deletions
        differences = set()

        for c in candidates:
            if c not in self.mem and c in other.mem:
                differences.add(c)
            elif c in self.mem and c not in other.mem:
                differences.add(c)
            else:
                if type(self.mem[c]) is not SimMemoryObject:
                    self.mem[c] = SimMemoryObject(self.state.se.BVV(ord(self.mem[c]), 8), c)
                if type(other.mem[c]) is not SimMemoryObject:
                    other.mem[c] = SimMemoryObject(self.state.se.BVV(ord(other.mem[c]), 8), c)

                if c in self.mem and self.mem[c] != other.mem[c]:
                    l.debug("Two different values %s %s" % (self.mem[c].object.model, other.mem[c].object.model))
                    differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    # Unconstrain a byte
    def unconstrain_byte(self, addr):
        unconstrained_byte = self.state.BV("%s_unconstrain_0x%x" % (self.id, addr), 8)
        self.store(addr, unconstrained_byte)

    # Replaces the differences between self and other with unconstrained bytes.
    def unconstrain_differences(self, other):
        changed_bytes = self.changed_bytes(other)
        l.debug("Will unconstrain %d %s bytes", len(changed_bytes), self.id)
        for b in changed_bytes:
            self.unconstrain_byte(b)

    # Merge this SimMemory with the other SimMemory
    def merge(self, others, flag, flag_values):
        changed_bytes = set()
        for o in others: #pylint:disable=redefined-outer-name
            self._repeat_constraints += o._repeat_constraints
            changed_bytes |= self.changed_bytes(o)

        l.debug("Merging %d bytes", len(changed_bytes))
        l.debug("... %s has changed bytes %s", self.id, changed_bytes)

        merging_occured = len(changed_bytes) > 0
        self._repeat_min = max(other._repeat_min for other in others)

        all_memories = others + [ self ]
        constraints = [ ]

        merged_to = None
        for b in sorted(changed_bytes):
            if merged_to is not None and not b >= merged_to:
                l.debug("merged_to = %d ... already merged byte 0x%x", merged_to, b)
                continue
            l.debug("... on byte 0x%x", b)

            memory_objects = [ ]
            unconstrained_in = [ ]

            # first get a list of all memory objects at that location, and
            # all memories that don't have those bytes
            for sm, fv in zip(all_memories, flag_values):
                if b in sm.mem:
                    l.debug("... present in %s", fv)
                    memory_objects.append((sm.mem[b], fv))
                else:
                    l.debug("... not present in %s", fv)
                    unconstrained_in.append((sm, fv))

            # get the size that we can merge easily. This is the minimum of
            # the size of all memory objects and unallocated spaces.
            min_size = min([ mo.length - (b-mo.base) for mo,_ in memory_objects ])
            for um in unconstrained_in:
                for i in range(0, min_size):
                    if b+i in um:
                        min_size = i
                        break
            merged_to = b + min_size
            l.debug("... determined minimum size of %d", min_size)

            # Now, we have the minimum size. We'll extract/create expressions of that
            # size and merge them
            extracted = [ (mo.bytes_at(b, min_size), fv) for mo,fv in memory_objects ]
            created = [ (self.state.se.Unconstrained("merge_uc_%s_%x" % (uc.id, b), min_size*8), fv) for uc,fv in unconstrained_in ]
            to_merge = extracted + created

            if options.ABSTRACT_MEMORY in self.state.options:
                merged_val = to_merge[0][0]
                for tm,_ in to_merge[1:]:
                    if options.REFINE_AFTER_WIDENING in self.state.options:
                        l.debug("Refining %s %s...", merged_val.model, tm.model)
                        merged_val = tm
                        l.debug("... Refined to %s", merged_val.model)
                    elif options.WIDEN_ON_MERGE in self.state.options:
                        l.debug("Widening %s %s...", merged_val.model, tm.model)
                        merged_val = merged_val.widen(tm)
                        l.debug('... Widened to %s', merged_val.model)
                    else:
                        l.debug("Merging %s %s...", merged_val.model, tm.model)
                        merged_val = merged_val.union(tm)
                        l.debug("... Merged to %s", merged_val.model)
                    #import ipdb; ipdb.set_trace()
                self.store(b, merged_val)
            else:
                merged_val = self.state.BVV(0, min_size*8)
                for tm,fv in to_merge:
                    merged_val = self.state.se.If(flag == fv, tm, merged_val)
                self.store(b, merged_val)
                constraints.append(self.state.se.Or(*[ flag == fv for fv in flag_values ]))

        return merging_occured, constraints

    def concrete_parts(self):
        '''
        Return a dict containing the concrete values in memory.
        '''
        d = { }
        for k,v in self.mem.iteritems():
            if not self.state.se.symbolic(v):
                d[k] = self.state.se.any_expr(v)

        return d

    def dbg_print(self):
        '''
        Print out debugging information.
        '''
        lst = []
        for i, addr in enumerate(self.mem.iterkeys()):
            lst.append(addr)
            if i >= 20:
                break

        for addr in sorted(lst):
            data = self.mem[addr]
            if type(data) is SimMemoryObject:
                memobj = data
                print "%xh : (%s)[%d]" % (addr, memobj, addr - memobj.base)
            else:
                print "%xh : <default data>" % (addr)

SimSymbolicMemory.register_default('memory', SimSymbolicMemory)
SimSymbolicMemory.register_default('registers', SimSymbolicMemory)
from ..s_errors import SimUnsatError, SimMemoryError
from .. import s_options as options
