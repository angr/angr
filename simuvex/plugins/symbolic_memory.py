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
    def __init__(self, offset, object, length=1): #pylint:disable=redefined-builtin
        self._offset = offset
        self._object = object
        self._length = length

    @staticmethod
    def get_length(bits):
        return (bits + 7) / 8

    @staticmethod
    def byterefs(obj):
        refs = []
        for i in xrange(SimMemoryObject.get_length(len(obj))):
            refs.append(SimMemoryObject(i, obj))

        return refs

    def size(self):
        return self._length * 8

    def __len__(self):
        return self.size()

    @property
    def offset(self):
        return self._offset

    @property
    def length(self):
        return self._length

    @property
    def object(self):
        return self._object

    def concat(self, arg):
        '''
        Concatenate with another guy
        '''
        if type(arg) is not SimMemoryObject:
            return False, self

        if self.object is not arg.object:
            return False, self

        if self.offset + self.length == arg.offset:
            if self.length + arg.length == SimMemoryObject.get_length(len(self.object)):
                return True, self.object
            else:
                newref = SimMemoryObject(self.offset, self.object, self.length + arg.length)
                return True, newref
        else:
            return False, self

    def eval(self):
        data = self.object
        memobj_size = SimMemoryObject.get_length(len(data))
        start = (memobj_size - self.offset) * 8 - 1
        end = (memobj_size - self.offset - self.length) * 8

        return data[start : end]

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

    #
    # Mappings
    #

    def addrs_for_name(self, n):
        if n in self._name_mapping: return set(self._name_mapping[n])
        else: return set()

    def addrs_for_hash(self, h):
        if h in self._hash_mapping: return set(self._hash_mapping[h])
        else: return set()

    #
    # Symbolicizing!
    #

    def make_symbolic(self, addr, length, name):
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
        if type(addr) in {int, long}:
            return [addr]
        strategy = self._default_read_strategy if strategy is None else strategy
        limit = self._read_address_range if limit is None else limit

        return self._concretize_addr(addr, strategy=strategy, limit=limit)

    #
    # Reading/checking/etc
    #

    def _concat(self, *args):
        '''
        Concatenate data inside memory, including MemoryObjectByteRefs.
        '''

        buff = []

        # Scan in the buff list and concatenate any MemoryObjectByteRef instances
        # TODO:

        tmp = None
        for elem in args:
            if type(elem) is not SimMemoryObject:
                if tmp is not None:
                    buff.append(tmp.eval())
                    tmp = None
                buff.append(elem)
            else:
                if tmp is None:
                    tmp = elem
                else:
                    ret, tmp = tmp.concat(elem)
                    if not ret:
                        # Concatenation failed
                        buff.append(tmp.eval())
                        if type(elem) is SimMemoryObject:
                            tmp = elem
                        else:
                            tmp = None
                            buff.append(elem)
                    else:
                        if type(tmp) is not SimMemoryObject:
                            buff.append(tmp)
                            tmp = None
                        # Concatenation succeeded
                        continue
        if tmp is not None:
            buff.append(tmp.eval())
            tmp = None

        if len(buff) == 1:
            r = buff[0]
        else:
            r = self.state.se.Concat(*buff)

        return r

    def _read_from(self, addr, num_bytes):
        buff = [ ]
        for i in range(0, num_bytes):
            try:
                b = self.mem[addr+i]
                if type(b) in (int, long, str):
                    b = self.state.BVV(b, 8)
                buff.append(b)
            except KeyError:
                if options.ABSTRACT_MEMORY in self.state.options:
                    # We are using the abstract memory!
                    b = self.state.se.StridedInterval(bits=8,
                                                      stride=1,
                                                      lower_bound=0,
                                                      upper_bound=0)
                    l.debug("Creating new default memory byte %s @ 0x%08x", b, addr + i)
                else:
                    mem_id = "%s_%x" % (self.id, addr+i)
                    l.debug("Creating new symbolic memory byte %s", mem_id)
                    b = self.state.BV(mem_id, 8)

                self.mem[addr+i] = b
                buff.append(b)

        r = self._concat(*buff)

        return r

    def load(self, dst, size, condition=None, fallback=None, bbl_addr=None, stmt_id=None):
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
        Returns the address of bytes equal to 'what', starting from 'start'.
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

    def _write_to(self, addr, cnt, size=None):
        cnt_size_bits = len(cnt)
        constraints = [ ]

        new_name_mapping = { }
        new_hash_mapping = { }

        # here, we ensure the uuids are generated for every expression written to memory
        cnt.uuid #pylint:disable=pointless-statement

        if size is None:
            l.debug("... full length")

            for offset, ref in enumerate(SimMemoryObject.byterefs(cnt)):
                if options.REVERSE_MEMORY_NAME_MAP in self.state.options or options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                    if addr+offset in self.mem:
                        l.debug("... removing old mappings")

                        # remove this address for the old variables
                        old_obj = self.mem[addr+offset]
                        if isinstance(old_obj, SimMemoryObject): old_obj = old_obj.object

                        if isinstance(old_obj, claripy.E):
                            if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                                var_set = self.state.se.variables(old_obj)
                                for v in var_set:
                                    if v not in new_name_mapping: new_name_mapping[v] = self.addrs_for_name(v)
                                    new_name_mapping[v].discard(addr+offset)

                            if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                                h = hash(old_obj)
                                if h not in new_hash_mapping: new_hash_mapping[h] = self.addrs_for_hash(h)
                                new_hash_mapping[h].discard(addr+offset)

                    l.debug("... adding new mappings")
                    if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                        # add the new variables to the mapping
                        var_set = self.state.se.variables(cnt)
                        for v in var_set:
                            if v not in new_name_mapping: new_name_mapping[v] = self.addrs_for_name(v)
                            new_name_mapping[v].add(addr+offset)

                    if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                        # add the new variables to the hash->addrs mapping
                        h = hash(cnt)
                        if h not in new_hash_mapping: new_hash_mapping[h] = self.addrs_for_hash(h)
                        new_hash_mapping[h].add(addr+offset)

                # and do the write
                l.debug("... writing 0x%x", addr + offset)
                self.mem[addr + offset] = ref
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

        for n,mapping in new_name_mapping.iteritems():
            if len(mapping) == 0: self._name_mapping.pop(n, None)
            else: self._name_mapping[n] = mapping
        for h,mapping in new_hash_mapping.iteritems():
            if len(mapping) == 0: self._hash_mapping.pop(h, None)
            else: self._hash_mapping[h] = mapping

        return constraints

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
            assert type(old_val).__name__ == 'E'

            # FIXME: This is a big hack
            def is_reversed(o):
                if type(o).__name__ == 'E' and type(o._model).__name__ == 'A' and \
                    o._model.op == 'Reverse':
                    return True
                return False

            def can_be_reversed(o):
                if type(o).__name__ == 'E' and \
                        (type(o._model).__name__ == 'BVV' or \
                                 (type(o._model).__name__ == 'StridedInterval' and o._model.is_integer())):
                    return True
                return False

            reverse_it = False
            if is_reversed(cnt):
                if is_reversed(old_val):
                    cnt = cnt._model.args[0]
                    old_val = old_val._model.args[0]
                    reverse_it = True
                elif can_be_reversed(old_val):
                    cnt = cnt._model.args[0]
                    reverse_it = True
            merged_val = self.state.StridedInterval(bits=len(old_val), to_conv=old_val)
            merged_val = merged_val.union(cnt)
            if reverse_it:
                merged_val = merged_val.reverse()

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

        return our_changes | our_deletions | their_changes | their_deletions

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

        import ipdb; ipdb.set_trace()

        merging_occured = len(changed_bytes) > 0

        self._repeat_min = max(other._repeat_min for other in others)

        constraints = [ ]
        for addr in changed_bytes:
            if options.ABSTRACT_MEMORY in self.state.options:
                # Directly merge every single byte and build no constraint at all
                merged_val = self.load(addr, 1)[0]
                for o in others:
                    other_val = o.load(addr, 1)[0]
                    merged_val = merged_val.union(other_val)

                self.store(addr, merged_val)
            else:
                # NOTE: This assumes that loading a concrete addr can't create new constraints.
                #       This is true now, but who knows if it'll be true in the future.
                alternatives = [ self.load(addr, 1)[0] ]
                for o in others: #pylint:disable=redefined-outer-name
                    alternatives.append(o.load(addr, 1)[0])

                and_constraints = [ ]
                merged_val = self.state.BV("%s_merge_0x%x" % (self.id, addr), 8)
                for a, fv in zip(alternatives, flag_values):
                    and_constraints.append(self.state.se.And(flag == fv, merged_val == a))
                self.store(addr, merged_val)

                constraints.append(self.state.se.Or(*and_constraints))
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

SimSymbolicMemory.register_default('memory', SimSymbolicMemory)
SimSymbolicMemory.register_default('registers', SimSymbolicMemory)
from ..s_errors import SimUnsatError, SimMemoryError
from .. import s_options as options
