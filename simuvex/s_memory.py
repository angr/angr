#!/usr/bin/env python

import logging
import cooldict
import collections
import itertools

l = logging.getLogger("simuvex.simmemory")

import symexec as se
from .s_exception import SimError
from .s_value import ConcretizingException

# Conventions used:
# 1) The whole memory is readable
# 2) Memory locations are by default writable
# 3) Memory locations are by default not executable

class SimMemoryError(SimError):
	pass

class Vectorizer(cooldict.CachedDict):
	def __init__(self, backer):
		super(Vectorizer, self).__init__(backer)
		self.cooldict_ignore = True

	def default_cacher(self, k):
		b = self.backer[k]
		if type(b) in ( int, str ):
			b = se.BitVecVal(ord(self.backer[k]), 8)

		self.cache[k] = b
		return b

class Concretizer(collections.MutableMapping):
	def __init__(self, memory):
		self.memory = memory

	def __getitem__(self, k):
		return self.memory.state.expr_value(self.memory.load(k, 1)[0]).any()

	def __setitem__(self, k, v):
		raise NotImplementedError("TODO: writes") # TODO

	def __delitem__(self, k):
		raise NotImplementedError("TODO: writes") # TODO

	def __iter__(self):
		return self.memory.mem.__iter__()

	def __len__(self):
		return len(list(self.__iter__()))

from .s_state import SimStatePlugin
class SimMemory(SimStatePlugin):
	def __init__(self, backer=None, memory_id="mem", repeat_min=None, repeat_constraints=None, repeat_expr=None, write_strategy=None, read_strategy=None):
		SimStatePlugin.__init__(self)
		if backer is None:
			backer = cooldict.BranchingDict()

		if not isinstance(backer, cooldict.BranchingDict):
			if not isinstance(backer, Vectorizer):
				backer = Vectorizer(backer)
			backer = cooldict.BranchingDict(backer)

		self.mem = backer
		self.id = memory_id

		# for the norepeat stuff
		self._repeat_constraints = [ ] if repeat_constraints is None else repeat_constraints
		self._repeat_expr = repeat_expr
		self._repeat_granularity = 0x10000
		self._repeat_min = 0x13370000 if repeat_min is None else repeat_min

		# default strategies
		self._read_address_range = 1024
		self._write_address_range = 1
		self._write_length_range = 1
		self._default_write_strategy = write_strategy if write_strategy is not None else [ "norepeats_simple" ]
		self._default_read_strategy = read_strategy if read_strategy is not None else ['symbolic', 'any']

	#
	# Address concretization
	#

	def _concretize_strategy(self, v, s, limit):
		r = None
		if s == "norepeats_simple":
			if v.is_solution(self._repeat_min):
				l.debug("... trying super simple method.")
				r = [ self._repeat_min ]
				self._repeat_min += self._repeat_granularity
			else:
				try:
					l.debug("... trying ranged simple method.")
					r = [ v.any(extra_constraints = [ v.expr > self._repeat_min, v.expr < self._repeat_min + self._repeat_granularity ]) ]
					self._repeat_min += self._repeat_granularity
				except ConcretizingException:
					try:
						l.debug("... just getting any value.")
						r = [ v.any(extra_constraints = [ v.expr > self._repeat_min ]) ]
						self._repeat_min = r[0] + self._repeat_granularity
					except ConcretizingException:
						l.debug("Unable to concretize to non-taken address.")

			#print "CONRETIZED TO:", hex(r[0])
			#import ipdb; ipdb.set_trace()
		if s == "norepeats":
			if self._repeat_expr is None:
				self._repeat_expr = self.state.new_symbolic("%s_repeat" % self.id, self.state.arch.bits)

			try:
				c = v.any(extra_constraints=self._repeat_constraints + [ v.expr == self._repeat_expr ])
				self._repeat_constraints.append(self._repeat_expr != c)
				r = [ c ]
			except ConcretizingException:
				l.debug("Unable to concretize to non-taken address.")
		if s == "symbolic":
			# if the address concretizes to less than the threshold of values, try to keep it symbolic
			mx = v.max()
			mn = v.min()
			l.debug("... range is (%d, %d)", mn, mx)
			if mx - mn < limit:
				l.debug("... generating %d addresses", limit)
				r = v.any_n(limit)
				l.debug("... done")
		if s == "symbolic_nonzero":
			# if the address concretizes to less than the threshold of values, try to keep it symbolic
			mx = v.max(lo=1)
			mn = v.min(lo=1)
			l.debug("... range is (%d, %d)", mn, mx)
			if mx - mn < limit:
				l.debug("... generating %d addresses", limit)
				r = v.any_n(limit)
				l.debug("... done")
		if s == "any":
			r = [ v.any() ]

		return r

	def _concretize_addr(self, v, strategy, limit):
		if v.is_symbolic() and not v.satisfiable():
			raise SimMemoryError("Trying to concretize with unsat constraints.")

		# if there's only one option, let's do it
		if v.is_unique():
			return [ v.any() ]

		l.debug("Concretizing address with limit %d", limit)

		for s in strategy:
			l.debug("... trying strategy %s", s)
			result = self._concretize_strategy(v, s, limit)
			if result is not None:
				return result

		raise SimMemoryError("Unable to concretize address with the provided strategy.")

	def concretize_write_addr(self, addr, strategy=None, limit=None):
		strategy = self._default_write_strategy if strategy is None else strategy
		limit = self._write_address_range if limit is None else limit

		return self._concretize_addr(addr, strategy=strategy, limit=limit)

	def concretize_read_addr(self, addr, strategy=None, limit=None):
		strategy = self._default_read_strategy if strategy is None else strategy
		limit = self._read_address_range if limit is None else limit

		return self._concretize_addr(addr, strategy=strategy, limit=limit)

	#
	# Reading/checking/etc
	#

	def _read_from(self, addr, num_bytes):
		buff = [ ]
		for i in range(0, num_bytes):
			try:
				buff.append(self.mem[addr+i])
			except KeyError:
				mem_id = "%s_%x" % (self.id, addr+i)
				l.debug("Creating new symbolic memory byte %s", mem_id)
				b = self.state.new_symbolic(mem_id, 8)
				self.mem[addr+i] = b
				buff.append(b)

		if len(buff) == 1:
			r = buff[0]
		else:
			r = se.Concat(*buff)

		if o.SIMPLIFY_READS in self.state.options:
			l.debug("... simplifying")
			r = se.simplify_expression(r)
		return r

	def load(self, dst, size, strategy=None, limit=None):
		if type(dst) in (int, long):
			return self._read_from(dst, size), [ ]

		if dst.is_unique():
			return self._read_from(dst.any(), size), [ ]

		# otherwise, get a concrete set of read addresses
		addrs = self.concretize_read_addr(dst, strategy=strategy, limit=limit)

		# if there's a single address, it's easy
		if len(addrs) == 1:
			return self._read_from(addrs[0], size), [ dst.expr == addrs[0] ]

		# otherwise, create a new symbolic variable and return the mess of constraints and values
		m = self.state.new_symbolic("%s_addr" % self.id, size*8)
		e = se.Or(*[ se.And(m == self._read_from(addr, size), dst.expr == addr) for addr in addrs ])
		return m, [ e ]

	def find(self, start, what, max_search, min_search=None, max_symbolic=None, preload=True):
		'''
		Returns the address of bytes equal to 'what', starting from 'start'.
		'''

		remaining_symbolic = max_symbolic
		seek_size = what.size()/8
		symbolic_what = se.is_symbolic(what)
		l.debug("Search for %d bytes...", seek_size)

		if preload:
			all_memory = self.state.mem_expr(start, max_search, endness="Iend_BE")

		cases = [ ]
		match_indices = [ ]
		for i in itertools.count():
			l.debug("... checking offset %d", i)
			if min_search is None or i > min_search:
				if max_search is not None and i > max_search:
					l.debug("... hit max size")
					break
				if remaining_symbolic is not None and remaining_symbolic == 0:
					l.debug("... hit max symbolic")
					break

			if preload:
				b = se.Extract(max_search*8 - i*8 - 1, max_search*8 - i*8 - 8, all_memory)
			else:
				b = self.state.mem_expr(start + i, seek_size, endness="Iend_BE")
			cases.append([ b == what, start + i ])
			match_indices.append(i)

			if not se.is_symbolic(b) and not symbolic_what:
				#print "... checking", b, 'against', what
				if se.concretize_constant(b == what):
					l.debug("... found concrete")
					break
			else:
				if remaining_symbolic is not None:
					remaining_symbolic -= 1

		r, c = sim_cases(self.state, cases, sym_name=self.id + "_find", sym_size=self.state.arch.bits, sequential=True)
		return r, c, match_indices # pylint:disable=undefined-loop-variable

	def __contains__(self, dst):
		if type(dst) in (int, long):
			addr = dst
		elif dst.is_symbolic():
			try:
				addr = self._concretize_addr(dst, strategy=['allocated'], limit=1)[0]
			except SimMemoryError:
				return False
		else:
			addr = dst.any()
		return addr in self.mem

	#
	# Writes
	#

	def _write_to(self, addr, cnt, symbolic_length=None):
		cnt_size = cnt.size()
		constraints = [ ]

		if symbolic_length is None:
			if cnt_size == 8:
				self.mem[addr] = cnt
			else:
				for off in range(0, cnt_size, 8):
					target = addr + off/8
					new_content = se.Extract(cnt_size - off - 1, cnt_size - off - 8, cnt)
					self.mem[target] = new_content
		elif not symbolic_length.is_symbolic():
			self._write_to(addr, se.Extract(cnt_size-1, cnt_size-(symbolic_length.any()*8), cnt))
		else:
			#min_size = symbolic_length.min()
			#max_size = min(cnt_size/8, symbolic_length.max())
			#if min_size > max_size:
			#	raise Exception("Min symbolic length greater than provided content.")

			#if min_size > 0:
			#	self._write_to(addr, se.Extract(cnt_size-1, cnt_size-min_size*8, cnt))

			max_size = cnt_size/8
			before_bytes = self._read_from(addr, max_size)
			for size in range(max_size):
				before_byte = se.Extract(cnt_size - size*8 - 1, cnt_size - size*8 - 8, before_bytes)
				after_byte = se.Extract(cnt_size - size*8 - 1, cnt_size - size*8 - 8, cnt)

				new_byte, c = sim_ite(self.state, se.UGT(symbolic_length.expr, size), after_byte, before_byte, sym_name=self.id+"_var_length", sym_size=8)
				self._write_to(addr + size, new_byte)
				constraints += c

			constraints += [ se.ULE(symbolic_length.expr, cnt_size/8) ]

		return constraints

	def store(self, dst, cnt, strategy=None, limit=None, symbolic_length=None):
		l.debug("Doing a store...")

		if o.SIMPLIFY_WRITES in self.state.options:
			l.debug("... simplifying")
			cnt = se.simplify_expression(cnt)

		if type(dst) in (int, long):
			l.debug("... int")
			addrs = [ dst ]
			constraint = [ ]
		elif dst.is_unique():
			l.debug("... unique")
			addrs = [ dst.any() ]
			constraint = [ ]
		else:
			l.debug("... symbolic")
			addrs = self.concretize_write_addr(dst, strategy=strategy, limit=limit)
			if len(addrs) == 1:
				l.debug("... concretized to 0x%x", addrs[0])
				constraint = [ dst.expr == addrs[0] ]
			else:
				l.debug("... concretized to %d values", len(addrs))
				constraint = [ se.Or(*[ dst.expr == a for a in addrs ])  ]

		if len(addrs) == 1:
			c = self._write_to(addrs[0], cnt, symbolic_length=symbolic_length)
			constraint += c
		else:
			if symbolic_length is None:
				length_expr = cnt.size()/8 # pylint:disable=maybe-no-member
			else:
				length_expr = symbolic_length.expr

			for a in addrs:
				ite_length, ite_constraints = sim_ite(self.state, dst.expr == a, length_expr, 0, sym_name="multiaddr_write_length", sym_size=self.state.arch.bits)
				c = self._write_to(a, cnt, symbolic_length = self.state.expr_value(ite_length))

				constraint += ite_constraints + c

		return constraint

	# Return a copy of the SimMemory
	def copy(self):
		#l.debug("Copying %d bytes of memory with id %s." % (len(self.mem), self.id))
		c = SimMemory(self.mem.branch(), memory_id=self.id, repeat_min=self._repeat_min, repeat_constraints=self._repeat_constraints, repeat_expr=self._repeat_expr, write_strategy=self._default_write_strategy, read_strategy=self._default_read_strategy)
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
		unconstrained_byte = self.state.new_symbolic("%s_unconstrain_0x%x" % (self.id, addr), 8)
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

		self._repeat_min = max(other._repeat_min for other in others)

		constraints = [ ]
		for addr in changed_bytes:
			# NOTE: This assumes that loading a concrete addr can't create new constraints.
			#		This is true now, but who knows if it'll be true in the future.
			alternatives = [ self.load(addr, 1)[0] ]
			for o in others: #pylint:disable=redefined-outer-name
				alternatives.append(o.load(addr, 1)[0])

			and_constraints = [ ]
			merged_val = self.state.new_symbolic("%s_merge_0x%x" % (self.id, addr), 8)
			for a, fv in zip(alternatives, flag_values):
				and_constraints.append(se.And(flag == fv, merged_val == a))
			self.store(addr, merged_val)

			constraints.append(se.Or(*and_constraints))
		return constraints

	def concrete_parts(self):
		'''
		Return a dict containing the concrete values in memory.
		'''
		d = { }
		for k,v in self.mem.iteritems():
			if not se.is_symbolic(v):
				d[k] = se.concretize_constant(v)

		return d

SimMemory.register_default('memory', SimMemory)
SimMemory.register_default('registers', SimMemory)
from .s_helpers import sim_ite, sim_cases
from . import s_options as o
