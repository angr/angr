#!/usr/bin/env python

import logging
import cooldict

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

from .s_state import SimStatePlugin
class SimMemory(SimStatePlugin):
	def __init__(self, backer=None, memory_id="mem", repeat_constraints=None, repeat_expr=None, write_strategies=None, read_strategies=None):
		SimStatePlugin.__init__(self)
		if backer is None:
			backer = cooldict.BranchingDict()

		if not isinstance(backer, cooldict.BranchingDict):
			if not isinstance(backer, Vectorizer):
				backer = Vectorizer(backer)
			backer = cooldict.BranchingDict(backer)

		self.mem = backer
		self.limit = 1024
		self.id = memory_id

		# for the norepeat stuff
		self.repeat_constraints = [ ] if repeat_constraints is None else repeat_constraints
		self.repeat_expr = repeat_expr

		# default strategies
		self.write_strategies = write_strategies if write_strategies is not None else [ "free", "writeable", "any" ]
		self.read_strategies = read_strategies if read_strategies is not None else ['symbolic', 'any']

	def read_from(self, addr, num_bytes):
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
			return buff[0]
		else:
			return se.Concat(*buff)

	def write_to(self, addr, cnt):
		for off in range(0, cnt.size(), 8):
			target = addr + off/8
			new_content = se.Extract(cnt.size() - off - 1, cnt.size() - off - 8, cnt)
			self.mem[target] = new_content

	def concretize_addr(self, v, strategies):
		if v.is_symbolic() and not v.satisfiable():
			raise SimMemoryError("Trying to concretize with unsat constraints.")

		# if there's only one option, let's do it
		if v.is_unique():
			return [ v.any() ]

		for s in strategies:
			if s == "norepeats":
				if self.repeat_expr is None:
					self.repeat_expr = self.state.new_symbolic("%s_repeat" % self.id, self.state.arch.bits)

				try:
					c = v.any(extra_constraints=self.repeat_constraints + [ v.expr == self.repeat_expr ])
					self.repeat_constraints.append(self.repeat_expr != c)
					return [ c ]
				except ConcretizingException:
					l.debug("Unable to concretize to non-taken address.")
					continue
			if s == "free":
				pass
			if s == "allocated":
				pass
			if s == "writeable":
				# TODO
				pass
			if s == "executable":
				# TODO
				pass
			if s == "symbolic":
				# if the address concretizes to less than the threshold of values, try to keep it symbolic
				if v.max() - v.min() < self.limit:
					return v.any_n(self.limit)
			if s == "any":
				return [ v.any() ]

		raise SimMemoryError("Unable to concretize address with the provided strategies.")

	def concretize_write_addr(self, dst):
		return self.concretize_addr(dst, strategies = self.write_strategies)

	def concretize_read_addr(self, dst):
		return self.concretize_addr(dst, strategies=self.read_strategies)

	def __contains__(self, dst):
		if type(dst) in (int, long):
			addr = dst
		elif dst.is_symbolic():
			try:
				addr = self.concretize_addr(dst, strategies=['allocated'])[0]
			except SimMemoryError:
				return False
		else:
			addr = dst.any()

		return addr in self.mem

	def store(self, dst, cnt):
		if type(dst) in (int, long):
			addr = dst
			constraint = [ ]
		elif dst.is_unique():
			addr = dst.any()
			constraint = [ ]
		else:
			addr = self.concretize_write_addr(dst)[0]
			constraint = [ dst.expr == addr ]

		self.write_to(addr, cnt)
		return constraint

	def load(self, dst, size):
		if type(dst) in (int, long):
			return self.read_from(dst, size), [ ]

		if dst.is_unique():
			return self.read_from(dst.any(), size), [ ]

		# otherwise, get a concrete set of read addresses
		addrs = self.concretize_read_addr(dst)

		# if there's a single address, it's easy
		if len(addrs) == 1:
			return self.read_from(addrs[0], size), [ dst.expr == addrs[0] ]

		# otherwise, create a new symbolic variable and return the mess of constraints and values
		m = self.state.new_symbolic("%s_addr" % self.id, size*8)
		e = se.Or(*[ se.And(m == self.read_from(addr, size), dst.expr == addr) for addr in addrs ])
		return m, [ e ]

	# Return a copy of the SimMemory
	def copy(self):
		#l.debug("Copying %d bytes of memory with id %s." % (len(self.mem), self.id))
		c = SimMemory(self.mem.branch(), memory_id=self.id, repeat_constraints=self.repeat_constraints, repeat_expr=self.repeat_expr, write_strategies=self.write_strategies, read_strategies=self.read_strategies)
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
		for o in others:
			self.repeat_constraints += o.repeat_constraints
			changed_bytes |= self.changed_bytes(o)

		constraints = [ ]
		for addr in changed_bytes:
			# NOTE: This assumes that loading a concrete addr can't create new constraints.
			#		This is true now, but who knows if it'll be true in the future.
			alternatives = [ self.load(addr, 1)[0] ]
			for o in others:
				alternatives.append(o.load(addr, 1)[0])

			and_constraints = [ ]
			merged_val = self.state.new_symbolic("%s_merge_0x%x" % (self.id, addr), 8)
			for a, fv in zip(alternatives, flag_values):
				and_constraints.append(se.And(flag == fv, merged_val == a))
			self.store(addr, merged_val)

			constraints.append(se.Or(*and_constraints))
		return constraints

SimMemory.register_default('memory', SimMemory)
SimMemory.register_default('registers', SimMemory)
