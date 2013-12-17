#!/usr/bin/env python

import logging
import itertools
import cooldict

l = logging.getLogger("s_memory")

import symexec
import s_exception
import s_value

addr_mem_counter = itertools.count()
var_mem_counter = itertools.count()
# Conventions used:
# 1) The whole memory is readable
# 2) Memory locations are by default writable
# 3) Memory locations are by default not executable

class SimMemoryError(s_exception.SimError):
	pass

class Vectorizer(cooldict.CachedDict):
	def __init__(self, backer):
		super(Vectorizer, self).__init__(backer)

	def default_cacher(self, k):
		b = self.backer[k]
		if type(b) in ( int, str ):
			b = symexec.BitVecVal(ord(self.backer[k]), 8)

		self.cache[k] = b
		return b


class SimMemory:
	def __init__(self, backer, bits=None, id="mem"):
		if not isinstance(backer, cooldict.BranchingDict):
			backer = cooldict.BranchingDict(backer)

		self.mem = backer
		self.limit = 1024
		self.bits = bits if bits else 64
		self.max_mem = 2**self.bits
		self.id = id

	# Returns num_bytes read from a given concrete location. If constraints are provided,
	# a string of concrete bytes is returned. Otherwise, a BitVec of concatenated symbolic
	# bytes is returned.
	def read_from(self, addr, num_bytes, constraints=None):
		bytes = [ ]
		for i in range(0, num_bytes):
			try:
				bytes.append(self.mem[addr+i])
			except KeyError:
				mem_id = "%s_%x_%d" % (self.id, addr, var_mem_counter.next())
				b = symexec.BitVec(mem_id, 8)
				self.mem[addr+i] = b
				bytes.append(b)

		if constraints is None:
			if len(bytes) == 1:
				return bytes[0]
			else:
				return symexec.Concat(*bytes)
		else:
			# TODO: actually take constraints into account
			r = ""
			for b in bytes:
				concrete = symexec.concretize_constant(b)
				r += chr(concrete)
			return r

	def write_to(self, addr, cnt):
		for off in range(0, cnt.size(), 8):
			target = addr + off/8
			new_content = symexec.Extract(cnt.size() - off - 1, cnt.size() - off - 8, cnt)
			self.mem[target] = new_content

	def concretize_addr(self, v, strategies):
		if v.is_symbolic and not v.satisfiable():
			raise SimMemoryError("Trying to concretize with unsat constraints.")

		# if there's only one option, let's do it
		if v.is_unique():
			return [ v.any() ]

		for s in strategies:
			if s == "free":
				# TODO
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
		return self.concretize_addr(dst, strategies = [ "free", "writeable", "any" ])

	def concretize_read_addr(self, dst):
		return self.concretize_addr(dst, strategies=['symbolic', 'any'])

	def __contains__(self, dst):
		if type(dst) == int:
			addr = dst
		else:
			if dst.is_symbolic():
				raise SimMemoryError("__contains__ doesn't support symbolic locations yet")
			addr = dst.any()

		return addr in self.mem

	def store(self, dst, cnt):
		if type(dst) == int:
			addr = dst
			constraint = [ ]
		else:
			addr = self.concretize_write_addr(dst)[0]
			constraint = [ dst.expr == addr ]

		self.write_to(addr, cnt)
		return constraint

	def load(self, dst, size):
		size_b = size/8
		if type(dst) == int:
			addrs = [ dst ]
		else:
			addrs = self.concretize_read_addr(dst)

		# if there's a single address, it's easy
		if len(addrs) == 1:
			return self.read_from(addrs[0], size/8), [ dst.expr == addrs[0] ]

		# otherwise, create a new symbolic variable and return the mess of constraints and values
		m = symexec.BitVec("%s_addr_%s" %(self.id, addr_mem_counter.next()), self.bits)
		e = symexec.Or(*[ symexec.And(m == self.read_from(addr, size_b), dst.expr == addr) for addr in addrs ])
		return m, [ e ]

	def load_val(self, dst, size):
		m, e = self.load(dst, size)
		return s_value.SimValue(m, e + dst.constraints)

	def copy(self):
		l.debug("Copying %d bytes of memory with id %s." % (len(self.mem), self.id))
		c = SimMemory(self.mem.branch(), bits=self.bits, id=self.id)
		return c
