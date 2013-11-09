#!/usr/bin/env python
import z3
import s_value
import copy
import logging
l = logging.getLogger("s_memory")
l.setLevel(logging.DEBUG)

addr_mem_counter = 0
var_mem_counter = 0
# Conventions used:
# 1) The whole memory is readable
# 2) Memory locations are by default writable
# 3) Memory locations are by default not executable

class SymbolicMemoryError(Exception):
	pass

class Cell:
	# Type: RWX bits
	def __init__(self, ctype, cnt):
		self.type = ctype | 4 # memory has to be readable
		self.cnt = cnt

class Symbolizer(dict):
	def __init__(self, id, backer = {}):
		self.backer = backer
		self.id = id
		super(Symbolizer, self).__init__()

	def __missing__(self, addr):
		global var_mem_counter

		# TODO: better default (page-based, for example)
		permissions = 7

		try:
			var = z3.BitVecVal(ord(self.backer[addr]), 8)
			if hasattr(self.backer, "get_perm"):
				permissions = self.backer.get_perm(addr)
		except KeyError:
			# give unconstrained on KeyError
			var = z3.BitVec("%s_%d" % (id, var_mem_counter), 8)
			var_mem_counter += 1

		c = Cell(permissions, var)
		self[addr] = c
		return c


class Memory:
	def __init__(self, backer={ }, sys=None, id="mem"):

		#TODO: copy-on-write behaviour
		self.__mem = Symbolizer(id, backer)
		self.__limit = 1024
		self.__bits = sys if sys else 64
		self.__max_mem = 2**self.__bits
		self.__freemem = [(0, self.__max_mem - 1)]
		self.__wrtmem =  [(0, self.__max_mem - 1)]
		self.__excmem =  [(0, self.__max_mem - 1)]

		# Commenting this out, pending clarification from Nilo
		#self.__excmem =  []
		# if text_sec:
		#	 keys = [[-1, 0]]  + text_sec + [[self.__max_mem, self.__max_mem + 1]]
		#	 self.__freemem = [ j for j in [ ((keys[i][1] + 1, keys[i+1][0] - 1) if keys[i+1][0] - keys[i][1] > 1 else ()) for i in range(len(keys)-1) ] if j ]
		#	 self.__wrtmem = list(self.__freemem)
		#	 self.__excmem = list(self.__freemem)
		# if backer:
		#	 self.__mem.update(initial[0])
		#	 self.__update_info_mem(initial[1])

	def __update_info_mem(self, w_type):
		s_keys = sorted(self.__mem.keys())
		keys = [ -1 ] + s_keys + [ self.__max_mem ]
		if w_type & 2 or w_type & 1: # if the memory has been written
			self.__freemem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]
		# updating writable memory
		if not w_type & 2: # the memory is marked as not re-writable
			keys = [ -1 ] + [k for k in s_keys if not self.__mem[k].type & 2] + [ self.__max_mem ]
			self.__wrtmem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]
		# updating executable memory
		if not w_type & 1: # the memory is marked as not executable
			keys = [ -1 ] + [k for k in s_keys if not self.__mem[k].type & 1] + [ self.__max_mem ]
			self.__excmem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]

	def is_readable(self, addr):
		return self.__mem[addr].type & 4

	def is_writable(self, addr):
		return self.__mem[addr].type & 2

	def is_executable(self, addr):
		return self.__mem[addr].type & 1

	def __read_from(self, addr, num_bytes):
		# Check every addresses insted only the first one?
		if self.is_readable(addr):
			if num_bytes == 1:
				return self.__mem[addr].cnt
			else:
				return z3.Concat(*[self.__mem[addr + i].cnt for i in range( 0, num_bytes)])
		else:
			l.warning("Attempted reading in a not readable location")
			# FIX ME
			return None

	def __write_to(self, addr, cnt, w_type=7):
		if self.is_writable(addr):
			for off in range(0, cnt.size(), 8):
				target = addr + off/8
				new_content = z3.Extract(cnt.size() - off - 1, cnt.size() - off - 8, cnt)
				new_perms = w_type | 4 # always readable
				self.__mem[target] = Cell(new_perms, new_content)

			# updating free memory
			self.__update_info_mem(w_type)
			return 1
		else:
			l.info("Attempted writing in a not writable location")
			return 0

	def concretize_write_addr(self, dst, constraints):
		# first, try the bitvector case
		if hasattr(dst, "as_long"):
			addr = dst.as_long()
			return addr

		# make sure it's satisfiable
		v = s_value.Value(dst, constraints)
		if not v.satisfiable():
			raise SymbolicMemoryError("Received unsatisfiable address for write.")

		# if there's only one option, let's do it
		if v.is_unique():
			return v.any()

		# first try writeable memory
		try:
			fcon = z3.Or([ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__wrtmem ])
			v.push_constraints([ fcon ])
			if v.satisfiable():
				# ok, found some memory!
				# free memory is always writable - TODO: why?
				return v.any()
			v.pop_constraints()
		except z3.Z3Exception:
			pass

		# ok, no free memory that this thing can address
		try:
			fcon = z3.Or([ False ] + [ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__freemem ])
			v.push_constraints([ fcon ])
			if v.satisfiable():
				return addr
		except z3.Z3Exception:
			pass

		# try anything
		return v.any()

	def store(self, dst, cnt, constraints, w_type=7):
		addr = self.concretize_write_addr(dst, constraints)
		self.__write_to(addr, cnt, w_type)
		return [dst == addr]

	def load_value(self, val, size):
		expr, constraints = self.load(val.expr, size, val.constraints)
		return s_value.Value(expr, constraints)

	#Load expressions from memory
	def load(self, dst, size, constraints=None):
		global addr_mem_counter
		expr = False
		size_b = size/8
		l.debug("Got load with size %d (%d bytes)" % (size, size_b))

		# first, try the bitvector case
		if hasattr(dst, "as_long"):
			return self.__read_from(dst.as_long()), [ ]

		# make sure it's satisfiable
		v = s_value.Value(dst, constraints)
		if not v.satisfiable():
			raise SymbolicMemoryError("Received unsatisfiable address for read.")

		# now see if the read is unique
		if v.is_unique():
			return self.__read_from(v.any(), size/8), [ ]

		if v.max() - v.min() < self.__limit:
			try:
				# within the limit to keep it symbolic
				fcon = z3.Or([ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__freemem ])
				v.push_constraints([ fcon ])
				if not v.satisfiable():
					v.pop_constraints()
			except z3.Z3Exception:
				pass

			var = z3.BitVec("%s_addr_%s" %(dst, addr_mem_counter), self.__bits)
			addr_mem_counter += 1
			expr = z3.Or([ z3.And(var == self.__read_from(addr, size_b),
					      dst == addr) for addr in v.iter() ])
			return var, [ expr ]

		# otherwise, time to concretize!

		# first, try to concretize it to some previously stored symbolic values
		try:
			fcon = z3.Or([ False ] + [ dst == addr for addr in self.__mem.keys() ])
			v.push_constraints([ fcon ])
			if not v.satisfiable():
				# now just point it anywhere
				v.pop_constraints()
		except z3.Z3Exception:
			pass

		addr = v.any()
		return self.__read_from(addr, size_b), [dst == addr]

	def get_bit_address(self):
		return self.__bits

	def pp(self):
		[l.debug("%d: [%s, %s]" %(addr, self.__mem[addr].cnt, self.__mem[addr].type)) for addr in self.__mem.keys()]

	def get_addresses(self):
		return self.__mem.keys()

	def get_max(self):
		return self.__max_mem

	#TODO: copy-on-write behaviour
	def copy(self):
		l.debug("Copying %d cells of memory." % len(self.__mem))
		c = copy.copy(self)
		c.__mem = copy.copy(self.__mem)
		c.__mem.backer = self.__mem.backer
		return c

	def __getitem__(self, index):
		return self.__mem[index]
