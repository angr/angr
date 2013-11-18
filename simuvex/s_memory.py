#!/usr/bin/env python

import copy
import logging
import itertools
import json

l = logging.getLogger("s_memory")

import symexec
import s_value
import s_exception

addr_mem_counter = itertools.count()
var_mem_counter = itertools.count()
# Conventions used:
# 1) The whole memory is readable
# 2) Memory locations are by default writable
# 3) Memory locations are by default not executable

class SimMemoryError(s_exception.SimError):
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
		# TODO: better default (page-based, for example)
		permissions = 7

		try:
			var = symexec.BitVecVal(ord(self.backer[addr]), 8)
			if hasattr(self.backer, "get_perm"):
				permissions = self.backer.get_perm(addr)
		except KeyError:
			# give unconstrained on KeyError
			var = symexec.BitVec("%s_%d" % (self.id, var_mem_counter.next()), 8)

		c = Cell(permissions, var)
		self[addr] = c
		return c


class SimMemory:
	def __init__(self, backer=None, sys=None, id="mem"):

		#TODO: copy-on-write behaviour
		self.mem = Symbolizer(id, backer if backer else { })
		self.limit = 1024
		self.bits = sys if sys else 64
		self.max_mem = 2**self.bits
		self.freemem = [(0, self.max_mem - 1)]
		self.wrtmem =  [(0, self.max_mem - 1)]
		self.excmem =  [(0, self.max_mem - 1)]
		self.id = id

		# Commenting this out, pending clarification from Nilo
		#self.excmem =  []
		# if text_sec:
		#	 keys = [[-1, 0]]  + text_sec + [[self.max_mem, self.max_mem + 1]]
		#	 self.freemem = [ j for j in [ ((keys[i][1] + 1, keys[i+1][0] - 1) if keys[i+1][0] - keys[i][1] > 1 else ()) for i in range(len(keys)-1) ] if j ]
		#	 self.wrtmem = list(self.freemem)
		#	 self.excmem = list(self.freemem)
		# if backer:
		#	 self.mem.update(initial[0])
		#	 self.update_info_mem(initial[1])

	def __update_info_mem(self, w_type):
		s_keys = sorted(self.mem.keys())
		keys = [ -1 ] + s_keys + [ self.max_mem ]
		if w_type & 2 or w_type & 1: # if the memory has been written
			self.freemem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]
		# updating writable memory
		if not w_type & 2: # the memory is marked as not re-writable
			keys = [ -1 ] + [k for k in s_keys if not self.mem[k].type & 2] + [ self.max_mem ]
			self.wrtmem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]
		# updating executable memory
		if not w_type & 1: # the memory is marked as not executable
			keys = [ -1 ] + [k for k in s_keys if not self.mem[k].type & 1] + [ self.max_mem ]
			self.excmem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]

	def is_readable(self, addr):
		return self.mem[addr].type & 4

	def is_writable(self, addr):
		return self.mem[addr].type & 2

	def is_executable(self, addr):
		return self.mem[addr].type & 1

	def __read_from(self, addr, num_bytes):
		# Check every addresses insted only the first one?
		if self.is_readable(addr):
			if num_bytes == 1:
				return self.mem[addr].cnt
			else:
				return symexec.Concat(*[self.mem[addr + i].cnt for i in range( 0, num_bytes)])
		else:
			l.warning("Attempted reading in a not readable location")
			# FIX ME
			return None

	def __write_to(self, addr, cnt, w_type=7):
		if self.is_writable(addr):
			for off in range(0, cnt.size(), 8):
				target = addr + off/8
				new_content = symexec.Extract(cnt.size() - off - 1, cnt.size() - off - 8, cnt)
				new_perms = w_type | 4 # always readable
				self.mem[target] = Cell(new_perms, new_content)

			# updating free memory
			self.__update_info_mem(w_type)
			return 1
		else:
			l.info("Attempted writing in a not writable location")
			return 0

	def concretize_write_addr(self, dst, constraints):
		# first, try the bitvector case
		if hasattr(dst, "as_long"):
			return dst.as_long()

		# make sure it's satisfiable
		v = s_value.SimValue(dst, constraints)
		if not v.satisfiable():
			raise SimMemoryError("Received unsatisfiable address for write.")

		# if there's only one option, let's do it
		if v.is_unique():
			return v.any()

		# ok, no free memory that this thing can address
		fcon = [ symexec.And(symexec.UGE(dst,a), symexec.ULE(dst,b)) for a,b in self.freemem ]
		if fcon:
			v.push_constraints(symexec.Or(*fcon))
			if v.satisfiable():
				return v.any()
			v.pop_constraints()

		# first try writeable memory
		fcon = [ symexec.And(symexec.UGE(dst,a), symexec.ULE(dst,b)) for a,b in self.wrtmem ]
		if fcon:
			v.push_constraints(symexec.Or(*fcon))
			if v.satisfiable():
				# ok, found some memory!
				# free memory is always writable - TODO: why?
				return v.any()
			v.pop_constraints()


		# try anything
		return v.any()

	def store(self, dst, cnt, constraints, w_type=7):
		addr = self.concretize_write_addr(dst, constraints)
		self.__write_to(addr, cnt, w_type)
		return [dst == addr]

	#Load expressions from memory
	def load(self, dst, size, constraints=None):
		expr = False
		size_b = size/8
		l.debug("Got load with size %d (%d bytes)" % (size, size_b))

		# first, try the bitvector case
		if hasattr(dst, "as_long"):
			return self.__read_from(dst.as_long(), size/8), [ ]

		# make sure it's satisfiable
		v = s_value.SimValue(dst, constraints)
		if not v.satisfiable():
			raise SimMemoryError("Received unsatisfiable address for read.")

		# now see if the read is unique
		if v.is_unique():
			return self.__read_from(v.any(), size/8), [ ]

		if v.max() - v.min() < self.limit:
			fcon = [ symexec.And(symexec.UGE(dst,a), symexec.ULE(dst,b)) for a,b in self.freemem ]
			if fcon:
				# within the limit to keep it symbolic
				v.push_constraints(symexec.Or(*fcon))
				if not v.satisfiable():
					v.pop_constraints()

			var = symexec.BitVec("%s_addr_%s" %(self.id, addr_mem_counter.next()), self.bits)
			expr = symexec.Or(*[ symexec.And(var == self.__read_from(addr, size_b),
					      dst == addr) for addr in sorted(v.any_n(self.limit)) ])
			return var, [ expr ]

		# otherwise, time to concretize!

		# first, try to concretize it to some previously stored symbolic values
		fcon = [ dst == addr for addr in self.mem.keys() ]
		if fcon:
			v.push_constraints(symexec.Or(*fcon))
			if not v.satisfiable():
				# now just point it anywhere
				v.pop_constraints()

		addr = v.any()
		return self.__read_from(addr, size_b), [dst == addr]

	def get_bit_address(self):
		return self.bits

	def pp(self):
		[l.debug("%d: [%s, %s]" %(addr, self.mem[addr].cnt, self.mem[addr].type)) for addr in self.mem.keys()]

	def get_addresses(self):
		return self.mem.keys()

	def get_max(self):
		return self.max_mem

	#TODO: copy-on-write behaviour
	def copy(self):
		l.debug("Copying %d cells of memory." % len(self.mem))
		c = copy.copy(self)
		c.mem = copy.copy(self.mem)
		c.mem.backer = self.mem.backer
		return c

	def __getitem__(self, index):
		return self.mem[index]

        def to_json(self):
                tmp = [[a, cell.type, str(cell.cnt)] for a, cell in self.mem.iteritems()]
                return json.dumps(tmp)
                
