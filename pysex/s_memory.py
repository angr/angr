#!/usr/bin/env python
import z3
import s_value
import random
import copy
import collections
import logging

logging.basicConfig()
l = logging.getLogger("s_memory")
addr_mem_counter = 0
var_mem_counter = 0

class Memory:
	def __init__(self, initial=None, sys=None, id="mem"):
		def default_mem_value():
			global var_mem_counter
			var = z3.BitVec("%s_%d" % (id, var_mem_counter), 8)
			var_mem_counter += 1
			return var

		#TODO: copy-on-write behaviour
		self.__mem = copy.copy(initial) if initial else collections.defaultdict(default_mem_value)
		self.__limit = 1024
		self.__bits = sys if sys else 64
		self.__max_mem = 2**self.__bits
		self.__freemem = [(0, self.__max_mem - 1)]

	def read_from(self, addr, num_bytes):
		if num_bytes == 1:
			return self.__mem[addr]
		else:
			return z3.Concat(*[self.__mem[addr + i] for i in range( 0, num_bytes)])

	def store(self, dst, cnt, constraints):
		# Memory is never full, is it? We just overwrite what's there...
		#if len(self.__mem) + cnt.size() >= self.__max_mem:
		#	raise Exception("Memory is full.")

		v = s_value.Value(dst, constraints)
		ret = []

		if v.is_unique():
			# if there's only one option, let's do it
			addr = v.any()
		else:
			# otherwise, let's first try to find some free memory
			if len(self.__mem) == 0:
				# do a page-aligned address just in case?
				addr = random.randint(0, self.__max_mem) % 0x1000
				ret = [dst == addr]

			fcon = z3.Or([ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__freemem ])
			v_free = s_value.Value(dst, constraints + [ fcon ])

			if v_free.satisfiable():
				# ok, found some memory!
				addr = v_free.any()
				ret = [dst == addr]
			else:
				# ok, no free memory that this thing can address
				addr = v.any()
				ret = [dst == addr]

		for off in range(0, cnt.size() / 8):
			self.__mem[(addr + off)] = z3.Extract((off << 3) + 7, (off << 3), cnt)

		keys = [ -1 ] + self.__mem.keys() + [ self.__max_mem ]
		self.__freemem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]

		return ret

	#Load expressions from memory
	def load(self, dst, size, constraints=None):
		global addr_mem_counter

		# what is the point of this check (other than screwing up multi-byte loads)?
		#if len(self.__mem) == 0:
		#	return self.__mem[-1], []

		expr = False
		ret = None

		size_b = size >> 3
		v = s_value.Value(dst, constraints)

		l.debug("Got load with size %d (%d bytes)" % (size, size_b))

		# specific read
		if v.is_unique():
			addr = v.any()
			expr = self.read_from(addr, size/8)
			expr = z3.simplify(expr)
			ret = expr, [ ]

		elif abs(v.max() - v.min()) <= self.__limit:
			# within the limit to keep it symbolic
			fcon = z3.Or([ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__freemem ])
			v_free = s_value.Value(dst, constraints + [ z3.Not(fcon) ])

			# try to point it to satisfiable memory if possible
			if v_free.satisfiable():
				to_iterate = v_free
			else:
				to_iterate = v

			var = z3.BitVec("%s_addr_%s" %(dst, addr_mem_counter), self.__bits)
			addr_mem_counter += 1
			for addr in to_iterate.iter():
				cnc = z3.Concat(*[self.__mem[addr + i] for i in range( 0, size_b)])
				expr = z3.simplify(z3.Or(var == cnc, expr))

			ret = expr, []
		else:
			# too big, time to concretize!
			if len(self.__mem):
				#first try to point it somewhere valid

				addr = random.choice(self.__mem.keys())
				cnc = z3.Concat(*[ self.__mem[addr + i] for i in range( 0, size_b)])
				cnc = z3.simplify(cnc)
				ret = cnc, [dst == addr]
			else:
				# otherwise, concretize to a random, page-aligned location, just for fun
				addr = random.randint(0, self.__max_mem) % 0x1000
				cnc = z3.Concat(*[ self.__mem[addr + i] for i in range( 0, size_b)])
				cnc = z3.simplify(cnc)
				ret = cnc, [dst == addr]

		return ret

	def get_bit_address(self):
		return self.__bits

	#TODO: copy-on-write behaviour
	def copy(self):
		return copy.copy(self)
