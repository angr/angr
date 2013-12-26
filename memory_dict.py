#!/usr/bin/env python

import collections
import cooldict

import logging
l = logging.getLogger("memory_dict")

class MemoryDict(collections.MutableMapping):
	# Create a memory dict, backed by the binaries. 'what' is either 'mem' or 'perm'
	def __init__(self, binaries, what, granularity=1):
		self.granularity = granularity
		if what == 'mem':
			mem = [ b.get_mem() for b in binaries.values() ]
		elif what == 'perm':
			mem = [ b.get_perms() for b in binaries.values() ]
		else:
			raise Exception("Unknown type.")
		self.mem = cooldict.CachedDict(cooldict.BackedDict(*mem))

	# Flattens the memory, if it hasn't already been flattened.
	def pull(self):
		if hasattr(self.mem, 'backer'):
			self.mem.backer.flatten()
			self.mem = self.mem.backer.storage

	def __getitem__(self, k):
		if self.granularity == 1:
			if type(k) == slice: return self.get_bytes(k.start, k.stop)
			else: return self.mem[k]

		try:
			if type(k) == slice: return self.get_bytes(k.start / self.granularity, k.stop / self.granularity)
			else: return self.mem[k / self.granularity]
		except KeyError:
			if type(k) == slice: return self.get_bytes(k.start, k.stop)
			else: return self.mem[k]

	def __setitem__(self, k, v):
		self.mem[k / self.granularity] = v

	def __delitem__(self, k):
		del self.mem[k / self.granularity]

	def __iter__(self):
		if self.granularity == 1:
			return self.mem.__iter__()
		else:
			tuple(set([ k/self.granularity for k in self.mem.__iter__() ]))

	def __len__(self):
		return len(self.mem)

	def __contains__(self, k):
		return k/self.granularity in self.mem

	def get_bytes(self, start, end):
		buff = []
		for i in range(start, end):
			buff.append(self[i])
		return "".join(buff)
