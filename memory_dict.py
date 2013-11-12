#!/usr/bin/env python

import collections
import cooldict

import logging
l = logging.getLogger("memory_dict")

class MemoryDict(collections.MutableMapping):
	def __init__(self, binaries):
		ida_mems = [ b.get_mem() for b in binaries.values() ]
		ida_perms = [ b.get_perms() for b in binaries.values() ]
		self.mem = cooldict.CachedDict(cooldict.BackedDict(*ida_mems))
		self.perm = cooldict.CachedDict(cooldict.BackedDict(*ida_perms))

	def pull(self):
		self.mem.backer.flatten()
		self.mem = self.mem.backer.storage
		self.perm.backer.flatten()
		self.perm = self.perm.backer.storage

	def __getitem__(self, k):
		if type(k) == slice: return self.get_bytes(k.start, k.stop)
		else: return self.mem[k]

	def __setitem__(self, k, v):
		self.mem[k] = v

	def __delitem__(self, k):
		del self.mem[k]
		del self.perm[k]

	def __iter__(self):
		return self.mem.__iter__()

	def __len__(self):
		return len(self.mem)

	def get_perm(self, k):
		return self.perm[k]

	def get_bytes(self, start, end):
		bytes = []
		for i in range(start, end):
			bytes.append(self[i])
		return "".join(bytes)
