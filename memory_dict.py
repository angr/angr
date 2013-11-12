#!/usr/bin/env python

import collections
import cooldict

import logging
l = logging.getLogger("memory_dict")

class MemoryDict(collections.MutableMapping):
	def __init__(self, binaries):
		ida_mems = [ b.get_mem() for b in binaries.values() ]
		ida_perms = [ b.get_perms() for b in binaries.values() ]
		self.mem = cooldict.BackedDict(*ida_mems)
		self.perm = cooldict.BackedDict(*ida_perms)

	def __getitem__(self, k):
		return self.mem[k]

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
		print "from %x" % start,
		for i in range(start, end):
			try:
				bytes.append(self[i])
			except Exception:
				print "to %x" % i
				break
		return "".join(bytes)
