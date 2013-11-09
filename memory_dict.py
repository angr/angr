#!/usr/bin/env python

import logging
l = logging.getLogger("memory_dict")

class MemoryDict(dict):
	def __init__(self, binaries):
		self.binaries = binaries
		super(MemoryDict, self).__init__()

	def __missing__(self, addr):
		# look into the ghost memory
		bin = self.get_bin(addr)
		if bin:
			b = bin.get_mem()[addr]
			self.__setitem__(addr, b)
			return b
		else:
			raise KeyError(str(addr))

	def get_bin(self, addr):
		#l.debug("Looking up bin for addr 0x%x", addr)
		for bin_name, bin in self.binaries.iteritems():
			r = (bin.min_addr(), bin.max_addr())
			#l.debug("... checking bin %s with range (0x%x, 0x%x)" % (bin_name, r[0], r[1]))
			if addr >= r[0] and addr <= r[1]:
				#l.debug("Address 0x%x is in memory of bin %s" % (addr, bin_name))
				return bin
		return None

	def keys(self):
		k = set()
		for bin_name, bin in self.binaries.iteritems():
			k.update(bin.get_mem().keys())
		return k

	def get_perm(self, addr):
		# look into the ghost memory
		bin = self.get_bin(addr)
		if bin:
			return bin.get_mem().get_perm(addr)
		else:
			raise KeyError(str(addr))

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
