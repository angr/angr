#!/usr/bin/env python

import logging
l = logging.getLogger("memory_dict")

class MemoryDict(dict):
	def __init__(self, binaries):
		self.binaries = binaries
		super(MemoryDict, self).__init__()

	def __missing__(self, addr):
		# by default ida set not found addresses to 255
		self.__setitem__(addr, 255)

		# look into the ghost memory
		for bin_name, bin in self.binaries.iteritems():
			r = (bin.min_addr(), bin.max_addr())
			if addr >= r[0] and addr <= r[1]:
				l.debug("Address %x is in memory of bin %s" % (addr, bin_name))
				self.__setitem__(addr, bin.get_mem()[addr])

		return self.__getitem__(addr)

	def keys(self):
		k = set()
		for bin_name, bin in self.binaries.iteritems():
			k.update(bin.get_mem().keys())
		return k
