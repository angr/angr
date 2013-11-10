#!/usr/bin/env python

import simuvex
from helpers import once
import logging
l = logging.getLogger("angr.function")

class Function(object):
	def __init__(self, start, ida, mem, arch, bin, name = None, end = None):
		self.bin = bin
		self.start = start
		self.end = end
		self.ida = ida
		self.mem = mem
		self.arch = arch
		self.name = [ "sub_%x" % start if not name else name ]

	def bytes(self):
		start, end = self.range()
		return "".join([self.mem[i] for i in range(start, end)])

	@once
	def range(self):
		if self.start is not None and self.end is not None:
			return (self.start, self.end)

		l.debug("Getting range from IDA")

		f = self.ida.idaapi.get_func(self.start)
		r = (f.startEA, f.endEA)
		l.debug("Got range (0x%x, 0x%x)." % r)
		return r

	@once
	def symbolic_translation(self, init=None):
		if not init: init = simuvex.SimState(memory_backer=self.mem, arch=self.arch)
		return simuvex.translate_bytes(self.start, self.bytes(), self.start, init, arch=self.arch)

	def sym_vex_blocks(self, init=None):
		blocks = { }
		total_size = 0
		sblocks, exits_out, unsat_exits = self.symbolic_translation(init)

		for exit_type in sblocks:
			for start, sirsb in sblocks[exit_type].iteritems():
				if sirsb.has_irsb:
					total_size += sirsb.irsb.size()
					l.debug("Block at 0x%x of size %d" % (start, sirsb.irsb.size()))
				blocks[start] = sirsb

		l.debug("Total VEX IRSB size, in bytes: %d" % total_size)
		return blocks

	def exits(self):
		sblocks, exits_out, unsat_exits = self.symbolic_translation()
		exits = [ ]

		for exit in exits_out:
			try:
				exits.append(exit.concretize())
			except simuvex.ConcretizingException:
				l.warning("Un-concrete exit.")

		return exits

