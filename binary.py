#!/usr/bin/env python

import idalink
import pysex
import logging
import loader

l = logging.getLogger("angr_binary")
l.setLevel(logging.DEBUG)

def ondemand(f):
	name = f.__name__
	def func(self, *args, **kwargs):
		if hasattr(self, "_" + name):
			return getattr(self, "_" + name)

		a = f(self, *args, **kwargs)
		setattr(self, "_" + name, a)
		return a
	func.__name__ = f.__name__
	return func

class Function(object):
	def __init__(self, func_start, ida):
		self.start = func_start
		self.ida = ida
		self.name = "sub_%x" % func_start

	@ondemand
	def range(self):
		starts, ends = [ ], [ ]
		l.debug("Getting range from IDA")

		f = self.ida.idaapi.get_func(self.start)
		r = (f.startEA, f.endEA)
		l.debug("Got range (%x, %x)." % r)
		return r

	@ondemand
	def ida_blocks(self):
		l.debug("Getting blocks from IDA")
		ida_blocks = { }

		flowchart = self.ida.idaapi.FlowChart(self.ida.idaapi.get_func(self.start))
		for block in flowchart:
			start, end = (block.startEA, block.endEA)
			block_bytes = self.ida.idaapi.get_many_bytes(start, end - start)

			if not block_bytes:
				l.warning("... empty block_bytes at %x" % start)
				continue

			ida_blocks[(start, end)] = block_bytes
		return ida_blocks

	@ondemand
	def bytes(self):
		start, end = self.range()
		return self.ida.idaapi.get_many_bytes(start, end - start)

	@ondemand
	def symbolic_translation(self, init=None):
		return pysex.translate_bytes(self.start, self.bytes(), self.start, init)

	@ondemand
	def sym_vex_blocks(self, init=None):
		blocks = { }
		total_size = 0
		sblocks, exits_out, unsat_exits = self.symbolic_translation(init)

		for exit_type in sblocks:
			for start, sirsb in sblocks[exit_type].iteritems():
				total_size += sirsb.irsb.size()
				blocks[start] = sirsb
				l.debug("Block at %x of size %d" % (start, sirsb.irsb.size()))

		l.debug("Total VEX IRSB size, in bytes: %d" % total_size)
		return blocks

	@ondemand
	def exits(self):
		sblocks, exits_out, unsat_exits = self.symbolic_translation()
		exits = [ ]

		for exit in exits_out:
			try:
				exits.append(exit.concretize())
			except pysex.ConcretizingException:
				l.warning("Un-concrete exit.")

		return exits

class Binary(object):
	def __init__(self, filename):
		self.filename = filename
		self.ida = idalink.IDALink(filename)

	@ondemand
	def functions(self):
		functions = { }
		for f in self.ida.idautils.Functions():
			functions[f] = Function(f, self.ida)
		return functions

	@ondemand
	def our_functions(self):
		functions = { }
		remaining_exits = [ self.entry() ]

		while remaining_exits:
			current_exit = remaining_exits[0]
			remaining_exits = remaining_exits[1:]

			if current_exit not in functions:
				print "New function: %x" % current_exit
				f = Function(current_exit, self.ida)
				functions[current_exit] = f
				new_exits = f.exits()
				print "Exits from %x: %s" % (current_exit,[hex(i) for i in new_exits])
				remaining_exits += [ i for i in new_exits if i != 100 ]
		return functions

	# Gets the entry point of the binary.
	@ondemand
	def entry(self):
		return self.ida.idc.BeginEA()
