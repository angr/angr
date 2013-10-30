#!/usr/bin/env python

import idalink
import pysex
import logging
import loader

l = logging.getLogger("angr_binary")
l.setLevel(logging.DEBUG)

arch_bits = { }
arch_bits["X86"] = 32
arch_bits["AMD64"] = 64
arch_bits["ARM"] = 32
arch_bits["PPC"] = 32
arch_bits["PPC64"] = 64
arch_bits["S390X"] = 32
arch_bits["MIPS32"] = 32

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
	def __init__(self, f, mem, arch):
		self.start = f['start']
                self.end = f['start'] + f['size']
		self.ida = None #FIXME!!!
                self.mem = mem
		self.arch = arch
		self.name = "sub_%x" % self.start
                self.lib = f['lib']

	@ondemand
	def range(self):
		r = (self.start, self.end)
		l.debug("Got range (%x, %x)." % r)
		return r

        #FIXME
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
		return [self.mem[i] for i in range(self.start, self.end + 1)]

	@ondemand
	def symbolic_translation(self, init=None):
		return pysex.translate_bytes(self.start, self.bytes(), self.start, init, arch=self.arch)

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
	def __init__(self, filename, arch="AMD64"):
		self.filename = filename
		self.arch = arch
		self.bits = arch_bits[arch]
		self.ida = idalink.IDALink(filename, ida_prog=("idal" if self.bits == 32 else "idal64"))
                self.mem, self.entryp = loader.load_binary(self.ida, self.bits)

	@ondemand
	def functions(self):
		functions = { }
		for f in self.mem.iterfunctions():
			functions[f['start']] = Function(f, self.mem, self.arch)
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
				f = Function(current_exit, self.ida, self.arch)
				functions[current_exit] = f
				new_exits = f.exits()
				print "Exits from %x: %s" % (current_exit,[hex(i) for i in new_exits])
				remaining_exits += [ i for i in new_exits if i != 100 ]
		return functions

	# Gets the entry point of the binary.
	@ondemand
	def entry(self):
		return self.entryp
