#!/usr/bin/env python

import idalink
import pyvex
import logging
import symbolic
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

	@ondemand
	def range(self):
		starts, ends = [ ], [ ]
		l.debug("Getting range from IDA")

		flowchart = self.ida.idaapi.FlowChart(self.ida.idaapi.get_func(self.start))
		for block in flowchart:
			start, end = (block.startEA, block.endEA)
			starts.append(start)
			ends.append(end)

		r = ( min(starts), max(ends) )
		l.debug("Got range %s." % str(r))
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
	def vex_blocks(self):
		#for (s, e), b in ida_blocks().iteritems():
		#	self.make_vex_blocks(s, e, b)
		blocks = { }
		total_size = 0
		for start,irsb in symbolic.translate_bytes(self.start, self.bytes(), self.start):
			size = irsb.size()
			total_size += size
			blocks[start] = irsb
			l.debug("Block at %x of size %d" % (start, irsb.size()))

		l.debug("Total VEX IRSB size, in bytes: %d" % total_size)
		return blocks

class Binary(object):
	def __init__(self, filename):
		self.filename = filename
		self.ida = idalink.make_idalink(filename)

	def __del__(self):
		l.debug("Closing idalink to %s" % self.filename)
		try:
			self.ida.link.close()
		except:
			l.warning("Closing idalink to %s failed with exception" % self.filename, exc_info=True)

	@ondemand
	def functions(self):
		functions = { }
		for f in self.ida.idautils.Functions():
			functions[f] = Function(f, self.ida)
		return functions
