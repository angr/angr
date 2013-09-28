#!/usr/bin/env python

import idalink
import pyvex
import logging
import symbolic
l = logging.getLogger("angr_binary")
l.setLevel(logging.DEBUG)

def class_once(f):
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
	@class_once
	def range(self):
		starts, ends = [ ], [ ]
		l.debug("Getting range from IDA")

		flowchart = idalink.idaapi.FlowChart(idalink.idaapi.get_func(self.start))
		for block in flowchart:
			start, end = (block.startEA, block.endEA)
			starts.append(start)
			ends.append(end)

		r = ( min(starts), max(ends) )
		l.debug("Got range %s." % str(r))
		return r

	@class_once
	def ida_blocks(self):
		l.debug("Getting blocks from IDA")
		ida_blocks = { }

		flowchart = idalink.idaapi.FlowChart(idalink.idaapi.get_func(self.start))
		for block in flowchart:
			start, end = (block.startEA, block.endEA)
			block_bytes = idalink.idaapi.get_many_bytes(start, end - start)

			if not block_bytes:
				l.warning("... empty block_bytes at %x" % start)
				continue

			ida_blocks[(start, end)] = block_bytes
		return ida_blocks

	@class_once
	def bytes(self):
		start, end = self.range()
		return idalink.idaapi.get_many_bytes(start, end - start)

	@class_once
	def vex_blocks(self):
		#for (s, e), b in ida_blocks().iteritems():
		#	self.make_vex_blocks(s, e, b)
		return symbolic.translate_bytes(self.start, self.bytes(), self.start)

	def __init__(self, func_start):
		self.start = func_start

	#def make_vex_blocks(self, start, end, block_bytes):
	#	l.debug("... Block: %x - %x" % (start, end))
	#	vex_blocks = { }

	#	done_bytes = 0
	#	while done_bytes < len(block_bytes):
	#		try:
	#			irsb = pyvex.IRSB(bytes = block_bytes[done_bytes:], mem_addr = start + done_bytes)
	#			size = irsb.size()
	#			instcount = irsb.instructions()
	#			statements = irsb.statements()

	#			if size == 0:
	#				#raise pyvex.VexException("Failed to translate %d bytes at %x" %
	#		      		#			 (len(block_bytes) - done_bytes, start + done_bytes))
	#		      		raise pyvex.VexException("gah")

	#			l.debug("...... IRSB has %d statements, %d instructions, and %d bytes", len(statements), instcount, size)


	#			done_bytes += size
	#			vex_blocks[(start, start + size)] = irsb
	#			irsb.pp()
	#		except pyvex.VexException:
	#			break

	#	if done_bytes != len(block_bytes):
	#		raise pyvex.VexException("Only translated %x out of %x bytes to VEX in block %x" % (done_bytes, len(block_bytes), start))

	#	return vex_blocks

class Binary(object):
	def __init__(self, filename):
		idalink.make_idalink(filename)
		self.functions = { }
		self.load_all_functions()

	def load_function(self, f):
		self.functions[f] = Function(f)

	def load_all_functions(self):
		for f in self.get_function_addrs():
			self.load_function(f)

	def get_function_addrs(self):
		return idalink.idautils.Functions()
