#!/usr/bin/env python

import idalink
import pyvex
import logging
l = logging.getLogger("angr_binary")
l.setLevel(logging.DEBUG)

class Function(object):
	def __init__(self, func_start):
		l.debug("Analyzing function starting at %x" % func_start)

		flowchart = idalink.idaapi.FlowChart(idalink.idaapi.get_func(func_start))
		for block in flowchart:
			start, end = (block.startEA, block.endEA)
			block_bytes = idalink.idaapi.get_many_bytes(start, end - start)

			if not block_bytes:
				l.warning("... empty block_bytes at %x" % start)
				continue

			self.ida_block = (start, end)
			self.ida_bytes = block_bytes
			try:
				self.vex_blocks = self.make_vex_blocks(start, end, block_bytes)
			except pyvex.VexException:
				self.vex_blocks = { }
				l.warning("Unsuccessful translation to VEX.", exc_info=True)

	def make_vex_blocks(self, start, end, block_bytes):
		l.debug("... Block: %x - %x" % (start, end))
		vex_blocks = { }

		done_bytes = 0
		while done_bytes < len(block_bytes):
			try:
				irsb = pyvex.IRSB(bytes = block_bytes[done_bytes:], mem_addr = start + done_bytes)
				size = irsb.size()
				instcount = irsb.instructions()
				statements = irsb.statements()

				if size == 0:
					#raise pyvex.VexException("Failed to translate %d bytes at %x" %
			      		#			 (len(block_bytes) - done_bytes, start + done_bytes))
			      		raise pyvex.VexException("gah")

				l.debug("...... IRSB has %d statements, %d instructions, and %d bytes", len(statements), instcount, size)


				done_bytes += size
				vex_blocks[(start, start + size)] = irsb
				irsb.pp()
			except pyvex.VexException:
				break

		if done_bytes != len(block_bytes):
			raise pyvex.VexException("Only translated %x out of %x bytes to VEX in block %x" % (done_bytes, len(block_bytes), start))

		return vex_blocks

class Binary(object):
	def __init__(self, filename):
		idalink.make_idalink(filename)
		self.functions = { }

	def load_function(f):
		self.functions[f] = Function(f)

	def load_all_functions():
		for f in get_function_addrs():
			load_function(f)

	def get_function_addrs(self):
		return idalink.idautils.Functions()
