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
	def symbolic_translation(self):
			    #init = pysex.s_state.SymbolicState(memory=loader.load_binary(self.ida))
		return pysex.translate_bytes(self.start, self.bytes(), self.start, None)

	@ondemand
	def sym_vex_blocks(self):
		blocks = { }
		total_size = 0
		sblocks, exits_out, unsat_exits = self.symbolic_translation()

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

class ImportEntry(object):

	def __init__(self, module_name, ea, name, ord):
		self.module_name = module_name
		self.ea = ea
		self.name = name
		self.ord = ord

class ExportEntry(object):

	def __init__(self, index, ordinal, ea, name):
		self.index = index
		self.oridinal = ordinal
		self.ea = ea
		self.name = name

class StringItem(object):

	def __init__(self, ea, value, length):
		self.ea = ea
		self.value = value
		self.length = length

class Binary(object):
	import_list = []
	current_module_name = ""

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

	@ondemand
	def exports(self):
		export_item_list = []
		for item in list(self.ida.idautils.Entries()):
			i = ExportEntry(item[0], item[1], item[2], item[3])
			export_item_list.append(i)
		return export_item_list

	@ondemand
	def imports(self):
		self.import_list = []
		import_modules_count = self.ida.idaapi.get_import_module_qty()

		for i in xrange(0, import_modules_count):
			self.current_module_name = self.ida.idaapi.get_import_module_name(i)

			self.ida.idaapi.enum_import_names(i, self.import_entry_callback)

		return self.import_list

	@ondemand
	def strings(self):
		ss = self.ida.idautils.Strings()
		string_list = []
		for s in ss:
			stringItem = StringItem(s.ea, str(s), s.length)
			string_list.append(stringItem)

		return string_list

	def dataRefsTo(self, ea):
		refs = self.ida.idautils.DataRefsTo(ea)
		refs_list = []
		for ref in refs:
			refs_list.append(ref)

		return refs_list

	# Callbacks
	def import_entry_callback(self, ea, name, ord):
		item = ImportEntry(self.current_module_name, ea, name, ord)
		self.import_list.append(item)
		return True
