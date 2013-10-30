#!/usr/bin/env python

import os
import pysex
import struct
import idalink
import logging
import pybfd.bfd
import subprocess

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

def once(f):
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
	def __init__(self, func_start, ida, arch):
		self.start = func_start
		self.ida = ida
		self.arch = arch
		self.name = "sub_%x" % func_start

	@once
	def range(self):
		starts, ends = [ ], [ ]
		l.debug("Getting range from IDA")

		f = self.ida.idaapi.get_func(self.start)
		r = (f.startEA, f.endEA)
		l.debug("Got range (%x, %x)." % r)
		return r

	@once
	def bytes(self):
		start, end = self.range()
		return "".join([self.ida.mem[i] for i in range(start, end)])

	@once
	def symbolic_translation(self, init=None):
		return pysex.translate_bytes(self.start, self.bytes(), self.start, init, arch=self.arch)

	@once
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

	@once
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
		self.dirname = os.path.dirname(filename)
		self.filename = os.path.basename(filename)
		self.fullpath = filename
		self.arch = arch

		try:
			self.bfd = pybfd.bfd.Bfd(filename)
			self.bits = self.bfd.arch_size
		except pybfd.bfd.BfdException:
			l.warning("Unable to load binary in BFD. Falling back to other stuff.")
			self.bfd = None
			self.bits = arch_bits[arch]

		self.ida = idalink.IDALink(filename, ida_prog=("idal" if self.bits == 32 else "idal64"))

	def get_lib_names(self):
		if self.bfd == None:
			l.warning("Unable to get dependencies without BFD support.")
			return [ ]

		syms = self.bfd.sections['.dynstr'].content.split('\x00')
		return [ s for s in syms if s != self.filename and ('.so' in s or '.dll' in s) ]

	@once
	def get_imports(self):
		p_nm = subprocess.Popen(["nm", "-D", self.fullpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		result_nm = p_nm.stdout.readlines()
		imports = [ ]

		for nm_out in result_nm:
			lib_symbol = nm_out.split()
			ntype = lib_symbol[0 if len(lib_symbol) == 2 else 1]
			if ntype not in "Uuvw":
				# skip anything but imports
				continue

			sym = lib_symbol[-1]
			imports.append(sym)

		return imports

	@once
	def get_exports(self):
		p_nm = subprocess.Popen(["nm", "-D", self.fullpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		result_nm = p_nm.stdout.readlines()
		exports = [ ]

		for nm_out in result_nm:
			lib_symbol = nm_out.split()
			ntype = lib_symbol[0 if len(lib_symbol) == 2 else 1]
			if ntype not in "ABCDGRSTVW":
				# skip anything but exports
				continue

			sym = lib_symbol[-1]
			exports.append(sym)

		return exports

	def get_symbol_addr(self, sym):
		addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
		if addr == self.ida.idc.BADADDR:
			raise Exception("Symbol %s in file %s unknown to IDA." % (sym, self.fullpath))
		return addr

	def get_import_addrs(self, sym):
		# first, try it directly
		addr = self.get_symbol_addr(sym)
		refs = list(self.ida.idautils.DataRefsTo(addr))
		return refs

	def resolve_import(self, sym, new_val):
		fmt = ""

		if self.bfd.big_endian:
			fmt += ">"
		elif self.bfd.little_endian:
			fmt += "<"

		if self.bits == 64:
			fmt += "Q"
		elif self.bits == 32:
			fmt += "I"
		elif self.bits == 16:
			fmt += "H"
		elif self.bits == 8:
			fmt += "B"

		packed = struct.pack(fmt, new_val)
		for plt_addr in self.get_import_addrs(sym):
			l.debug("... setting %x to %x" % (plt_addr, new_val))
			for n,p in enumerate(packed):
				self.ida.mem[plt_addr + n] = p

	@once
	def min_addr(self):
		nm = self.ida.idc.NextAddr(0)
		pm = self.ida.idc.PrevAddr(nm)

		if pm == self.ida.idc.BADADDR: return nm
		else: return pm

	@once
	def max_addr(self):
		pm = self.ida.idc.PrevAddr(self.ida.idc.MAXADDR)
		nm = self.ida.idc.NextAddr(pm)

		if nm == self.ida.idc.BADADDR: return pm
		else: return nm

	def get_mem(self):
		return self.ida.mem

	def rebase(self, delta):
		if self.ida.idaapi.rebase_program(delta, self.ida.idaapi.MSF_FIXONCE | self.ida.idaapi.MSF_LDKEEP) != 0:
			raise Exception("Rebasing of %s failed!" % self.filename)

		self.ida.mem.reset()
		if hasattr(self, "_functions"): delattr(self, "_functions")
		if hasattr(self, "_our_functions"): delattr(self, "_our_functions")
		if hasattr(self, "_entry"): delattr(self, "_entry")
		if hasattr(self, "_min_addr"): delattr(self, "_min_addr")
		if hasattr(self, "_max_addr"): delattr(self, "_max_addr")

	@once
	def functions(self):
		functions = { }
		for f in self.ida.idautils.Functions():
			functions[f] = Function(f, self.ida, self.arch)
		return functions

	@once
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
	@once
	def entry(self):
		return self.ida.idc.BeginEA()
