#!/usr/bin/env python

import os
import struct
import idalink
import logging
import pybfd.bfd
import subprocess

from function import Function
from helpers import once

l = logging.getLogger("angr.binary")
l.setLevel(logging.DEBUG)

arch_bits = { }
arch_bits["X86"] = 32
arch_bits["AMD64"] = 64
arch_bits["ARM"] = 32
arch_bits["PPC"] = 32
arch_bits["PPC64"] = 64
arch_bits["S390X"] = 32
arch_bits["MIPS32"] = 32

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

		# first try the __imp_name
		try:
			plt_addrs = self.get_import_addrs("__imp_" + sym)
		except Exception:
			l.debug("... no __imp_%s found. Trying %s." % (sym, sym))
			plt_addrs = self.get_import_addrs(sym)
		l.debug("... %d plt refs found." % len(plt_addrs))

		packed = struct.pack(fmt, new_val)
		for plt_addr in plt_addrs:
			l.debug("... setting 0x%x to 0x%x" % (plt_addr, new_val))
			for n,p in enumerate(packed):
				self.ida.mem[plt_addr + n] = p

	def min_addr(self):
		nm = self.ida.idc.NextAddr(0)
		pm = self.ida.idc.PrevAddr(nm)

		if pm == self.ida.idc.BADADDR: return nm
		else: return pm

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
	def functions(self, mem=None):
		mem = mem if mem else self.ida.mem

		functions = { }
		for f in self.ida.idautils.Functions():
			name = self.ida.idaapi.get_name(0, f)
			functions[f] = Function(f, self.ida, mem, self.arch, self, name)

		return functions

	@once
	def our_functions(self):
		functions = { }
		remaining_exits = [ self.entry() ]

		while remaining_exits:
			current_exit = remaining_exits[0]
			remaining_exits = remaining_exits[1:]

			if current_exit not in functions:
				print "New function: 0x%x" % current_exit
				f = Function(current_exit, self.ida, self.arch)
				functions[current_exit] = f
				new_exits = f.exits()
				print "Exits from 0x%x: %s" % (current_exit,[hex(i) for i in new_exits])
				remaining_exits += [ i for i in new_exits if i != 100 ]

		return functions

	# Gets the entry point of the binary.
	def entry(self):
		return self.ida.idc.BeginEA()
