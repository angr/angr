#!/usr/bin/env python

# pylint: disable=W0703

# for the pybfd import error:
# pylint: disable=F0401

import os
import struct
import idalink
import logging
import pybfd.bfd
import subprocess
from function import Function
from helpers import once

l = logging.getLogger("angr.binary")
l.setLevel(logging.WARNING)

arch_bits = { }
arch_bits["X86"] = 32
arch_bits["AMD64"] = 64
arch_bits["ARM"] = 32
arch_bits["PPC"] = 32
arch_bits["PPC64"] = 64
arch_bits["S390X"] = 32
arch_bits["MIPS32"] = 32

class ImportEntry(object):
	def __init__(self, module_name, ea, name, entry_ord):
		self.module_name = module_name
		self.ea = ea
		self.name = name
		self.ord = entry_ord

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
	def __init__(self, filename, arch="AMD64"):
		self.dirname = os.path.dirname(filename)
		self.filename = os.path.basename(filename)
		self.fullpath = filename
		self.arch = arch
		self.toolsdir = os.path.dirname(os.path.realpath(__file__)) + "/tools"
		self.self_functions = [ ]
		self.added_functions = [ ]
		self.import_list = []
		self.current_module_name = None

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
		return [ s for s in syms if s != self.fullpath and ('.so' in s or '.dll' in s) ]

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
			imports.append([sym, ntype])

		return imports

	@once
	def get_exports(self):
		p_nm = subprocess.Popen(["nm", "-D", self.fullpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		result_nm = p_nm.stdout.readlines()
		exports = [ ]
		for nm_out in result_nm:
			lib_symbol = nm_out.split()
			ntype = lib_symbol[0 if len(lib_symbol) == 2 else 1]
			if ntype not in "ABCDGRSTVWi":
				# skip anything but exports
				continue

			sym = lib_symbol[-1]
			exports.append([sym, ntype])

		return exports



	def qemu_get_symbol_addr(self, sym):
		def qemu_type(x):
			return {
				'X86': 'i386',
				'AMD64': 'x86_64',
				'ARM': 'arm',
				'PPC': 'ppc',
				'PPC64': 'ppc64',
				#FIXME: not provided in many distros
				'S390x': 's390x',
				'MIPS32': 'mips',
				}[x]

		qemu = 'qemu-' + qemu_type(self.arch)
		p_qe = subprocess.Popen([qemu, self.toolsdir + '/sym', self.filename, sym], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		result_qe = p_qe.stdout.readlines()
		if len(result_qe) != 1:
			raise Exception("Something nasty happened in running tool/sym")

		addr = result_qe[0].strip().split(' ')[-1]
		addr = int(addr, 16)
		return (addr + self.ida.idaapi.get_imagebase())

	def get_symbol_addr(self, sym):
		addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)

		# if IDA doesn't know the symbol, use QEMU
		if addr == self.ida.idc.BADADDR:
			addr = self.qemu_get_symbol_addr(sym)
			l.debug("QEMU got %x for %s" % (addr, sym))
			# make sure QEMU and IDA agree
			ida_func = self.ida.idaapi.get_func(addr)
			ida_name = self.ida.idaapi.get_name(0, addr)

			#l.debug("... sym: %s, ida: %s" % (sym, ida_name))

			# TODO: match symbols to IDA symbols better
			sym_al = ''.join(ch for ch in sym if ch.isalnum())
			ida_al = ''.join(ch for ch in ida_name if ch.isalnum())

			if sym_al in ida_al:
				#l.debug("... names (%s and %s) match!" % (sym, ida_name))
				pass
			elif not ida_func: # data section
				loc_name = "loc_" + ("%x" % addr).upper()
				if ida_name != loc_name:
					l.warning("%s wasn't recognized by IDA as a function. IDA name: %s" % (sym, ida_name))
				else:
					r = self.ida.idc.MakeFunction(addr, self.ida.idc.BADADDR)
					if not r:
						raise Exception("Failure making IDA function at 0x%x for %s." % (addr, sym))
                                	ida_func = self.ida.idaapi.get_func(addr)
			elif ida_func.startEA != addr:
				# add the start, end, and name to the self_functions list
				l.warning("%s points to 0x%x, which IDA sees as being partially through function at %x. Creating self function." % (sym, addr, ida_func.startEA))
                                # sometimes happens
				if (addr, ida_func.endEA, sym) not in self.self_functions:
                                	self.self_functions.append((addr, ida_func.endEA, sym))
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

		try:
			plt_addrs = self.get_import_addrs(sym)
		except Exception:
			# now try the __imp_name
			l.debug("... no %s found. Trying __imp_%s." % (sym, sym))
			plt_addrs = self.get_import_addrs("__imp_" + sym)
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

	def get_perms(self):
		return self.ida.perms

	def rebase(self, delta):
		if self.ida.idaapi.rebase_program(delta, self.ida.idaapi.MSF_FIXONCE | self.ida.idaapi.MSF_LDKEEP) != 0:
			raise Exception("Rebasing of %s failed!" % self.filename)
		self.ida.mem.reset()
		if hasattr(self, "_functions"): delattr(self, "_functions")
		if hasattr(self, "_our_functions"): delattr(self, "_our_functions")
		if hasattr(self, "_entry"): delattr(self, "_entry")
		if hasattr(self, "_min_addr"): delattr(self, "_min_addr")
		if hasattr(self, "_max_addr"): delattr(self, "_max_addr")

	def functions(self, mem=None):
		mem = mem if mem else self.ida.mem

		functions = { }
		for f in self.ida.idautils.Functions():
			name = self.ida.idaapi.get_name(0, f)
			functions[f] = Function(f, self.ida, mem, self.arch, self, name)

		for s, e, n in self.self_functions:
			l.debug("Binary %s creating self function %s at 0x%x" % (self.filename, n, s))
			functions[s] = Function(s, self.ida, mem, self.arch, self, name=n, end=e)

		for s, e, n in self.added_functions:
			l.debug("Binary %s creating added function %s at 0x%x" % (self.filename, n, s))
			functions[s] = Function(s, self.ida, mem, self.arch, self, name=n, end=e)

		return functions

	def add_function(self, start, end, sym):
		if (start, end, sym) not in self.added_functions:
			self.added_functions.append((start, end, sym))

	def add_function_chunk(self, addr):
		ida_func = self.ida.idaapi.get_func(addr)
		if not ida_func:
			return

		end = None
		for bb in self.ida.idaapi.FlowChart(ida_func):
			# contiguous blocks
			if end:
				if bb.startEA == end:
					end = bb.endEA
				else:
					break
			if bb.startEA == addr:
				end = bb.endEA

		if not end:
			raise Exception("Error in retrieving function chunk starting from address: %s." %addr)
		self.add_function(addr, end, self.ida.idaapi.get_name(0, addr))


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

	@once
	def exports(self):
		export_item_list = []
		for item in list(self.ida.idautils.Entries()):
			i = ExportEntry(item[0], item[1], item[2], item[3])
			export_item_list.append(i)
		return export_item_list

	@once
	def imports(self):
		import_modules_count = self.ida.idaapi.get_import_module_qty()

		for i in xrange(0, import_modules_count):
			self.current_module_name = self.ida.idaapi.get_import_module_name(i)
			self.ida.idaapi.enum_import_names(i, self.import_entry_callback)

		return self.import_list

	@once
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

	def codeRefsTo(self, ea):
		refs = self.ida.idautils.CodeRefsTo(ea, True)
		refs_list = []
		for ref in refs:
			refs_list.append(ref)

		return refs_list

	# Callbacks
	def import_entry_callback(self, ea, name, entry_ord):
		item = ImportEntry(self.current_module_name, ea, name, entry_ord)
		self.import_list.append(item)
		return True

