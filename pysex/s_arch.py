#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex
import s_irsb
import random

import logging
l = logging.getLogger("s_arch")

class SymbolicArchError(Exception):
	pass

class SymbolicAMD64:
	def __init__(self):
		self.bits = 64
		self.vex_arch = "VexArchAMD64"

	def emulate_subroutine(self, call_imark, state):
		# TODO: clobber rax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for AMD64 at 0x%x" % call_imark.addr)
		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=call_imark.addr, arch="VexArchAMD64")
		ret_sirsb = s_irsb.SymbolicIRSB(ret_irsb, state.copy_after())

		exits = ret_sirsb.exits()
		if len(exits) != 1:
			raise SymbolicArchError("Return has more than one exit. This isn't supported.")

		return exits[0]

class SymbolicX86:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchX86"

	def emulate_subroutine(self, call_imark, state):
		# TODO: clobber eax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for X86 at 0x%x" % call_imark.addr)
		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=call_imark.addr, arch="VexArchX86")
		ret_sirsb = s_irsb.SymbolicIRSB(ret_irsb, state.copy_after())

		exits = ret_sirsb.exits()
		if len(exits) != 1 or not exits[0].symbolic_value().is_unique():
			raise SymbolicArchError("Return has more than one exit. This isn't supported.")

		return exits[0]

class SymbolicARM:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchARM"

	def emulate_subroutine(self, call_imark, state):
		return None

class SymbolicMIPS32:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchMIPS32"

	def emulate_subroutine(self, call_imark, state):
		return None

Architectures = { }
Architectures["AMD64"] = SymbolicAMD64()
Architectures["X86"] = SymbolicX86()
Architectures["ARM"] = SymbolicARM()
Architectures["MIPS32"] = SymbolicMIPS32()
