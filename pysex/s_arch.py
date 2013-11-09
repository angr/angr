#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex
import s_irsb
import random

import logging
l = logging.getLogger("s_arch")

class CallEmulationError(Exception):
	pass

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
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=call_imark.addr, arch="VexArchAMD64")
		ret_sirsb = s_irsb.SymbolicIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SymbolicX86:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchX86"

	def emulate_subroutine(self, call_imark, state):
		# TODO: clobber eax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for X86 at 0x%x" % call_imark.addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=call_imark.addr, arch="VexArchX86")
		ret_sirsb = s_irsb.SymbolicIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SymbolicARM:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchARM"

	def emulate_subroutine(self, call_imark, state):
		l.debug("Emulating return for ARM at 0x%x" % call_imark.addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		# NOTE: ARM stuff
		ret_irsb = pyvex.IRSB(bytes="\xE1\xA0\xF0\x0E", mem_addr=call_imark.addr, arch="VexArchARM")
		ret_sirsb = s_irsb.SymbolicIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

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
