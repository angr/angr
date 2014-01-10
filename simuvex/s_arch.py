#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex
import s_irsb
import s_exception

import logging
l = logging.getLogger("s_arch")

class CallEmulationError(s_exception.SimError):
	pass

class SimArchError(s_exception.SimError):
	pass

class SimAMD64:
	def __init__(self):
		self.bits = 64
		self.vex_arch = "VexArchAMD64"
		self.name = "AMD64"
		self.max_inst_bytes = 15
		self.ip_offset = 184
		self.sp_offset = 48
		self.endness = "Iend_LE"

	def emulate_return(self, state, inst_addr=0):
		# TODO: clobber rax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for AMD64 at 0x%x" % inst_addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=inst_addr, arch="VexArchAMD64")
		ret_sirsb = s_irsb.SimIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SimX86:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchX86"
		self.name = "X86"
		self.max_inst_bytes = 15
		self.ip_offset = 68
		self.sp_offset = 24
		self.endness = "Iend_LE"

	def emulate_return(self, state, inst_addr=0):
		# TODO: clobber eax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for X86 at 0x%x" % inst_addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=inst_addr, arch="VexArchX86")
		ret_sirsb = s_irsb.SimIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SimARM:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchARM"
		self.name = "ARM"
		self.max_inst_bytes = 4
		self.ip_offset = 68
		self.sp_offset = 60
		self.endness = "Iend_LE"

	def emulate_return(self, state, inst_addr=0):
		l.debug("Emulating return for ARM at 0x%x" % inst_addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		# NOTE: ARM stuff
		ret_irsb = pyvex.IRSB(bytes="\xE1\xA0\xF0\x0E", mem_addr=inst_addr, arch="VexArchARM")
		ret_sirsb = s_irsb.SimIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SimMIPS32:
	def __init__(self):
		self.bits = 32
		self.vex_arch = "VexArchMIPS32"
		self.name = "MIPS32"
		self.max_inst_bytes = 4
		self.ip_offset = 128
		self.sp_offset = 116
		self.endness = "Iend_BE"

	def emulate_return(self, state, inst_addr=0):
		return None

Architectures = { }
Architectures["AMD64"] = SimAMD64()
Architectures["X86"] = SimX86()
Architectures["ARM"] = SimARM()
Architectures["MIPS32"] = SimMIPS32()
