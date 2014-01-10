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

class SimArch:
	def __init__(self, bits, vex_arch, name, max_inst_bytes, ip_offset, sp_offset, bp_offset, ret_offset, stack_change, endness):
		self.bits = bits
		self.vex_arch = vex_arch
		self.name = name
		self.max_inst_bytes = max_inst_bytes
		self.ip_offset = ip_offset
		self.sp_offset = sp_offset
		self.bp_offset = bp_offset
		self.ret_offset = ret_offset
		self.endness = endness
		self.stack_change = stack_change

class SimAMD64(SimArch):
	def __init__(self):
		SimArch.__init__(self, 64, "VexArchAMD64", "AMD64", 15, 184, 48, 56, 16, -8, "Iend_LE")

	def emulate_return(self, state, inst_addr=0):
		# TODO: clobber rax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for AMD64 at 0x%x" % inst_addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=inst_addr, arch="VexArchAMD64")
		ret_sirsb = s_irsb.SimIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SimX86(SimArch):
	def __init__(self):
		SimArch.__init__(self, 32, "VexArchX86", "X86", 15, 68, 24, 28, 8, -4, "Iend_LE")

	def emulate_return(self, state, inst_addr=0):
		# TODO: clobber eax, maybe?
		# TODO: fix cheap mem_addr hack here
		l.debug("Emulating return for X86 at 0x%x" % inst_addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		ret_irsb = pyvex.IRSB(bytes="\xc3", mem_addr=inst_addr, arch="VexArchX86")
		ret_sirsb = s_irsb.SimIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SimARM(SimArch):
	def __init__(self):
		# TODO: determine proper base register (if it exists)
		# TODO: handle multiple return registers?
		SimArch.__init__(self, 32, "VexArchARM", "ARM", 4, 68, 60, 60, 8, -4, "Iend_LE")

	def emulate_return(self, state, inst_addr=0):
		l.debug("Emulating return for ARM at 0x%x" % inst_addr)
		if len(state.block_path) == 0:
			raise CallEmulationError("unable to emulate return with no call stack")

		# NOTE: ARM stuff
		ret_irsb = pyvex.IRSB(bytes="\xE1\xA0\xF0\x0E", mem_addr=inst_addr, arch="VexArchARM")
		ret_sirsb = s_irsb.SimIRSB(ret_irsb, state.copy_after(), ethereal=True)
		return ret_sirsb.exits()[0]

class SimMIPS32(SimArch):
	def __init__(self):
		# TODO: multiple return registers?
		SimArch.__init__(self, 32, "VexArchMIPS32", "MIPS32", 4, 128, 116, 120, 8, -4, "Iend_BE")

	def emulate_return(self, state, inst_addr=0):
		return None

Architectures = { }
Architectures["AMD64"] = SimAMD64()
Architectures["X86"] = SimX86()
Architectures["ARM"] = SimARM()
Architectures["MIPS32"] = SimMIPS32()
