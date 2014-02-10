#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex # pylint: disable=F0401
import s_exception

import logging
l = logging.getLogger("s_arch")

class CallEmulationError(s_exception.SimError):
	pass

class SimArchError(s_exception.SimError):
	pass

class SimArch:
	def __init__(self, bits, vex_arch, name, max_inst_bytes, ip_offset, sp_offset, bp_offset, ret_offset, stack_change, endness, ret_instruction, nop_instruction):
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
		self.ret_instruction = ret_instruction
		self.nop_instruction = nop_instruction

	def get_ret_irsb(self, inst_addr):
		l.debug("Creating ret IRSB at 0x%x", inst_addr)
		irsb = pyvex.IRSB(bytes=self.ret_instruction, mem_addr=inst_addr, arch=self.vex_arch)
		l.debug("... created IRSB %s", irsb)
		return irsb
	
	def get_nop_irsb(self, inst_addr):
		return pyvex.IRSB(bytes=self.nop_instruction, mem_addr=inst_addr, arch=self.vex_arch)

class SimAMD64(SimArch):
	def __init__(self):
		SimArch.__init__(self, 64, "VexArchAMD64", "AMD64", 15, 184, 48, 56, 16, -8, "Iend_LE", "\xc3", "\x90")

class SimX86(SimArch):
	def __init__(self):
		SimArch.__init__(self, 32, "VexArchX86", "X86", 15, 68, 24, 28, 8, -4, "Iend_LE", "\xc3", "\x90")

class SimARM(SimArch):
	def __init__(self):
		# TODO: determine proper base register (if it exists)
		# TODO: handle multiple return registers?
		# TODO: which endianness should we put here?
		SimArch.__init__(self, 32, "VexArchARM", "ARM", 4, 68, 60, 60, 8, -4, "Iend_LE", "\x0E\xF0\xA0\xE1", "\x00\x00\x00\x00")

class SimMIPS32(SimArch):
	def __init__(self):
		# TODO: multiple return registers?
		# TODO: which endianness?
		SimArch.__init__(self, 32, "VexArchMIPS32", "MIPS32", 4, 128, 116, 120, 8, -4, "Iend_LE", "\x08\x00\xE0\x03" + "\x25\x08\x20\x00", "\x00\x00\x00\x00")

class SimPPC32(SimArch):
	def __init__(self):
		# Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
		# PowerPC doesn't have stack base pointer, so bp_offset is set to -1 below
		# Normally r1 is used as stack pointer
		# TODO: Return instruction
		SimArch.__init__(self, 32, "VexArchPPC32", "PPC32", 4, 1152, 4, -1, 8, -4, "Iend_BE", "\x4e\x80\x00\x20", "\x60\x00\x00\x00") # 4e800020: blr

Architectures = { }
Architectures["AMD64"] = SimAMD64()
Architectures["X86"] = SimX86()
Architectures["ARM"] = SimARM()
Architectures["MIPS32"] = SimMIPS32()
Architectures["PPC32"] = SimPPC32()
