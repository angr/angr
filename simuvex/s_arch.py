#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex # pylint: disable=F0401

import logging
l = logging.getLogger("s_arch")

class SimArch:
	def __init__(self):
		self.bits = None
		self.vex_arch = None
		self.name = None
		self.max_inst_bytes = None
		self.ip_offset = None
		self.sp_offset = None
		self.bp_offset = None
		self.ret_offset = None
		self.memory_endness = None
		self.register_endness = None
		self.stack_change = None
		self.ret_instruction = None
		self.nop_instruction = None
		self.instruction_alignment = None
		self.function_prologs = None
		self.cache_irsb = None
		self.qemu_name = None
		self.ida_processor = None
		self.concretize_unique_registers = set() # this is a list of registers that should be concretized, if unique, at the end of each block

	def get_ret_irsb(self, inst_addr):
		l.debug("Creating ret IRSB at 0x%x", inst_addr)
		irsb = pyvex.IRSB(bytes=self.ret_instruction, mem_addr=inst_addr, arch=self.vex_arch)
		l.debug("... created IRSB %s", irsb)
		return irsb

	def get_nop_irsb(self, inst_addr):
		return pyvex.IRSB(bytes=self.nop_instruction, mem_addr=inst_addr, arch=self.vex_arch)

	@property
	def struct_fmt(self):
		fmt = ""

		if self.memory_endness == "Iend_BE":
			fmt += ">"
		else:
			fmt += "<"

		if self.bits == 64:
			fmt += "Q"
		elif self.bits == 32:
			fmt += "I"
		elif self.bits == 16:
			fmt += "H"
		elif self.bits == 8:
			fmt += "B"

		return fmt

	@property
	def bytes(self):
		return self.bits/8

class SimAMD64(SimArch):
	def __init__(self):
		SimArch.__init__(self)
		self.bits = 64
		self.vex_arch = "VexArchAMD64"
		self.name = "AMD64"
		self.qemu_name = 'x86_64'
		self.ida_processor = 'metapc'
		self.max_inst_bytes = 15
		self.ip_offset = 184
		self.sp_offset = 48
		self.bp_offset = 56
		self.ret_offset = 16
		self.stack_change = -8
		self.memory_endness = "Iend_LE"
		self.register_endness = "Iend_LE"
		self.ret_instruction = "\xc3"
		self.nop_instruction = "\x90"
		self.instruction_alignment = 1

class SimX86(SimArch):
	def __init__(self):
		SimArch.__init__(self)
		self.bits = 32
		self.vex_arch = "VexArchX86"
		self.name = "X86"
		self.qemu_name = 'i386'
		self.ida_processor = 'metapc'
		self.max_inst_bytes = 15
		self.ip_offset = 68
		self.sp_offset = 24
		self.bp_offset = 28
		self.ret_offset = 8
		self.stack_change = -4
		self.memory_endness = "Iend_LE"
		self.register_endness = "Iend_LE"
		self.ret_instruction = "\xc3"
		self.nop_instruction = "\x90"
		self.instruction_alignment = 1

class SimARM(SimArch):
	def __init__(self, endness="Iend_LE"):
		# TODO: determine proper base register (if it exists)
		# TODO: handle multiple return registers?
		# TODO: which endianness should we put here?
		SimArch.__init__(self)
		self.bits = 32
		self.vex_arch = "VexArchARM"
		self.name = "ARM"
		self.qemu_name = 'arm'
		self.ida_processor = 'armb'
		self.max_inst_bytes = 4
		self.ip_offset = 68
		self.sp_offset = 60
		self.bp_offset = 60
		self.ret_offset = 8
		self.stack_change = -4
		self.memory_endness = endness
		self.register_endness = endness
		self.ret_instruction = "\x0E\xF0\xA0\xE1"
		self.nop_instruction = "\x00\x00\x00\x00"
		self.instruction_alignment = 4
		self.cache_irsb = False
		self.concretize_unique_registers.add(64)

		if endness == "Iend_BE":
			self.ret_instruction = self.ret_instruction[::-1]
			self.nop_instruction = self.nop_instruction[::-1]

class SimMIPS32(SimArch):
	def __init__(self, endness="Iend_BE"):
		# TODO: multiple return registers?
		# TODO: which endianness?
		SimArch.__init__(self)
		self.bits = 32
		self.vex_arch = "VexArchMIPS32"
		self.name = "MIPS32"
		self.qemu_name = 'mips'
		self.ida_processor = 'mipsb'
		self.max_inst_bytes = 4
		self.ip_offset = 128
		self.sp_offset = 116
		self.bp_offset = 120
		self.ret_offset = 8
		self.stack_change = -4
		self.memory_endness = endness
		self.register_endness = endness
		self.ret_instruction = "\x08\x00\xE0\x03" + "\x25\x08\x20\x00"
		self.nop_instruction = "\x00\x00\x00\x00"
		self.instruction_alignment = 4

		if endness == "Iend_BE":
			self.ret_instruction = "\x08\x00\xE0\x03"[::-1] + "\x25\x08\x20\x00"[::-1]
			self.nop_instruction = self.nop_instruction[::-1]

class SimPPC32(SimArch):
	def __init__(self):
		# Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
		# PowerPC doesn't have stack base pointer, so bp_offset is set to -1 below
		# Normally r1 is used as stack pointer

		SimArch.__init__(self)
		self.bits = 32
		self.vex_arch = "VexArchPPC32"
		self.name = "PPC32"
		self.qemu_name = 'ppc'
		self.ida_processor = 'ppc'
		self.max_inst_bytes = 4
		self.ip_offset = 1168
		self.sp_offset = 20
		self.bp_offset = -1
		self.ret_offset = 8
		self.stack_change = -4
		self.memory_endness = 'Iend_BE'
		self.register_endness = 'Iend_BE'
		self.ret_instruction = "\x4e\x80\x00\x20"
		self.nop_instruction = "\x60\x00\x00\x00"
		self.instruction_alignment = 4
		self.function_prologs=("\x94\x21\xff", "\x7c\x08\x02\xa6", "\x94\x21\xfe") # 4e800020: blr

Architectures = { }
Architectures["AMD64"] = SimAMD64
Architectures["X86"] = SimX86
Architectures["ARM"] = SimARM
Architectures["MIPS32"] = SimMIPS32
Architectures["PPC32"] = SimPPC32
