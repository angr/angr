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
		self.initial_sp = 0xffff0000
		self.default_register_values = [ ]
		self.concretize_unique_registers = set() # this is a list of registers that should be concretized, if unique, at the end of each block

	def make_state(self, solver_engine, **kwargs):
		s = SimState(solver_engine, arch=self, **kwargs)
		s.store_reg(self.sp_offset, self.initial_sp, self.bits)

		for (reg, val) in self.default_register_values:
			s.store_reg(reg, val)

		return s

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
		self.default_register_values = [
			( 'd', 1 ),
			( 'rsp', 0xfffffffffff0000 )
		]

		self.registers = {
			'rax': (16, 8),
			'rcx': (24, 8),
			'rdx': (32, 8),
			'rbx': (40, 8),

			'sp': (48, 8),
			'rsp': (48, 8),

			'rbp': (56, 8),
			'rsi': (64, 8),
			'rdi': (72, 8),

			'r8': (80, 8),
			'r9': (88, 8),
			'r10': (96, 8),
			'r11': (104, 8),
			'r12': (112, 8),
			'r13': (120, 8),
			'r14': (128, 8),
			'r15': (136, 8),

			# condition stuff
			'cc_op': (144, 8),
			'cc_dep1': (152, 8),
			'cc_dep2': (160, 8),
			'cc_ndep': (168, 8),

			# this determines which direction SSE instructions go
			'd': (176, 8),

			'rip': (184, 8),
			'pc': (184, 8),
			'ip': (184, 8)
		}

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
		self.default_register_values = [
			( 'esp', 0xffff0000 ) # the stack
		]


		self.registers = {
			'eax': (8, 4),
			'ecx': (12, 4),
			'edx': (16, 4),
			'ebx': (20, 4),

			'sp': (24, 4),
			'esp': (24, 4),

			'ebp': (28, 4),
			'esi': (32, 4),
			'edi': (36, 4),

			# condition stuff
			'cc_op': (40, 4),
			'cc_dep1': (44, 4),
			'cc_dep2': (48, 4),
			'cc_ndep': (52, 4),

			# this determines which direction SSE instructions go
			'd': (56, 4),

			'eip': (68, 4),
			'pc': (68, 4),
			'ip': (68, 4)
		}

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
		self.default_register_values = [
			( 'sp', 0xffff0000 ), # the stack
			( 'thumb', 0x00000000 ) # the thumb state
		]

		self.registers = {
			# GPRs
			'r0': (8, 4),
			'r1': (12, 4),
			'r2': (16, 4),
			'r3': (20, 4),
			'r4': (24, 4),
			'r5': (28, 4),
			'r6': (32, 4),
			'r7': (36, 4),
			'r8': (40, 4),
			'r9': (44, 4),
			'r10': (48, 4),
			'r11': (52, 4),
			'r12': (56, 4),

			# stack pointer
			'sp': (60, 4),
			'r13': (60, 4),

			# link register
			'r14': (64, 4),
			'lr': (64, 4),

			# program counter
			'r15': (68, 4),
			'ip': (68, 4),
			'pc': (68, 4),

			# condition stuff
			'cc_op': (72, 4),
			'cc_dep1': (76, 4),
			'cc_dep2': (80, 4),
			'cc_ndep': (84, 4),

			# thumb state
			'thumb': ( 0x188, 4 )
		}

		if endness == "Iend_BE":
			self.ret_instruction = self.ret_instruction[::-1]
			self.nop_instruction = self.nop_instruction[::-1]

class SimMIPS32(SimArch):
	def __init__(self, endness="Iend_LE"):
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

		self.default_register_values = [
			( 'sp', 0xffff0000 ) # the stack
		]

		self.registers = {
			'r0': (0, 4),
			'r1': (4, 4),
			'r2': (8, 4),
			'r3': (12, 4),
			'r4': (16, 4),
			'r5': (20, 4),
			'r6': (24, 4),
			'r7': (28, 4),
			'r8': (32, 4),
			'r9': (36, 4),
			'r10': (40, 4),
			'r11': (44, 4),
			'r12': (48, 4),
			'r13': (52, 4),
			'r14': (56, 4),
			'r15': (60, 4),
			'r16': (64, 4),
			'r17': (68, 4),
			'r18': (72, 4),
			'r19': (76, 4),
			'r20': (80, 4),
			'r21': (84, 4),
			'r22': (88, 4),
			'r23': (92, 4),
			'r24': (96, 4),
			'r25': (100, 4),
			'r26': (104, 4),
			'r27': (108, 4),
			'r28': (112, 4),

			'r29': (116, 4),
			'sp': (116, 4),

			'r30': (120, 4),
			'bp': (120, 4),

			'r31': (124, 4),
			'lr': (124, 4),

			'pc': (128, 4),
			'ip': (128, 4),

			'hi': (132, 4),
			'lo': (136, 4),
		}

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

		self.default_register_values = [
			( 'sp', 0xffff0000 ) # the stack
		]

		self.registers = {
			'r0': (16, 4),
			'r1': (20, 4), 'sp': (20, 4),
			'r2': (24, 4),
			'r3': (28, 4),
			'r4': (32, 4),
			'r5': (36, 4),
			'r6': (40, 4),
			'r7': (44, 4),
			'r8': (48, 4),
			'r9': (52, 4),
			'r10': (56, 4),
			'r11': (60, 4),
			'r12': (64, 4),
			'r13': (68, 4),
			'r14': (72, 4),
			'r15': (76, 4),
			'r16': (80, 4),
			'r17': (84, 4),
			'r18': (88, 4),
			'r19': (92, 4),
			'r20': (96, 4),
			'r21': (100, 4),
			'r22': (104, 4),
			'r23': (108, 4),
			'r24': (112, 4),
			'r25': (116, 4),
			'r26': (120, 4),
			'r27': (124, 4),
			'r28': (128, 4),
			'r29': (132, 4),
			'r30': (136, 4),
			'r31': (140, 4),

			# TODO: pc,lr
			'ip': (1160, 4),
		}

Architectures = { }
Architectures["AMD64"] = SimAMD64
Architectures["X86"] = SimX86
Architectures["ARM"] = SimARM
Architectures["MIPS32"] = SimMIPS32
Architectures["PPC32"] = SimPPC32

from .s_state import SimState
