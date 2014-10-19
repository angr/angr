#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex # pylint: disable=F0401

import logging
l = logging.getLogger("s_arch")

class SimArch:
    def __init__(self):
        # various names
        self.vex_arch = None
        self.name = None
        self.qemu_name = None

        # instruction stuff
        self.max_inst_bytes = None
        self.ret_instruction = None
        self.nop_instruction = None
        self.instruction_alignment = None

        # register ofsets
        self.ip_offset = None
        self.sp_offset = None
        self.bp_offset = None
        self.ret_offset = None

        # memory stuff
        self.bits = None
        self.vex_endness = None
        self.memory_endness = None
        self.register_endness = None
        self.stack_change = None

        # is it safe to cache IRSBs?
        self.cache_irsb = False

        self.function_prologs = None
        self.ida_processor = None
        self.initial_sp = 0xffff0000
        self.stack_size = 0x8000000
        self.default_register_values = [ ]
        self.default_symbolic_registers = [ ]
        self.registers = { }
        self.persistent_regs = [ ]
        self.concretize_unique_registers = set() # this is a list of registers that should be concretized, if unique, at the end of each block

    def make_state(self, **kwargs):
        initial_prefix = kwargs.pop("initial_prefix", None)

        s = SimState(arch=self, **kwargs)
        s.store_reg(self.sp_offset, self.initial_sp, self.bits / 8)

        if initial_prefix is not None:
            for reg in self.default_symbolic_registers:
                s.store_reg(reg, s.se.Unconstrained(initial_prefix + "_" + reg, self.bits, explicit_name=True))

        for (reg, val, is_addr, mem_region) in self.default_register_values:
            if ABSTRACT_MEMORY in s.options and is_addr:
                addr = s.se.ValueSet(region=mem_region, bits=self.bits, val=val)
                s.store_reg(reg, addr)
            else:
                s.store_reg(reg, val)

        return s

    def prepare_call_state(self, calling_state, initial_state=None, preserve_registers=(), preserve_memory=()): #pylint:disable=unused-argument,no-self-use
        '''
        This function prepares a state that is executing a call instruction.
        If given an initial_state, it copies over all of the critical registers to it from the
        calling_state. Otherwise, it prepares the calling_state for action.

        This is mostly used to create minimalistic for CFG generation. Some ABIs, such as MIPS PIE and
        x86 PIE, require certain information to be maintained in certain registers. For example, for
        PIE MIPS, this function transfer t9, gp, and ra to the new state.
        '''

        if initial_state is None:
            new_state = calling_state.copy()
        else:
            new_state = initial_state.copy()
            for r in set(preserve_registers):
                new_state.store_reg(r, calling_state.reg_expr(r))
            for a,s in set(preserve_memory):
                new_state.store_mem(a, calling_state.mem_expr(a,s))

        return new_state

    def get_default_reg_value(self, register):
        if register == 'sp':
            # Convert it to the corresponding register name
            registers = [r for r, v in self.registers.items() if v[0] == self.sp_offset]
            if len(registers) > 0:
                register = registers[0]
            else:
                return None
        for reg, val, _, _ in self.default_register_values:
            if reg == register:
                return val
        return None

    def get_ret_irsb(self, inst_addr):
        l.debug("Creating ret IRSB at 0x%x", inst_addr)
        irsb = pyvex.IRSB(bytes=self.ret_instruction, mem_addr=inst_addr,
        arch=self.vex_arch, endness=self.vex_endness)
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
    def __init__(self, endness=None): #pylint:disable=unused-argument
        SimArch.__init__(self)
        self.bits = 64
        self.vex_arch = "VexArchAMD64"
        self.vex_endness = "VexEndnessLE"
        self.name = "AMD64"
        self.qemu_name = 'x86_64'
        self.ida_processor = 'metapc'
        self.max_inst_bytes = 15
        self.ip_offset = 184
        self.sp_offset = 48
        self.bp_offset = 56
        self.ret_offset = 16
        self.stack_change = -8
        self.initial_sp = 0x7ffffffffff0000
        self.memory_endness = "Iend_LE"
        self.register_endness = "Iend_LE"
        self.ret_instruction = "\xc3"
        self.nop_instruction = "\x90"
        self.instruction_alignment = 1
        self.default_register_values = [
            ( 'd', 1, False, None ),
            ( 'rsp', self.initial_sp, True, 'global' )
        ]
        self.default_symbolic_registers = [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip' ]

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
    def __init__(self, endness=None): #pylint:disable=unused-argument
        SimArch.__init__(self)
        self.bits = 32
        self.vex_arch = "VexArchX86"
        self.vex_endness = "VexEndnessLE"
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
            ( 'esp', self.initial_sp, True, 'global' ) # the stack
        ]
        self.default_symbolic_registers = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip' ]


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
        self.vex_endness = "VexEndnessLE" if endness == "Iend_LE" else "VexEndnessBE"
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
            ( 'sp', self.initial_sp, True, 'global' ), # the stack
            ( 'thumb', 0x00000000, False, None ) # the thumb state
        ]
        self.default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc' ]

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
        self.vex_endness = "VexEndnessLE" if endness == "Iend_LE" else "VexEndnessBE"
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
        self.persistent_regs = ['gp', 'ra', 't9']

        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ) # the stack
        ]

        self.default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28', 'sp', 'bp', 'lr', 'pc', 'hi', 'lo' ]

        self.registers = {
            'r0': (0, 4), 'zero': (0, 4),
            'r1': (4, 4), 'at': (4, 4),
            'r2': (8, 4), 'v0': (8, 4),
            'r3': (12, 4), 'v1': (12, 4),
            'r4': (16, 4), 'a0': (16, 4),
            'r5': (20, 4), 'a1': (20, 4),
            'r6': (24, 4), 'a2': (24, 4),
            'r7': (28, 4), 'a3': (28, 4),
            'r8': (32, 4), 't0': (32, 4),
            'r9': (36, 4), 't1': (36, 4),
            'r10': (40, 4), 't2': (40, 4),
            'r11': (44, 4), 't3': (44, 4),
            'r12': (48, 4), 't4': (48, 4),
            'r13': (52, 4), 't5': (52, 4),
            'r14': (56, 4), 't6': (56, 4),
            'r15': (60, 4), 't7': (60, 4),
            'r16': (64, 4), 's0': (64, 4),
            'r17': (68, 4), 's1': (68, 4),
            'r18': (72, 4), 's2': (72, 4),
            'r19': (76, 4), 's3': (76, 4),
            'r20': (80, 4), 's4': (80, 4),
            'r21': (84, 4), 's5': (84, 4),
            'r22': (88, 4), 's6': (88, 4),
            'r23': (92, 4), 's7': (92, 4),
            'r24': (96, 4), 't8': (96, 4),
            'r25': (100, 4), 't9': (100, 4),
            'r26': (104, 4), 'k0': (104, 4),
            'r27': (108, 4), 'k1': (108, 4),
            'r28': (112, 4), 'gp': (112, 4),

            'r29': (116, 4), 'sp': (116, 4),

            'r30': (120, 4), 's8': (120, 4), 'bp': (120, 4),

            'r31': (124, 4), 'ra': (124, 4), 'lr': (124, 4),

            'pc': (128, 4),
            'ip': (128, 4),

            'hi': (132, 4),
            'lo': (136, 4),
        }

        if endness == "Iend_BE":
            self.ret_instruction = "\x08\x00\xE0\x03"[::-1] + "\x25\x08\x20\x00"[::-1]
            self.nop_instruction = self.nop_instruction[::-1]

    def prepare_call_state(self, calling_state, initial_state=None, preserve_registers=(), preserve_memory=()):
        istate = initial_state if initial_state is not None else self.make_state()
        return SimArch.prepare_call_state(self, calling_state, initial_state=istate, preserve_registers=preserve_registers + ('t9', 'gp', 'ra'), preserve_memory=preserve_memory)

class SimPPC32(SimArch):
    def __init__(self, endness="Iend_BE"):
        # Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
        # PowerPC doesn't have stack base pointer, so bp_offset is set to -1 below
        # Normally r1 is used as stack pointer

        SimArch.__init__(self)
        self.bits = 32
        self.vex_arch = "VexArchPPC32"
        self.vex_endness = "VexEndnessLE" if endness == "Iend_LE" else "VexEndnessBE"
        self.name = "PPC32"
        self.qemu_name = 'ppc'
        self.ida_processor = 'ppc'
        self.max_inst_bytes = 4
        self.ip_offset = 1168
        self.sp_offset = 20
        self.bp_offset = -1
        self.ret_offset = 8
        self.stack_change = -4
        self.memory_endness = endness
        self.register_endness = endness
        self.ret_instruction = "\x4e\x80\x00\x20"
        self.nop_instruction = "\x60\x00\x00\x00"
        self.instruction_alignment = 4
        self.function_prologs=("\x94\x21\xff", "\x7c\x08\x02\xa6", "\x94\x21\xfe") # 4e800020: blr

        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ) # the stack
        ]

        self.default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28', 'r29', 'r30', 'r31', 'sp', 'pc' ]

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

            # TODO: lr
            'ip': (1160, 4),
            'pc': (1160, 4),
        }

        if endness == 'Iend_LE':
            self.ret_instruction = self.ret_instruction[::-1]
            self.nop_instruction = self.nop_instruction[::-1]
            self.function_prologs = tuple(map(lambda x: x[::-1], self.function_prologs))

class SimPPC64(SimArch):
    def __init__(self, endness="Iend_BE"):
        # Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
        # PowerPC doesn't have stack base pointer, so bp_offset is set to -1 below
        # Normally r1 is used as stack pointer

        SimArch.__init__(self)
        self.bits = 64
        self.vex_arch = "VexArchPPC64"
        self.vex_endness = "VexEndnessLE" if endness == "Iend_LE" else "VexEndnessBE"
        self.name = "PPC64"
        self.qemu_name = 'ppc64'
        self.ida_processor = 'ppc64'
        self.max_inst_bytes = 4
        self.ip_offset = 1296
        self.sp_offset = 24
        self.bp_offset = -1
        self.ret_offset = 8
        self.stack_change = -8
        self.initial_sp = 0xffffffffff000000
        self.memory_endness = endness
        self.register_endness = endness
        self.ret_instruction = "\x4e\x80\x00\x20"
        self.nop_instruction = "\x60\x00\x00\x00"
        self.instruction_alignment = 4
        self.function_prologs=("\x94\x21\xff", "\x7c\x08\x02\xa6", "\x94\x21\xfe") # 4e800020: blr

        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ) # the stack
        ]

        self.registers = {
            'r0': (16, 8),
            'r1': (24, 8), 'sp': (24, 8),
            'r2': (32, 8), 'rtoc': (32, 8),
            'r3': (40, 8),
            'r4': (48, 8),
            'r5': (56, 8),
            'r6': (64, 8),
            'r7': (72, 8),
            'r8': (80, 8),
            'r9': (88, 8),
            'r10': (96, 8),
            'r11': (104, 8),
            'r12': (112, 8),
            'r13': (120, 8),
            'r14': (128, 8),
            'r15': (136, 8),
            'r16': (144, 8),
            'r17': (152, 8),
            'r18': (160, 8),
            'r19': (168, 8),
            'r20': (176, 8),
            'r21': (184, 8),
            'r22': (192, 8),
            'r23': (200, 8),
            'r24': (208, 8),
            'r25': (216, 8),
            'r26': (224, 8),
            'r27': (232, 8),
            'r28': (240, 8),
            'r29': (248, 8),
            'r30': (256, 8),
            'r31': (260, 8),

            # TODO: pc,lr
            'ip': (1296, 4),
        }

        if endness == 'Iend_LE':
            self.ret_instruction = self.ret_instruction[::-1]
            self.nop_instruction = self.nop_instruction[::-1]
            self.function_prologs = tuple(map(lambda x: x[::-1], self.function_prologs))

Architectures = { }
Architectures["AMD64"] = SimAMD64
Architectures["X86"] = SimX86
Architectures["ARM"] = SimARM
Architectures["MIPS32"] = SimMIPS32
Architectures["PPC32"] = SimPPC32
Architectures["PPC64"] = SimPPC64

from .s_state import SimState
from .s_options import ABSTRACT_MEMORY
