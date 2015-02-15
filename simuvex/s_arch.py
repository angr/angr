#!/usr/bin/env python
''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import pyvex # pylint: disable=F0401
import capstone as _capstone #pylint:disable=import-error

import logging
l = logging.getLogger("s_arch")

import ana

class SimArch(ana.Storable):
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
        self.cache_irsb = True

        self.function_prologs = set()
        self.ida_processor = None
        self.cs_arch = None
        self.cs_mode = None
        self._cs = None
        self.initial_sp = 0xffff0000
        # Difference of the stack pointer after a call instruction (or its equivalent) is executed
        self.call_sp_fix = 0
        self.stack_size = 0x8000000
        self.default_register_values = [ ]
        self.entry_register_values = { }
        self.default_symbolic_registers = [ ]
        self.registers = { }
        self.argument_registers = { }
        self.persistent_regs = [ ]
        self.concretize_unique_registers = set() # this is a list of registers that should be concretized, if unique, at the end of each block

        # there are going to be crazy-loads of these guys if we pickle them individually
        # for each state
        self.make_uuid()

    def gather_info_from_state(self, state):
        return {}

    def prepare_state(self, state, info=None):
        return state

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

    @property
    def capstone(self):
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode)
            self._cs.detail = True
        return self._cs

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
        self.call_sp_fix = -8
        self.memory_endness = "Iend_LE"
        self.register_endness = "Iend_LE"
        self.cs_arch = _capstone.CS_ARCH_X86
        self.cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
        self.function_prologs = {
            r"\x55\x48\x89\xe5", # push rbp; mov rbp, rsp
            r"\x48\x83\xec[\x00-\xff]", # sub rsp, xxx
        }
        self.ret_instruction = "\xc3"
        self.nop_instruction = "\x90"
        self.instruction_alignment = 1
        self.default_register_values = [
            ( 'd', 1, False, None ),
            ( 'rsp', self.initial_sp, True, 'global' ),
            ( 'fs', 0x9000000000000000, True, 'global')
        ]
        self.entry_register_values = {
            'rax': 0x1c,
            'rdx': 'ld_destructor'
        }

        self.default_symbolic_registers = [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip' ]

        self.register_names = {
            16: 'rax',
            24: 'rcx',
            32: 'rdx',
            40: 'rbx',

            48: 'rsp',

            56: 'rbp',
            64: 'rsi',
            72: 'rdi',

            80: 'r8',
            88: 'r9',
            96: 'r10',
            104: 'r11',
            112: 'r12',
            120: 'r13',
            128: 'r14',
            136: 'r15',

            # condition stuff
            144: 'cc_op',
            152: 'cc_dep1',
            160: 'cc_dep2',
            168: 'cc_ndep',

            # this determines which direction SSE instructions go
            176: 'd',

            184: 'rip',

            208: 'fs',
        }

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
            'ip': (184, 8),

            'fs': (208, 8)
        }

        self.argument_registers = {
            self.registers['rax'][0],
            self.registers['rcx'][0],
            self.registers['rdx'][0],
            self.registers['rbx'][0],
            self.registers['rsi'][0],
            self.registers['rdi'][0],
            self.registers['r8'][0],
            self.registers['r9'][0],
            self.registers['r10'][0],
            self.registers['r11'][0],
            self.registers['r12'][0],
            self.registers['r13'][0],
            self.registers['r14'][0],
            self.registers['r15'][0],
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
        self.call_sp_fix = -8
        self.ip_offset = 68
        self.sp_offset = 24
        self.bp_offset = 28
        self.ret_offset = 8
        self.stack_change = -4
        self.memory_endness = "Iend_LE"
        self.register_endness = "Iend_LE"
        self.cs_arch = _capstone.CS_ARCH_X86
        self.cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
        self.function_prologs = {
            r"\x55\x8b\xec\x55", # push ebp; mov ebp, esp
        }
        self.ret_instruction = "\xc3"
        self.nop_instruction = "\x90"
        self.instruction_alignment = 1
        self.default_register_values = [
            ( 'esp', self.initial_sp, True, 'global' ) # the stack
        ]
        self.entry_register_values = {
            'eax': 0x1C,
            'edx': 'ld_destructor',
            'ebp': 0
        }
        self.default_symbolic_registers = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip' ]

        self.register_names = {
            8: 'eax',
            12: 'ecx',
            16: 'edx',
            20: 'ebx',

            24: 'esp',

            28: 'ebp',
            32: 'esi',
            36: 'edi',

            # condition stuff
            40: 'cc_op',
            44: 'cc_dep1',
            48: 'cc_dep2',
            52: 'cc_ndep',

            # this determines which direction SSE instructions go
            56: 'd',

            68: 'eip',

            296: 'gs',
        }

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
            'ip': (68, 4),

            'gs': (296, 2),
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
        self.cs_arch = _capstone.CS_ARCH_ARM
        self.cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else _capstone.CS_MODE_BIG_ENDIAN
        self.ret_instruction = "\x0E\xF0\xA0\xE1"
        self.nop_instruction = "\x00\x00\x00\x00"
        if endness == "Iend_LE":
            self.function_prologs = {
                r"[\x00-\xff][\x00-\xff]\x2d\xe9", # stmfd sp!, {xxxxx}
            }
        else:
            self.function_prologs = {
                r"\xe9\x2d[\x00-\xff][\x00-\xff]", # stmfd sp!, {xxxxx}
            }
        self.instruction_alignment = 4
        self.concretize_unique_registers.add(64)
        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ), # the stack
            ( 'thumb', 0x00000000, False, None ) # the thumb state
        ]
        self.entry_register_values = {
            'r0': 'ld_destructor'
        }

        self.default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc' ]

        self.register_names = {
            8: 'r0',
            12: 'r1',
            16: 'r2',
            20: 'r3',
            24: 'r4',
            28: 'r5',
            32: 'r6',
            36: 'r7',
            40: 'r8',
            44: 'r9',
            48: 'r10',
            52: 'r11',
            56: 'r12',

            # stack pointer
            60: 'sp',

            # link register
            64: 'lr',

            # program counter
            68: 'pc',

            # condition stuff
            72: 'cc_op',
            76: 'cc_dep1',
            80: 'cc_dep2',
            84: 'cc_ndep',

            # thumb state
            188: 'thumb',
        }

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
            'ip': (68, 4),

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

        self._cs_thumb = None

    @property
    def capstone(self):
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_ARM)
            self._cs.detail = True
        return self._cs

    @property
    def capstone_thumb(self):
        if self._cs_thumb is None:
            self._cs_thumb = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_THUMB)
            self._cs_thumb.detail = True
        return self._cs_thumb

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
        self.cs_arch = _capstone.CS_ARCH_MIPS
        self.cs_mode = _capstone.CS_MODE_32 + (_capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else _capstone.CS_MODE_BIG_ENDIAN)
        if endness == "Iend_LE":
            self.function_prologs = {
                r"[\x00-\xff]\xff\xbd\x27", # addiu $sp, xxx
                r"[\x00-\xff][\x00-\xff]\x1c\x3c[\x00-\xff][\x00-\xff]\x9c\x27", # lui $gp, xxx; addiu $gp, $gp, xxxx
            }
        else:
            self.function_prologs = {
                r"\x27\xbd\xff[\x00-\xff]", # addiu $sp, xxx
                r"\x3c\x1c[\x00-\xff][\x00-\xff]\x9c\x27[\x00-\xff][\x00-\xff]", # lui $gp, xxx; addiu $gp, $gp, xxxx
            }

        self.ret_instruction = "\x08\x00\xE0\x03" + "\x25\x08\x20\x00"
        self.nop_instruction = "\x00\x00\x00\x00"
        self.instruction_alignment = 4
        self.persistent_regs = ['gp', 'ra', 't9']

        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ),   # the stack
        ]
        self.entry_register_values = {
            'v0': 'ld_destructor',
            'ra': 0
        }

        self.default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28', 'sp', 'bp', 'lr', 'pc', 'hi', 'lo' ]

        self.register_names = {
            0: 'zero',
            4: 'at',
            8: 'v0',
            12: 'v1',
            16: 'a0',
            20: 'a1',
            24: 'a2',
            28: 'a3',
            32: 't0',
            36: 't1',
            40: 't2',
            44: 't3',
            48: 't4',
            52: 't5',
            56: 't6',
            60: 't7',
            64: 's0',
            68: 's1',
            72: 's2',
            76: 's3',
            80: 's4',
            84: 's5',
            88: 's6',
            92: 's7',
            96: 't8',
            100: 't9',
            104: 'k0',
            108: 'k1',
            112: 'gp',
            116: 'sp',
            120: 's8',
            124: 'ra',

            128: 'pc',

            132: 'hi',
            136: 'lo',
        }

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

            'r30': (120, 4), 's8': (120, 4), 'bp': (120, 4), 'fp': (120, 4),

            'r31': (124, 4), 'ra': (124, 4), 'lr': (124, 4),

            'pc': (128, 4),
            'ip': (128, 4),

            'hi': (132, 4),
            'lo': (136, 4),
        }

        if endness == "Iend_BE":
            self.ret_instruction = "\x08\x00\xE0\x03"[::-1] + "\x25\x08\x20\x00"[::-1]
            self.nop_instruction = self.nop_instruction[::-1]

    def gather_info_from_state(self, state):
        info = {}
        for reg in self.persistent_regs:
            info[reg] = state.reg_expr(reg) # TODO: Only do t9 for PIC
        return info

    def prepare_state(self, state, info=None):
        if info is not None:
            # TODO: Only do this for PIC!
            if 't9' in info:
                state.store_reg('t9', info['t9'])
            elif 'current_function' in info:
                state.store_reg('t9', info['current_function'])

        return state

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
        self.ip_offset = 1160
        self.sp_offset = 20
        self.bp_offset = -1
        self.ret_offset = 8
        self.stack_change = -4
        self.memory_endness = endness
        self.register_endness = endness
        self.cs_arch = _capstone.CS_ARCH_PPC
        self.cs_mode = _capstone.CS_MODE_32 + (_capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else _capstone.CS_MODE_BIG_ENDIAN)
        self.ret_instruction = "\x4e\x80\x00\x20"
        self.nop_instruction = "\x60\x00\x00\x00"
        self.instruction_alignment = 4

        if endness == "Iend_LE":
            self.function_prologs = {
                r"\x94\x21\xff",
                r"\x7c\x08\x02\xa6",
                "\x94\x21\xfe"
            } # 4e800020: blr
        else:
            self.function_prologs = {
                r"\xff\x21\x94",
                r"\xa6\x02\x08\x7c"
                r"\xfe\x21\x94"
            } # 4e800020: blr

        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ) # the stack
        ]
        self.entry_register_values = {
            'r3': 'argc',
            'r4': 'argv',
            'r5': 'envp',
            'r6': 'auxv',
            'r7': 'ld_destructor'
        }

        self.default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28', 'r29', 'r30', 'r31', 'sp', 'pc' ]

        self.registers_names = {
            16: 'r0',
            20: 'r1',
            24: 'r2',
            28: 'r3',
            32: 'r4',
            36: 'r5',
            40: 'r6',
            44: 'r7',
            48: 'r8',
            52: 'r9',
            56: 'r10',
            60: 'r11',
            64: 'r12',
            68: 'r13',
            72: 'r14',
            76: 'r15',
            80: 'r16',
            84: 'r17',
            88: 'r18',
            92: 'r19',
            96: 'r20',
            100: 'r21',
            104: 'r22',
            108: 'r23',
            112: 'r24',
            116: 'r25',
            120: 'r26',
            124: 'r27',
            128: 'r28',
            132: 'r29',
            136: 'r30',
            140: 'r31',

            # TODO: lr
            1160: 'pc',
        }

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
        self.cs_arch = _capstone.CS_ARCH_PPC
        self.cs_mode = _capstone.CS_MODE_64 + (_capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else _capstone.CS_MODE_BIG_ENDIAN)
        self.ret_instruction = "\x4e\x80\x00\x20"
        self.nop_instruction = "\x60\x00\x00\x00"
        self.instruction_alignment = 4

        if endness == "Iend_LE":
            self.function_prologs = {
                r"\x94\x21\xff",
                r"\x7c\x08\x02\xa6",
                r"\x94\x21\xfe"
            } # 4e800020: blr
        else:
            self.function_prologs = {
                r"\xff\x21\x94",
                r"\xa6\x02\x08\x7c",
                r"\xfe\x21\x94",
            } # 4e800020: blr

        self.default_register_values = [
            ( 'sp', self.initial_sp, True, 'global' ) # the stack
        ]
        self.entry_register_values = {
            'r2': 'toc',
            'r3': 'argc',
            'r4': 'argv',
            'r5': 'envp',
            'r6': 'auxv',
            'r7': 'ld_destructor'
        }

        self.register_names = {
            16: 'r0',
            24: 'r1',
            32: 'r2',
            40: 'r3',
            48: 'r4',
            56: 'r5',
            64: 'r6',
            72: 'r7',
            80: 'r8',
            88: 'r9',
            96: 'r10',
            104: 'r11',
            112: 'r12',
            120: 'r13',
            128: 'r14',
            136: 'r15',
            144: 'r16',
            152: 'r17',
            160: 'r18',
            168: 'r19',
            176: 'r20',
            184: 'r21',
            192: 'r22',
            200: 'r23',
            208: 'r24',
            216: 'r25',
            224: 'r26',
            232: 'r27',
            240: 'r28',
            248: 'r29',
            256: 'r30',
            260: 'r31',

            # TODO: pc,lr
            1296: 'pc',
        }

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

Architectures = { }
Architectures["AMD64"] = SimAMD64
Architectures["X86"] = SimX86
Architectures["ARM"] = SimARM
Architectures["MIPS32"] = SimMIPS32
Architectures["PPC32"] = SimPPC32
Architectures["PPC64"] = SimPPC64

from .s_state import SimState
from .s_options import ABSTRACT_MEMORY
