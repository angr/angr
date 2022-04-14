import claripy

import logging
import time

from angr import sim_options as o

l = logging.getLogger(name=__name__)

#####################
# Dirty calls
#####################

# they return retval, constraints

# Reference:
# http://www-inteng.fnal.gov/Integrated_Eng/GoodwinDocs/pdf/Sys%20docs/PowerPC/PowerPC%20Elapsed%20Time.pdf
# and
# http://www.cap-lore.com/code/TB/
def ppcg_dirtyhelper_MFTB(state):
    # TODO: This is an incorrect implementation. Fix it later!
    return state.solver.BVV(0x200, 64), [ ]

def ppc32g_dirtyhelper_MFSPR_287(state):
    return state.solver.BVV(0x200, 32), [ ]

def amd64g_dirtyhelper_RDTSC(state):
    if o.USE_SYSTEM_TIMES in state.options:
        val = state.solver.BVV(int(time.process_time() * 1000000) + 12345678, 64)
    else:
        val = state.solver.BVS('RDTSC', 64, key=('hardware', 'rdtsc'))
    return val, []


x86g_dirtyhelper_RDTSC = amd64g_dirtyhelper_RDTSC

# For all the CPUID helpers: we've implemented the very nice CPUID functions, but we don't use them.
# we claim to be a much dumber cpu than we can support because otherwise we get bogged down doing
# various tasks in the libc initializers.


# Copied basically directly from the vex source
def amd64g_dirtyhelper_CPUID_baseline(state, _):
    if 'CPUID_SYMBOLIC' in state.options:
        state.regs.rax = claripy.BVS("cpuid_a", 32).zero_extend(32)
        state.regs.rbx = claripy.BVS("cpuid_b", 32).zero_extend(32)
        state.regs.rcx = claripy.BVS("cpuid_c", 32).zero_extend(32)
        state.regs.rdx = claripy.BVS("cpuid_d", 32).zero_extend(32)
        return None, []

    old_eax = state.regs.rax[31:0]
    def SET_ABCD(a, b, c, d, condition=None):
        if condition is None:
            state.registers.store('rax', a, size=8)
            state.registers.store('rbx', b, size=8)
            state.registers.store('rcx', c, size=8)
            state.registers.store('rdx', d, size=8)
        else:
            cond = old_eax == condition
            state.registers.store('rax', a, size=8, condition=cond)
            state.registers.store('rbx', b, size=8, condition=cond)
            state.registers.store('rcx', c, size=8, condition=cond)
            state.registers.store('rdx', d, size=8, condition=cond)

    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000)
    SET_ABCD(0x00000001, 0x72676e41, 0x21444955, 0x50432079, 0)
    SET_ABCD(0x00000f5a, 0x01000800, 0x00000000, 0x078bfbff, 1)
    SET_ABCD(0x80000018, 0x68747541, 0x444d4163, 0x69746e65, 0x80000000)
    SET_ABCD(0x00000f5a, 0x00000505, 0x00000000, 0x21d3fbff, 0x80000001)
    SET_ABCD(0x20444d41, 0x6574704f, 0x206e6f72, 0x296d7428, 0x80000002)
    SET_ABCD(0x6f725020, 0x73736563, 0x3820726f, 0x00003834, 0x80000003)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000004)
    SET_ABCD(0xff08ff08, 0xff20ff20, 0x40020140, 0x40020140, 0x80000005)
    SET_ABCD(0x00000000, 0x42004200, 0x04008140, 0x00000000, 0x80000006)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x0000000f, 0x80000007)
    SET_ABCD(0x00003028, 0x00000000, 0x00000000, 0x00000000, 0x80000008)

    return None, [ ]

amd64g_dirtyhelper_CPUID_avx_and_cx16 = amd64g_dirtyhelper_CPUID_baseline
amd64g_dirtyhelper_CPUID_avx2 = amd64g_dirtyhelper_CPUID_baseline


def amd64g_create_mxcsr(_, sseround):
    return 0x1F80 | ((sseround & 3) << 13)


# see canonical implementation of this in guest_amd64_helpers.c
def amd64g_dirtyhelper_XSAVE_COMPONENT_1_EXCLUDING_XMMREGS(state, _, addr):

    mxcsr = amd64g_create_mxcsr(state, state.regs.sseround)
    mxcsr = mxcsr[15:0]

    state.mem[state.solver.eval(addr) + 12*2].short = mxcsr
    state.mem[state.solver.eval(addr) + 13*2].short = mxcsr >> 16

    state.mem[state.solver.eval(addr) + 14*2].short = 0xffff
    state.mem[state.solver.eval(addr) + 15*2].short = 0x0000

    return None, []

EmNote_NONE = 0
EmWarn_X86_x87exns = 1
EmWarn_X86_x87precision = 2
EmWarn_X86_sseExns = 3
EmWarn_X86_fz = 4
EmWarn_X86_daz = 5
EmWarn_X86_acFlag = 6
EmWarn_PPCexns = 7
EmWarn_PPC64_redir_overflow = 8
EmWarn_PPC64_redir_underflow = 9
EmWarn_S390X_fpext_rounding = 10
EmWarn_S390X_invalid_rounding = 11

def amd64g_check_ldmxcsr(state, mxcsr):

    rmode = state.solver.LShR(mxcsr, 13) & 3

    ew = state.solver.If(
            (mxcsr & 0x1F80) != 0x1F80,
            state.solver.BVV(EmWarn_X86_sseExns, 64),
            state.solver.If(
                mxcsr & (1 << 15) != 0,
                state.solver.BVV(EmWarn_X86_fz, 64),
                state.solver.If(
                    mxcsr & (1 << 6) != 0,
                    state.solver.BVV(EmWarn_X86_daz, 64),
                    state.solver.BVV(EmNote_NONE, 64)
                )
            )
         )

    return (ew << 32) | rmode, ()


# see canonical implementation of this in guest_amd64_helpers.c
def amd64g_dirtyhelper_XRSTOR_COMPONENT_1_EXCLUDING_XMMREGS(state, _, addr):

    w32 = state.solver.BVV(
             (state.mem[state.solver.eval(addr) + 12*2].short.concrete & 0xFFFF) |
             ((state.mem[state.solver.eval(addr) + 13*2].short.concrete & 0xFFFF) << 16)
             , 64)

    w64, _ = amd64g_check_ldmxcsr(state, w32)
    warnXMM = w64 >> 32
    state.regs.sseround = w64 & 0xFFFFFFFF

    return warnXMM, []


def CORRECT_amd64g_dirtyhelper_CPUID_avx_and_cx16(state, _):
    if 'CPUID_SYMBOLIC' in state.options:
        state.regs.rax = claripy.BVS("cpuid_a", 32).zero_extend(32)
        state.regs.rbx = claripy.BVS("cpuid_b", 32).zero_extend(32)
        state.regs.rcx = claripy.BVS("cpuid_c", 32).zero_extend(32)
        state.regs.rdx = claripy.BVS("cpuid_d", 32).zero_extend(32)
        return None, []

    old_eax = state.regs.rax[31:0]
    old_ecx = state.regs.rcx[31:0]

    def SET_ABCD(a, b, c, d, condition=None, condition2=None):
        if condition is None:
            state.registers.store('rax', a, size=8)
            state.registers.store('rbx', b, size=8)
            state.registers.store('rcx', c, size=8)
            state.registers.store('rdx', d, size=8)

        elif condition2 is None:
            cond = old_eax == condition
            state.registers.store('rax', a, size=8, condition=cond)
            state.registers.store('rbx', b, size=8, condition=cond)
            state.registers.store('rcx', c, size=8, condition=cond)
            state.registers.store('rdx', d, size=8, condition=cond)

        else:
            cond = claripy.And(old_eax == condition, old_ecx == condition2)
            state.registers.store('rax', a, size=8, condition=cond)
            state.registers.store('rbx', b, size=8, condition=cond)
            state.registers.store('rcx', c, size=8, condition=cond)
            state.registers.store('rdx', d, size=8, condition=cond)

    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000)
    SET_ABCD(0x0000000d, 0x756e6547, 0x6c65746e, 0x49656e69, 0x00000000)
    SET_ABCD(0x000206a7, 0x00100800, 0x1f9ae3bf, 0xbfebfbff, 0x00000001)
    SET_ABCD(0x76035a01, 0x00f0b0ff, 0x00000000, 0x00ca0000, 0x00000002)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000003)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000004)
    SET_ABCD(0x1c004121, 0x01c0003f, 0x0000003f, 0x00000000, 0x00000004, 0x00000000)
    SET_ABCD(0x1c004122, 0x01c0003f, 0x0000003f, 0x00000000, 0x00000004, 0x00000001)
    SET_ABCD(0x1c004143, 0x01c0003f, 0x000001ff, 0x00000000, 0x00000004, 0x00000002)
    SET_ABCD(0x1c03c163, 0x02c0003f, 0x00001fff, 0x00000006, 0x00000004, 0x00000003)
    SET_ABCD(0x00000040, 0x00000040, 0x00000003, 0x00001120, 0x00000005)
    SET_ABCD(0x00000077, 0x00000002, 0x00000009, 0x00000000, 0x00000006)
    SET_ABCD(0x00000000, 0x00000800, 0x00000000, 0x00000000, 0x00000007)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009)
    SET_ABCD(0x07300803, 0x00000000, 0x00000000, 0x00000603, 0x0000000a)
    SET_ABCD(0x00000000, 0x00000000, old_ecx,    0x00000000, 0x0000000b)
    SET_ABCD(0x00000001, 0x00000001, 0x00000100, 0x00000000, 0x0000000b, 0x00000000)
    SET_ABCD(0x00000004, 0x00000004, 0x00000201, 0x00000000, 0x0000000b, 0x00000001)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000c)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000d)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000, 0x0000000d, 0x00000000)
    SET_ABCD(0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x0000000d, 0x00000001)
    SET_ABCD(0x00000100, 0x00000240, 0x00000000, 0x00000000, 0x0000000d, 0x00000002)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000, 0x0000000e)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000, 0x0000000f)
    SET_ABCD(0x80000008, 0x00000000, 0x00000000, 0x00000000, 0x80000000)
    SET_ABCD(0x00000000, 0x00000000, 0x00000001, 0x28100800, 0x80000001)
    SET_ABCD(0x20202020, 0x20202020, 0x65746e49, 0x2952286c, 0x80000002)
    SET_ABCD(0x726f4320, 0x4d542865, 0x35692029, 0x3033322d, 0x80000003)
    SET_ABCD(0x50432030, 0x20402055, 0x30382e32, 0x007a4847, 0x80000004)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000005)
    SET_ABCD(0x00000000, 0x00000000, 0x01006040, 0x00000000, 0x80000006)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000100, 0x80000007)
    SET_ABCD(0x00003024, 0x00000000, 0x00000000, 0x00000000, 0x80000008)

    return None, [ ]

def amd64g_dirtyhelper_IN(state, portno, sz): #pylint:disable=unused-argument
    return state.solver.Unconstrained('IN', 64, key=('hardware', 'in')), [ ]

def amd64g_dirtyhelper_OUT(state, portno, data, sz): #pylint:disable=unused-argument
    return None, [ ]

def amd64g_dirtyhelper_SxDT(state, addr, op): #pylint:disable=unused-argument
    # SIDT and SGDT are the only instructions dealt with by vex
    # and they both store 80 bit of data
    # See http://amd-dev.wpengine.netdna-cdn.com/wordpress/media/2008/10/24594_APM_v3.pdf
    # page 377
    state.memory.store(addr, state.solver.Unconstrained('SxDT', 80))

    return None, [ ]

def x86g_dirtyhelper_CPUID_sse0(state, _):
    if 'CPUID_SYMBOLIC' in state.options:
        state.regs.eax = claripy.BVS("cpuid_a", 32)
        state.regs.ebx = claripy.BVS("cpuid_b", 32)
        state.regs.ecx = claripy.BVS("cpuid_c", 32)
        state.regs.edx = claripy.BVS("cpuid_d", 32)
        return None, []

    old_eax = state.regs.eax

    def SET_ABCD(a, b, c, d, condition=None, condition2=None):
        if condition is None:
            state.registers.store('eax', a, size=4)
            state.registers.store('ebx', b, size=4)
            state.registers.store('ecx', c, size=4)
            state.registers.store('edx', d, size=4)

        elif condition2 is None:
            cond = old_eax == condition
            state.registers.store('eax', a, size=4, condition=cond)
            state.registers.store('ebx', b, size=4, condition=cond)
            state.registers.store('ecx', c, size=4, condition=cond)
            state.registers.store('edx', d, size=4, condition=cond)

    SET_ABCD(0x543, 0, 0, 0x8001bf)
    SET_ABCD(0x1, 0x72676e41, 0x21444955, 0x50432079, 0)

    return None, [ ]

x86g_dirtyhelper_CPUID_sse2 = x86g_dirtyhelper_CPUID_sse0
x86g_dirtyhelper_CPUID_sse3 = x86g_dirtyhelper_CPUID_sse0

def CORRECT_x86g_dirtyhelper_CPUID_sse2(state, _):
    if 'CPUID_SYMBOLIC' in state.options:
        state.regs.eax = claripy.BVS("cpuid_a", 32)
        state.regs.ebx = claripy.BVS("cpuid_b", 32)
        state.regs.ecx = claripy.BVS("cpuid_c", 32)
        state.regs.edx = claripy.BVS("cpuid_d", 32)
        return None, []

    old_eax = state.regs.eax
    old_ecx = state.regs.ecx

    def SET_ABCD(a, b, c, d, condition=None, condition2=None):
        if condition is None:
            state.registers.store('eax', a, size=4)
            state.registers.store('ebx', b, size=4)
            state.registers.store('ecx', c, size=4)
            state.registers.store('edx', d, size=4)

        elif condition2 is None:
            cond = old_eax == condition
            state.registers.store('eax', a, size=4, condition=cond)
            state.registers.store('ebx', b, size=4, condition=cond)
            state.registers.store('ecx', c, size=4, condition=cond)
            state.registers.store('edx', d, size=4, condition=cond)

        else:
            cond = claripy.And(old_eax == condition, old_ecx == condition2)
            state.registers.store('eax', a, size=4, condition=cond)
            state.registers.store('ebx', b, size=4, condition=cond)
            state.registers.store('ecx', c, size=4, condition=cond)
            state.registers.store('edx', d, size=4, condition=cond)

    SET_ABCD(0x07280202, 0x00000000, 0x00000000, 0x00000000)
    SET_ABCD(0x0000000a, 0x756e6547, 0x6c65746e, 0x49656e69, 0x00000000)
    SET_ABCD(0x000006f6, 0x00020800, 0x0000e3bd, 0xbfebfbff, 0x00000001)
    SET_ABCD(0x05b0b101, 0x005657f0, 0x00000000, 0x2cb43049, 0x00000002)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000003)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000004)
    SET_ABCD(0x04000121, 0x01c0003f, 0x0000003f, 0x00000001, 0x00000004, 0x00000000)
    SET_ABCD(0x04000122, 0x01c0003f, 0x0000003f, 0x00000001, 0x00000004, 0x00000001)
    SET_ABCD(0x04004143, 0x03c0003f, 0x00000fff, 0x00000001, 0x00000004, 0x00000002)
    SET_ABCD(0x00000040, 0x00000040, 0x00000003, 0x00000020, 0x00000005)
    SET_ABCD(0x00000001, 0x00000002, 0x00000001, 0x00000000, 0x00000006)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000007)
    SET_ABCD(0x00000400, 0x00000000, 0x00000000, 0x00000000, 0x00000008)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009)
    SET_ABCD(0x07280202, 0x00000000, 0x00000000, 0x00000000, 0x0000000a)
    SET_ABCD(0x80000008, 0x00000000, 0x00000000, 0x00000000, 0x80000000)
    SET_ABCD(0x00000000, 0x00000000, 0x00000001, 0x20100000, 0x80000001)
    SET_ABCD(0x65746e49, 0x2952286c, 0x726f4320, 0x4d542865, 0x80000002)
    SET_ABCD(0x43203229, 0x20205550, 0x20202020, 0x20202020, 0x80000003)
    SET_ABCD(0x30303636, 0x20402020, 0x30342e32, 0x007a4847, 0x80000004)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000005)
    SET_ABCD(0x00000000, 0x00000000, 0x10008040, 0x00000000, 0x80000006)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000007)
    SET_ABCD(0x00003024, 0x00000000, 0x00000000, 0x00000000, 0x80000008)

    return None, [ ]

def x86g_dirtyhelper_IN(state, portno, sz): #pylint:disable=unused-argument
    return state.solver.Unconstrained('IN', 32, key=('hardware', 'in')), [ ]

def x86g_dirtyhelper_OUT(state, portno, data, sz): #pylint:disable=unused-argument
    return None, [ ]

def x86g_dirtyhelper_SxDT(state, addr, op):
    # SIDT and SGDT are the only instructions dealt with by vex
    # and they both store 48 bit data
    if not op.concrete:
        # resolved failed
        return None, [ ]
    elif op._model_concrete.value == 0:
        state.memory.store(addr, state.solver.Unconstrained('SIDT', 48))
    elif op._model_concrete.value == 1:
        state.memory.store(addr, state.regs.gdt)

    return None, [ ]

def x86g_dirtyhelper_LGDT_LIDT(state, addr, op):
    if not op.concrete:
        # resolved failed
        return None, [ ]

    limit = state.memory.load(addr, 2, endness='Iend_LE')
    base = state.memory.load(addr + 2, 4, endness='Iend_LE')

    if op._model_concrete.value == 2:
        state.regs.gdt = state.solver.Concat(base, limit).zero_extend(16)
    elif op._model_concrete.value == 3:
        # LIDT is a nop
        pass

    return None, [ ]

def x86g_dirtyhelper_FINIT(state, gsptr): #pylint:disable=unused-argument
    state.regs.fpu_tags = 0
    state.regs.fpround = 0
    state.regs.fc3210 = 0x0300
    state.regs.ftop = 0
    return None, [ ]

amd64g_dirtyhelper_FINIT = x86g_dirtyhelper_FINIT

def x86g_dirtyhelper_write_cr0(state, value):
    # make a deep copy of the arch before modifying it so we don't accidentally modify it for all other states
    state.arch = state.arch.copy()
    state.arch.vex_archinfo['x86_cr0'] = state.solver.eval_one(value)
    return None, [ ]

def x86g_dirtyhelper_loadF80le(state, addr):
    tbyte = state.memory.load(addr, size=10, endness='Iend_LE')
    sign = tbyte[79]
    exponent = tbyte[78:64]
    mantissa = tbyte[62:0]

    normalized_exponent = exponent[10:0] - 16383 + 1023
    zero_exponent = state.solver.BVV(0, 11)
    inf_exponent = state.solver.BVV(-1, 11)
    final_exponent = claripy.If(exponent == 0, zero_exponent, claripy.If(exponent == -1, inf_exponent, normalized_exponent))

    normalized_mantissa = tbyte[62:11]
    zero_mantissa = claripy.BVV(0, 52)
    inf_mantissa = claripy.BVV(-1, 52)
    final_mantissa = claripy.If(exponent == 0, zero_mantissa, claripy.If(exponent == -1, claripy.If(mantissa == 0, zero_mantissa, inf_mantissa), normalized_mantissa))

    qword = claripy.Concat(sign, final_exponent, final_mantissa)
    assert len(qword) == 64
    return qword, []

def x86g_dirtyhelper_storeF80le(state, addr, qword):
    sign = qword[63]
    exponent = qword[62:52]
    mantissa = qword[51:0]

    normalized_exponent = exponent.zero_extend(4) - 1023 + 16383
    zero_exponent = state.solver.BVV(0, 15)
    inf_exponent = state.solver.BVV(-1, 15)
    final_exponent = claripy.If(exponent == 0, zero_exponent, claripy.If(exponent == -1, inf_exponent, normalized_exponent))

    normalized_mantissa = claripy.Concat(claripy.BVV(1, 1), mantissa, claripy.BVV(0, 11))
    zero_mantissa = claripy.BVV(0, 64)
    inf_mantissa = claripy.BVV(-1, 64)
    final_mantissa = claripy.If(exponent == 0, zero_mantissa, claripy.If(exponent == -1, claripy.If(mantissa == 0, zero_mantissa, inf_mantissa), normalized_mantissa))

    tbyte = claripy.Concat(sign, final_exponent, final_mantissa)
    assert len(tbyte) == 80
    state.memory.store(addr, tbyte, endness='Iend_LE')
    return None, []
