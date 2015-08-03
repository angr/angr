import logging
l = logging.getLogger("simuvex.vex.dirty")

import claripy

#####################
# Dirty calls
#####################

# Reference:
# http://www-inteng.fnal.gov/Integrated_Eng/GoodwinDocs/pdf/Sys%20docs/PowerPC/PowerPC%20Elapsed%20Time.pdf
# and
# http://www.cap-lore.com/code/TB/
def ppcg_dirtyhelper_MFTB(state):
    # TODO: This is an incorrect implementation. Fix it later!
    return state.BVV(0x200, 64), [ ]

def ppc32g_dirtyhelper_MFSPR_287(state):
    return state.BVV(0x200, 32), [ ]

def amd64g_dirtyhelper_RDTSC(state):
    return state.se.Unconstrained('RDTSC', 64), [ ]

x86g_dirtyhelper_RDTSC = amd64g_dirtyhelper_RDTSC

# For all the CPUID helpers: we've implemented the very nice CPUID functions, but we don't use them.
# we claim to be a much dumber cpu than we can support because otherwise we get bogged down doing
# various tasks in the libc initializers.

# Copied basically directly from the vex source
def amd64g_dirtyhelper_CPUID_baseline(state, _):
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
    SET_ABCD(0x00000001, 0x68747541, 0x444d4163, 0x69746e65, 0)
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

def CORRECT_amd64g_dirtyhelper_CPUID_avx_and_cx16(state, _):
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

def amd64g_dirtyhelper_IN(state, portno, sz):
    return state.se.Unconstrained('IN', 64), [ ]

def amd64g_dirtyhelper_OUT(state, portno, data, sz):
    return None, [ ]

def amd64g_dirtyhelper_SxDT(state, addr, op):
    # SIDT and SGDT are the only instructions dealt with by vex
    # and they both store 80 bit of data
    # See http://amd-dev.wpengine.netdna-cdn.com/wordpress/media/2008/10/24594_APM_v3.pdf 
    # page 377
    state.memory.store(addr, state.se.Unconstrained('SxDT', 80))

    return None, [ ]

def x86g_dirtyhelper_CPUID_sse0(state, _):
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
    SET_ABCD(0x1, 0x756e6547, 0x6c65746e, 0x49656e69, 0)

    return None, [ ]

x86g_dirtyhelper_CPUID_sse2 = x86g_dirtyhelper_CPUID_sse0
x86g_dirtyhelper_CPUID_sse3 = x86g_dirtyhelper_CPUID_sse0

def CORRECT_x86g_dirtyhelper_CPUID_sse2(state, _):
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

def x86g_dirtyhelper_IN(state, portno, sz):
    return state.se.Unconstrained('IN', 32), [ ]

def x86g_dirtyhelper_OUT(state, portno, data, sz):
    return None, [ ]

def x86g_dirtyhelper_SxDT(state, addr, op):
    # SIDT and SGDT are the only instructions dealt with by vex
    # and they both store 48 bit data
    r = op.resolved()
    if r is op:
        # resolved failed
        return None, [ ]
    elif r == 0:
        state.memory.store(addr, state.se.Unconstrained('SIDT', 48))
    elif r == 1:
        state.memory.store(addr, state.regs.gdt)

    return None, [ ]

def x86g_dirtyhelper_LGDT_LIDT(state, addr, op):
    r = op.resolved()
    if r is op:
        # resolved failed
        return None, [ ]

    limit = state.memory.load(addr, 2, endness='Iend_LE')
    base = state.memory.load(addr + 2, 4, endness='Iend_LE')

    if r == 2:
        state.regs.gdt = state.se.Concat(base, limit).zero_extend(16)
    elif r == 3:
        # LIDT is a nop
        pass

    return None, [ ]
