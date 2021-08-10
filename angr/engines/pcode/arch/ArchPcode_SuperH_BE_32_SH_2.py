###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_SuperH_BE_32_SH_2(ArchPcode):
    name = 'SuperH:BE:32:SH-2'
    pcode_arch = 'SuperH:BE:32:SH-2'
    description = 'SuperH SH-2 processor 32-bit big-endian'
    bits = 32
    ip_offset = 0x118
    sp_offset = 0x3c
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('r0', 4, 0x0),
        Register('r1', 4, 0x4),
        Register('r2', 4, 0x8),
        Register('r3', 4, 0xc),
        Register('r4', 4, 0x10),
        Register('r5', 4, 0x14),
        Register('r6', 4, 0x18),
        Register('r7', 4, 0x1c),
        Register('r8', 4, 0x20),
        Register('r9', 4, 0x24),
        Register('r10', 4, 0x28),
        Register('r11', 4, 0x2c),
        Register('r12', 4, 0x30),
        Register('r13', 4, 0x34),
        Register('r14', 4, 0x38),
        Register('r15', 4, 0x3c),
        Register('sr', 4, 0x100),
        Register('gbr', 4, 0x104),
        Register('vbr', 4, 0x108),
        Register('mach', 4, 0x10c),
        Register('macl', 4, 0x110),
        Register('pr', 4, 0x114),
        Register('pc', 4, 0x118, alias_names=('ip',))
    ]

register_arch(['superh:be:32:sh-2'], 32, Endness.BE, ArchPcode_SuperH_BE_32_SH_2)
