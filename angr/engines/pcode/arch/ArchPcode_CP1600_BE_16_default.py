###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_CP1600_BE_16_default(ArchPcode):
    name = 'CP1600:BE:16:default'
    pcode_arch = 'CP1600:BE:16:default'
    description = 'General Instruments CP1600'
    bits = 16
    ip_offset = 0xe
    sp_offset = 0xc
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('r0', 2, 0x0),
        Register('r1', 2, 0x2),
        Register('r2', 2, 0x4),
        Register('r3', 2, 0x6),
        Register('r4', 2, 0x8),
        Register('r5', 2, 0xa),
        Register('r6', 2, 0xc),
        Register('r7', 2, 0xe, alias_names=('pc', 'ip')),
        Register('i', 1, 0x10),
        Register('c', 1, 0x11),
        Register('o', 1, 0x12),
        Register('z', 1, 0x13),
        Register('s', 1, 0x14),
        Register('contextreg', 4, 0x20)
    ]

register_arch(['cp1600:be:16:default'], 16, Endness.BE, ArchPcode_CP1600_BE_16_default)
