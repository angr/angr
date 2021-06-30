###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_6809_BE_16_default(ArchPcode):
    name = '6809:BE:16:default'
    pcode_arch = '6809:BE:16:default'
    description = '6809 Microprocessor'
    bits = 16
    ip_offset = 0x10
    sp_offset = 0x18
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('d', 2, 0x0),
        Register('a', 1, 0x0),
        Register('b', 1, 0x1),
        Register('cc', 1, 0x8),
        Register('dp', 1, 0x9),
        Register('pc', 2, 0x10, alias_names=('ip',)),
        Register('x', 2, 0x12),
        Register('y', 2, 0x14),
        Register('u', 2, 0x16),
        Register('s', 2, 0x18),
        Register('exg16_r0', 2, 0x20),
        Register('exg8h_r0', 1, 0x20),
        Register('exg8l_r0', 1, 0x21),
        Register('exg16_r1', 2, 0x22),
        Register('exg8h_r1', 1, 0x22),
        Register('exg8l_r1', 1, 0x23)
    ]

register_arch(['6809:be:16:default'], 16, Endness.BE, ArchPcode_6809_BE_16_default)
