###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_6805_BE_16_default(ArchPcode):
    name = '6805:BE:16:default'
    pcode_arch = '6805:BE:16:default'
    description = '6805 Microcontroller Family'
    bits = 16
    ip_offset = 0x20
    sp_offset = 0x22
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('swi_vector', 2, 0x3ffc),
        Register('a', 1, 0x0),
        Register('x', 1, 0x1),
        Register('pc', 2, 0x20, alias_names=('ip',)),
        Register('sp', 2, 0x22),
        Register('h', 1, 0x30),
        Register('i', 1, 0x31),
        Register('n', 1, 0x32),
        Register('z', 1, 0x33),
        Register('c', 1, 0x34)
    ]

register_arch(['6805:be:16:default'], 16, Endness.BE, ArchPcode_6805_BE_16_default)
