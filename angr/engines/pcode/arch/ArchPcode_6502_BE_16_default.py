###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_6502_BE_16_default(ArchPcode):
    name = '6502:BE:16:default'
    pcode_arch = '6502:BE:16:default'
    description = '6502 Microcontroller Family'
    bits = 16
    ip_offset = 0x20
    sp_offset = 0x22
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('a', 1, 0x0),
        Register('x', 1, 0x1),
        Register('y', 1, 0x2),
        Register('p', 1, 0x3),
        Register('pc', 2, 0x20, alias_names=('ip',)),
        Register('pcl', 1, 0x20),
        Register('pch', 1, 0x21),
        Register('sp', 2, 0x22),
        Register('s', 1, 0x22),
        Register('sh', 1, 0x23),
        Register('n', 1, 0x30),
        Register('v', 1, 0x31),
        Register('b', 1, 0x32),
        Register('d', 1, 0x33),
        Register('i', 1, 0x34),
        Register('z', 1, 0x35),
        Register('c', 1, 0x36)
    ]

register_arch(['6502:be:16:default'], 16, Endness.LE, ArchPcode_6502_BE_16_default)
