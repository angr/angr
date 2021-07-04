###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_M8C_BE_16_default(ArchPcode):
    name = 'M8C:BE:16:default'
    pcode_arch = 'M8C:BE:16:default'
    description = 'Cypress M8C Microcontroller Family'
    bits = 16
    ip_offset = 0x10
    sp_offset = 0x2
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('a', 1, 0x0),
        Register('x', 1, 0x1),
        Register('sp', 1, 0x2),
        Register('f', 1, 0x3),
        Register('pc', 2, 0x10, alias_names=('ip',)),
        Register('contextreg', 4, 0x30)
    ]

register_arch(['m8c:be:16:default'], 16, Endness.BE, ArchPcode_M8C_BE_16_default)
