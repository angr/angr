###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_HCS08_BE_16_MC9S08GB60(ArchPcode):
    name = 'HCS08:BE:16:MC9S08GB60'
    pcode_arch = 'HCS08:BE:16:MC9S08GB60'
    description = 'HCS08 Microcontroller Family - MC9S08GB60'
    bits = 16
    ip_offset = 0x20
    sp_offset = 0x22
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('a', 1, 0x0),
        Register('hix', 2, 0x10),
        Register('hi', 1, 0x10),
        Register('x', 1, 0x11),
        Register('pc', 2, 0x20, alias_names=('ip',)),
        Register('pch', 1, 0x20),
        Register('pcl', 1, 0x21),
        Register('sp', 2, 0x22),
        Register('sph', 1, 0x22),
        Register('spl', 1, 0x23),
        Register('ccr', 1, 0x30)
    ]

register_arch(['hcs08:be:16:mc9s08gb60'], 16, Endness.BE, ArchPcode_HCS08_BE_16_MC9S08GB60)
