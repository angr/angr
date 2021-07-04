###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_HC05_BE_16_M68HC05TB(ArchPcode):
    name = 'HC05:BE:16:M68HC05TB'
    pcode_arch = 'HC05:BE:16:M68HC05TB'
    description = 'HC05 (6805) Microcontroller Family - M68HC05TB'
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

register_arch(['hc05:be:16:m68hc05tb'], 16, Endness.BE, ArchPcode_HC05_BE_16_M68HC05TB)
