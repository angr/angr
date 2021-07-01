###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_8048_LE_16_default(ArchPcode):
    name = '8048:LE:16:default'
    pcode_arch = '8048:LE:16:default'
    description = '8048 Microcontroller Family'
    bits = 16
    ip_offset = 0x20
    sp_offset = 0x1
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('a', 1, 0x0),
        Register('sp', 1, 0x1),
        Register('r0', 1, 0x10),
        Register('r1', 1, 0x11),
        Register('r2', 1, 0x12),
        Register('r3', 1, 0x13),
        Register('r4', 1, 0x14),
        Register('r5', 1, 0x15),
        Register('r6', 1, 0x16),
        Register('r7', 1, 0x17),
        Register('pc', 2, 0x20, alias_names=('ip',)),
        Register('c', 1, 0x30),
        Register('ac', 1, 0x31),
        Register('f0', 1, 0x32),
        Register('f1', 1, 0x33),
        Register('bs', 1, 0x34),
        Register('dfb', 1, 0x35)
    ]

register_arch(['8048:le:16:default'], 16, Endness.LE, ArchPcode_8048_LE_16_default)
