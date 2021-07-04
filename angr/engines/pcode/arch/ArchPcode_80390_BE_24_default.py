###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_80390_BE_24_default(ArchPcode):
    name = '80390:BE:24:default'
    pcode_arch = '80390:BE:24:default'
    description = '80390 in flat mode'
    bits = 16
    ip_offset = 0x44
    sp_offset = 0x40
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('r0r1r2r3', 4, 0x0),
        Register('r0r1', 2, 0x0),
        Register('r0', 1, 0x0),
        Register('r1r2r3', 3, 0x1),
        Register('r2r1', 2, 0x1),
        Register('r1', 1, 0x1),
        Register('r2r3', 2, 0x2),
        Register('r2', 1, 0x2),
        Register('r3', 1, 0x3),
        Register('r4r5r6r7', 4, 0x4),
        Register('r4r5', 2, 0x4),
        Register('r4', 1, 0x4),
        Register('r5r6r7', 3, 0x5),
        Register('r5', 1, 0x5),
        Register('r6r7', 2, 0x6),
        Register('r6', 1, 0x6),
        Register('r7', 1, 0x7),
        Register('ab', 2, 0xa),
        Register('b', 1, 0xa),
        Register('acc', 1, 0xb),
        Register('sp', 1, 0x40),
        Register('pc', 3, 0x44, alias_names=('ip',)),
        Register('psw', 1, 0x48),
        Register('jumptableguard1', 1, 0x70),
        Register('jumptableguard2', 1, 0x71),
        Register('dptr', 3, 0x82),
        Register('dpx', 1, 0x82),
        Register('dph', 1, 0x83),
        Register('dpl', 1, 0x84)
    ]

register_arch(['80390:be:24:default'], 16, Endness.BE, ArchPcode_80390_BE_24_default)
