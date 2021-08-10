###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_8051_BE_24_mx51(ArchPcode):
    name = '8051:BE:24:mx51'
    pcode_arch = '8051:BE:24:mx51'
    description = 'NXP/Phillips MX51'
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
        Register('sp', 3, 0x40),
        Register('pc', 3, 0x44, alias_names=('ip',)),
        Register('psw', 1, 0x48),
        Register('dptr2', 2, 0x4a),
        Register('jumptableguard1', 1, 0x70),
        Register('jumptableguard2', 1, 0x71),
        Register('dptr', 2, 0x82),
        Register('dph', 1, 0x82),
        Register('dpl', 1, 0x83),
        Register('auxr1', 1, 0xa2),
        Register('eptr', 3, 0xc0),
        Register('eph', 1, 0xc0),
        Register('epm', 1, 0xc1),
        Register('epl', 1, 0xc2)
    ]

register_arch(['8051:be:24:mx51'], 16, Endness.BE, ArchPcode_8051_BE_24_mx51)
