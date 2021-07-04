###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_z180_LE_16_default(ArchPcode):
    name = 'z180:LE:16:default'
    pcode_arch = 'z180:LE:16:default'
    description = 'Zilog Z180'
    bits = 16
    ip_offset = 0x42
    sp_offset = 0x44
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('af', 2, 0x0),
        Register('f', 1, 0x0),
        Register('a', 1, 0x1),
        Register('bc', 2, 0x2),
        Register('c', 1, 0x2),
        Register('b', 1, 0x3),
        Register('de', 2, 0x4),
        Register('e', 1, 0x4),
        Register('d', 1, 0x5),
        Register('hl', 2, 0x6),
        Register('l', 1, 0x6),
        Register('h', 1, 0x7),
        Register('i', 1, 0x8),
        Register('r', 1, 0x9),
        Register('af_', 2, 0x20),
        Register('f_', 1, 0x20),
        Register('a_', 1, 0x21),
        Register('bc_', 2, 0x22),
        Register('c_', 1, 0x22),
        Register('b_', 1, 0x23),
        Register('de_', 2, 0x24),
        Register('e_', 1, 0x24),
        Register('d_', 1, 0x25),
        Register('hl_', 2, 0x26),
        Register('l_', 1, 0x26),
        Register('h_', 1, 0x27),
        Register('pc', 2, 0x42, alias_names=('ip',)),
        Register('sp', 2, 0x44),
        Register('ix', 2, 0x46),
        Register('iy', 2, 0x48),
        Register('rcbar', 1, 0x50),
        Register('rcbr', 1, 0x51),
        Register('rbbr', 1, 0x52),
        Register('decompile_mode', 1, 0x60),
        Register('contextreg', 4, 0xf0)
    ]

register_arch(['z180:le:16:default'], 16, Endness.LE, ArchPcode_z180_LE_16_default)
