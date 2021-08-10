###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_8085_LE_16_default(ArchPcode):
    name = '8085:LE:16:default'
    pcode_arch = '8085:LE:16:default'
    description = 'Intel 8085'
    bits = 16
    ip_offset = 0x20
    sp_offset = 0x22
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
        Register('af_', 2, 0x10),
        Register('a_', 1, 0x10),
        Register('f_', 1, 0x11),
        Register('bc_', 2, 0x12),
        Register('b_', 1, 0x12),
        Register('c_', 1, 0x13),
        Register('de_', 2, 0x14),
        Register('d_', 1, 0x14),
        Register('e_', 1, 0x15),
        Register('hl_', 2, 0x16),
        Register('h_', 1, 0x16),
        Register('l_', 1, 0x17),
        Register('pc', 2, 0x20, alias_names=('ip',)),
        Register('sp', 2, 0x22),
        Register('s_flag', 1, 0x30),
        Register('z_flag', 1, 0x31),
        Register('ac_flag', 1, 0x32),
        Register('p_flag', 1, 0x33),
        Register('cy_flag', 1, 0x34)
    ]

register_arch(['8085:le:16:default'], 16, Endness.LE, ArchPcode_8085_LE_16_default)
