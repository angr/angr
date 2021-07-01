###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_PIC_12_LE_16_PIC_12C5xx(ArchPcode):
    name = 'PIC-12:LE:16:PIC-12C5xx'
    pcode_arch = 'PIC-12:LE:16:PIC-12C5xx'
    description = 'PIC-12C5xx'
    bits = 16
    ip_offset = 0x0
    sp_offset = 0x2
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('indf', 1, 0x0),
        Register('tmr0', 1, 0x1),
        Register('pcl.0', 1, 0x2),
        Register('status.0', 1, 0x3),
        Register('fsr.0', 1, 0x4),
        Register('osccal', 1, 0x5),
        Register('gpio', 1, 0x6),
        Register('pc', 2, 0x0, alias_names=('ip',)),
        Register('stkptr', 1, 0x2),
        Register('w', 1, 0x3),
        Register('pcl', 1, 0x4),
        Register('fsr', 1, 0x5),
        Register('status', 1, 0x6),
        Register('pa', 1, 0x7),
        Register('z', 1, 0x8),
        Register('dc', 1, 0x9),
        Register('c', 1, 0xa),
        Register('option', 1, 0xb),
        Register('tris', 1, 0x20)
    ]

register_arch(['pic-12:le:16:pic-12c5xx'], 16, Endness.LE, ArchPcode_PIC_12_LE_16_PIC_12C5xx)
