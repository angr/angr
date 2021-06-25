###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_PIC_16_LE_16_PIC_16(ArchPcode):
    name = 'PIC-16:LE:16:PIC-16'
    pcode_arch = 'PIC-16:LE:16:PIC-16'
    description = 'PIC-16(C,CR)XXX'
    bits = 16
    ip_offset = 0x0
    sp_offset = 0x2
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('indf', 1, 0x0),
        Register('tmr0', 1, 0x1),
        Register('pcl', 1, 0x2),
        Register('status', 1, 0x3),
        Register('fsr', 1, 0x4),
        Register('porta', 1, 0x5),
        Register('portb', 1, 0x6),
        Register('portc', 1, 0x7),
        Register('portd', 1, 0x8),
        Register('porte', 1, 0x9),
        Register('pclath', 1, 0xa),
        Register('intcon', 1, 0xb),
        Register('pir1', 1, 0xc),
        Register('pir2', 1, 0xd),
        Register('tmr1l', 1, 0xe),
        Register('tmr1h', 1, 0xf),
        Register('pc', 2, 0x0, alias_names=('ip',)),
        Register('stkptr', 1, 0x2),
        Register('w', 1, 0x3),
        Register('skipnext', 1, 0x4),
        Register('irp', 1, 0x7),
        Register('rp', 1, 0x8),
        Register('contextreg', 4, 0x100)
    ]

register_arch(['pic-16:le:16:pic-16'], 16, Endness.LE, ArchPcode_PIC_16_LE_16_PIC_16)
