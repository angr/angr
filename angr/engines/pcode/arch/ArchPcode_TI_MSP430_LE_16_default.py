###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_TI_MSP430_LE_16_default(ArchPcode):
    name = 'TI_MSP430:LE:16:default'
    pcode_arch = 'TI_MSP430:LE:16:default'
    description = 'TI MSP430 16-Bit MicroController'
    bits = 16
    ip_offset = 0x0
    sp_offset = 0x2
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('pc', 2, 0x0, alias_names=('ip',)),
        Register('pc_lo', 1, 0x0),
        Register('pc_hi', 1, 0x1),
        Register('sp', 2, 0x2),
        Register('sp_lo', 1, 0x2),
        Register('sp_hi', 1, 0x3),
        Register('sr', 2, 0x4),
        Register('sr_lo', 1, 0x4),
        Register('sr_hi', 1, 0x5),
        Register('r3', 2, 0x6),
        Register('r3_lo', 1, 0x6),
        Register('r3_hi', 1, 0x7),
        Register('r4', 2, 0x8),
        Register('r4_lo', 1, 0x8),
        Register('r4_hi', 1, 0x9),
        Register('r5', 2, 0xa),
        Register('r5_lo', 1, 0xa),
        Register('r5_hi', 1, 0xb),
        Register('r6', 2, 0xc),
        Register('r6_lo', 1, 0xc),
        Register('r6_hi', 1, 0xd),
        Register('r7', 2, 0xe),
        Register('r7_lo', 1, 0xe),
        Register('r7_hi', 1, 0xf),
        Register('r8', 2, 0x10),
        Register('r8_lo', 1, 0x10),
        Register('r8_hi', 1, 0x11),
        Register('r9', 2, 0x12),
        Register('r9_lo', 1, 0x12),
        Register('r9_hi', 1, 0x13),
        Register('r10', 2, 0x14),
        Register('r10_lo', 1, 0x14),
        Register('r10_hi', 1, 0x15),
        Register('r11', 2, 0x16),
        Register('r11_lo', 1, 0x16),
        Register('r11_hi', 1, 0x17),
        Register('r12', 2, 0x18),
        Register('r12_lo', 1, 0x18),
        Register('r12_hi', 1, 0x19),
        Register('r13', 2, 0x1a),
        Register('r13_lo', 1, 0x1a),
        Register('r13_hi', 1, 0x1b),
        Register('r14', 2, 0x1c),
        Register('r14_lo', 1, 0x1c),
        Register('r14_hi', 1, 0x1d),
        Register('r15', 2, 0x1e),
        Register('r15_lo', 1, 0x1e),
        Register('r15_hi', 1, 0x1f),
        Register('none', 2, 0x20),
        Register('none_lo', 1, 0x20),
        Register('none_hi', 1, 0x21),
        Register('contextreg', 4, 0x1000),
        Register('cnt', 1, 0x2000)
    ]

register_arch(['ti_msp430:le:16:default'], 16, Endness.LE, ArchPcode_TI_MSP430_LE_16_default)
