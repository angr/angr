###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_TI_MSP430X_LE_32_default(ArchPcode):
    name = 'TI_MSP430X:LE:32:default'
    pcode_arch = 'TI_MSP430X:LE:32:default'
    description = 'TI MSP430X 20-Bit MicroController'
    bits = 32
    ip_offset = 0x0
    sp_offset = 0x4
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('pc', 4, 0x0, alias_names=('ip',)),
        Register('pc_16', 2, 0x0),
        Register('pc_lo', 1, 0x0),
        Register('pc_hi', 1, 0x1),
        Register('sp', 4, 0x4),
        Register('sp_16', 2, 0x4),
        Register('sp_lo', 1, 0x4),
        Register('sp_hi', 1, 0x5),
        Register('sr', 4, 0x8),
        Register('sr_16', 2, 0x8),
        Register('sr_lo', 1, 0x8),
        Register('sr_hi', 1, 0x9),
        Register('r3', 4, 0xc),
        Register('r3_16', 2, 0xc),
        Register('r3_lo', 1, 0xc),
        Register('r3_hi', 1, 0xd),
        Register('r4', 4, 0x10),
        Register('r4_16', 2, 0x10),
        Register('r4_lo', 1, 0x10),
        Register('r4_hi', 1, 0x11),
        Register('r5', 4, 0x14),
        Register('r5_16', 2, 0x14),
        Register('r5_lo', 1, 0x14),
        Register('r5_hi', 1, 0x15),
        Register('r6', 4, 0x18),
        Register('r6_16', 2, 0x18),
        Register('r6_lo', 1, 0x18),
        Register('r6_hi', 1, 0x19),
        Register('r7', 4, 0x1c),
        Register('r7_16', 2, 0x1c),
        Register('r7_lo', 1, 0x1c),
        Register('r7_hi', 1, 0x1d),
        Register('r8', 4, 0x20),
        Register('r8_16', 2, 0x20),
        Register('r8_lo', 1, 0x20),
        Register('r8_hi', 1, 0x21),
        Register('r9', 4, 0x24),
        Register('r9_16', 2, 0x24),
        Register('r9_lo', 1, 0x24),
        Register('r9_hi', 1, 0x25),
        Register('r10', 4, 0x28),
        Register('r10_16', 2, 0x28),
        Register('r10_lo', 1, 0x28),
        Register('r10_hi', 1, 0x29),
        Register('r11', 4, 0x2c),
        Register('r11_16', 2, 0x2c),
        Register('r11_lo', 1, 0x2c),
        Register('r11_hi', 1, 0x2d),
        Register('r12', 4, 0x30),
        Register('r12_16', 2, 0x30),
        Register('r12_lo', 1, 0x30),
        Register('r12_hi', 1, 0x31),
        Register('r13', 4, 0x34),
        Register('r13_16', 2, 0x34),
        Register('r13_lo', 1, 0x34),
        Register('r13_hi', 1, 0x35),
        Register('r14', 4, 0x38),
        Register('r14_16', 2, 0x38),
        Register('r14_lo', 1, 0x38),
        Register('r14_hi', 1, 0x39),
        Register('r15', 4, 0x3c),
        Register('r15_16', 2, 0x3c),
        Register('r15_lo', 1, 0x3c),
        Register('r15_hi', 1, 0x3d),
        Register('none', 4, 0x40),
        Register('none_lo', 1, 0x40),
        Register('none_hi', 1, 0x41),
        Register('contextreg', 4, 0x1000),
        Register('cnt', 1, 0x2000)
    ]

register_arch(['ti_msp430x:le:32:default'], 32, Endness.LE, ArchPcode_TI_MSP430X_LE_32_default)
