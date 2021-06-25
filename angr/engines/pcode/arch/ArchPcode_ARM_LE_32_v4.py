###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_ARM_LE_32_v4(ArchPcode):
    name = 'ARM:LE:32:v4'
    pcode_arch = 'ARM:LE:32:v4'
    description = 'Generic ARM v4 little endian'
    bits = 32
    ip_offset = 0x5c
    sp_offset = 0x54
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('contextreg', 8, 0x0),
        Register('r0', 4, 0x20),
        Register('r1', 4, 0x24),
        Register('r2', 4, 0x28),
        Register('r3', 4, 0x2c),
        Register('r4', 4, 0x30),
        Register('r5', 4, 0x34),
        Register('r6', 4, 0x38),
        Register('r7', 4, 0x3c),
        Register('r8', 4, 0x40),
        Register('r9', 4, 0x44),
        Register('r10', 4, 0x48),
        Register('r11', 4, 0x4c),
        Register('r12', 4, 0x50),
        Register('sp', 4, 0x54),
        Register('lr', 4, 0x58),
        Register('pc', 4, 0x5c, alias_names=('ip',)),
        Register('ng', 1, 0x60),
        Register('zr', 1, 0x61),
        Register('cy', 1, 0x62),
        Register('ov', 1, 0x63),
        Register('tmpng', 1, 0x64),
        Register('tmpzr', 1, 0x65),
        Register('tmpcy', 1, 0x66),
        Register('tmpov', 1, 0x67),
        Register('shift_carry', 1, 0x68),
        Register('tb', 1, 0x69),
        Register('q', 1, 0x6a),
        Register('ge1', 1, 0x6b),
        Register('ge2', 1, 0x6c),
        Register('ge3', 1, 0x6d),
        Register('ge4', 1, 0x6e),
        Register('cpsr', 4, 0x70),
        Register('spsr', 4, 0x74),
        Register('mult_addr', 4, 0x80),
        Register('r14_svc', 4, 0x84),
        Register('r13_svc', 4, 0x88),
        Register('spsr_svc', 4, 0x8c),
        Register('mult_dat16', 16, 0x90),
        Register('mult_dat8', 8, 0x90),
        Register('fpsr', 4, 0xa0),
        Register('isamodeswitch', 1, 0xb0),
        Register('fp0', 10, 0x100),
        Register('fp1', 10, 0x10a),
        Register('fp2', 10, 0x114),
        Register('fp3', 10, 0x11e),
        Register('fp4', 10, 0x128),
        Register('fp5', 10, 0x132),
        Register('fp6', 10, 0x13c),
        Register('fp7', 10, 0x146),
        Register('cr0', 4, 0x200),
        Register('cr1', 4, 0x204),
        Register('cr2', 4, 0x208),
        Register('cr3', 4, 0x20c),
        Register('cr4', 4, 0x210),
        Register('cr5', 4, 0x214),
        Register('cr6', 4, 0x218),
        Register('cr7', 4, 0x21c),
        Register('cr8', 4, 0x220),
        Register('cr9', 4, 0x224),
        Register('cr10', 4, 0x228),
        Register('cr11', 4, 0x22c),
        Register('cr12', 4, 0x230),
        Register('cr13', 4, 0x234),
        Register('cr14', 4, 0x238),
        Register('cr15', 4, 0x23c)
    ]

register_arch(['arm:le:32:v4'], 32, Endness.LE, ArchPcode_ARM_LE_32_v4)
