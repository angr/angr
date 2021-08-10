###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_SuperH_BE_32_SH_2A(ArchPcode):
    name = 'SuperH:BE:32:SH-2A'
    pcode_arch = 'SuperH:BE:32:SH-2A'
    description = 'SuperH SH-2A processor 32-bit big-endian'
    bits = 32
    ip_offset = 0x118
    sp_offset = 0x3c
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('r0', 4, 0x0),
        Register('r1', 4, 0x4),
        Register('r2', 4, 0x8),
        Register('r3', 4, 0xc),
        Register('r4', 4, 0x10),
        Register('r5', 4, 0x14),
        Register('r6', 4, 0x18),
        Register('r7', 4, 0x1c),
        Register('r8', 4, 0x20),
        Register('r9', 4, 0x24),
        Register('r10', 4, 0x28),
        Register('r11', 4, 0x2c),
        Register('r12', 4, 0x30),
        Register('r13', 4, 0x34),
        Register('r14', 4, 0x38),
        Register('r15', 4, 0x3c),
        Register('sr', 4, 0x100),
        Register('gbr', 4, 0x104),
        Register('vbr', 4, 0x108),
        Register('mach', 4, 0x10c),
        Register('macl', 4, 0x110),
        Register('pr', 4, 0x114),
        Register('pc', 4, 0x118, alias_names=('ip',)),
        Register('tbr', 4, 0x180),
        Register('dr0', 8, 0x200),
        Register('fr0', 4, 0x200),
        Register('fr1', 4, 0x204),
        Register('dr2', 8, 0x208),
        Register('fr2', 4, 0x208),
        Register('fr3', 4, 0x20c),
        Register('dr4', 8, 0x210),
        Register('fr4', 4, 0x210),
        Register('fr5', 4, 0x214),
        Register('dr6', 8, 0x218),
        Register('fr6', 4, 0x218),
        Register('fr7', 4, 0x21c),
        Register('dr8', 8, 0x220),
        Register('fr8', 4, 0x220),
        Register('fr9', 4, 0x224),
        Register('dr10', 8, 0x228),
        Register('fr10', 4, 0x228),
        Register('fr11', 4, 0x22c),
        Register('dr12', 8, 0x230),
        Register('fr12', 4, 0x230),
        Register('fr13', 4, 0x234),
        Register('dr14', 8, 0x238),
        Register('fr14', 4, 0x238),
        Register('fr15', 4, 0x23c),
        Register('fpscr', 4, 0x300),
        Register('fpul', 4, 0x304),
        Register('resbank_base', 40960, 0x10000)
    ]

register_arch(['superh:be:32:sh-2a'], 32, Endness.BE, ArchPcode_SuperH_BE_32_SH_2A)
