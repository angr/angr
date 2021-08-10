###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_Toy_BE_32_builder_align2(ArchPcode):
    name = 'Toy:BE:32:builder.align2'
    pcode_arch = 'Toy:BE:32:builder.align2'
    description = 'Toy (test-builder) processor 32-bit big-endian word-aligned'
    bits = 32
    ip_offset = 0x103c
    sp_offset = 0x1034
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('r0', 4, 0x1000),
        Register('r0h', 2, 0x1000),
        Register('r0l', 2, 0x1002),
        Register('r1', 4, 0x1004),
        Register('r1h', 2, 0x1004),
        Register('r1l', 2, 0x1006),
        Register('r2', 4, 0x1008),
        Register('r2h', 2, 0x1008),
        Register('r2l', 2, 0x100a),
        Register('r3', 4, 0x100c),
        Register('r3h', 2, 0x100c),
        Register('r3l', 2, 0x100e),
        Register('r4', 4, 0x1010),
        Register('r4h', 2, 0x1010),
        Register('r4l', 2, 0x1012),
        Register('r5', 4, 0x1014),
        Register('r5h', 2, 0x1014),
        Register('r5l', 2, 0x1016),
        Register('r6', 4, 0x1018),
        Register('r6h', 2, 0x1018),
        Register('r6l', 2, 0x101a),
        Register('r7', 4, 0x101c),
        Register('r7h', 2, 0x101c),
        Register('r7l', 2, 0x101e),
        Register('r8', 4, 0x1020),
        Register('r8h', 2, 0x1020),
        Register('r8l', 2, 0x1022),
        Register('r9', 4, 0x1024),
        Register('r9h', 2, 0x1024),
        Register('r9l', 2, 0x1026),
        Register('r10', 4, 0x1028),
        Register('r10h', 2, 0x1028),
        Register('r10l', 2, 0x102a),
        Register('r11', 4, 0x102c),
        Register('r11h', 2, 0x102c),
        Register('r11l', 2, 0x102e),
        Register('r12', 4, 0x1030),
        Register('r12h', 2, 0x1030),
        Register('r12l', 2, 0x1032),
        Register('sp', 4, 0x1034),
        Register('sph', 2, 0x1034),
        Register('spl', 2, 0x1036),
        Register('lr', 4, 0x1038),
        Register('lrh', 2, 0x1038),
        Register('lrl', 2, 0x103a),
        Register('pc', 4, 0x103c, alias_names=('ip',)),
        Register('pch', 2, 0x103c),
        Register('pcl', 2, 0x103e),
        Register('c', 1, 0x1100),
        Register('z', 1, 0x1101),
        Register('n', 1, 0x1102),
        Register('v', 1, 0x1103),
        Register('contextreg', 8, 0x2000)
    ]

register_arch(['toy:be:32:builder.align2'], 32, Endness.BE, ArchPcode_Toy_BE_32_builder_align2)
