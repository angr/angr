###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_Toy_BE_64_default(ArchPcode):
    name = 'Toy:BE:64:default'
    pcode_arch = 'Toy:BE:64:default'
    description = 'Toy (test) processor 64-bit big-endian'
    bits = 64
    ip_offset = 0x1078
    sp_offset = 0x1068
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('r0', 8, 0x1000),
        Register('r0h', 4, 0x1000),
        Register('r0l', 4, 0x1004),
        Register('r1', 8, 0x1008),
        Register('r1h', 4, 0x1008),
        Register('r1l', 4, 0x100c),
        Register('r2', 8, 0x1010),
        Register('r2h', 4, 0x1010),
        Register('r2l', 4, 0x1014),
        Register('r3', 8, 0x1018),
        Register('r3h', 4, 0x1018),
        Register('r3l', 4, 0x101c),
        Register('r4', 8, 0x1020),
        Register('r4h', 4, 0x1020),
        Register('r4l', 4, 0x1024),
        Register('r5', 8, 0x1028),
        Register('r5h', 4, 0x1028),
        Register('r5l', 4, 0x102c),
        Register('r6', 8, 0x1030),
        Register('r6h', 4, 0x1030),
        Register('r6l', 4, 0x1034),
        Register('r7', 8, 0x1038),
        Register('r7h', 4, 0x1038),
        Register('r7l', 4, 0x103c),
        Register('r8', 8, 0x1040),
        Register('r8h', 4, 0x1040),
        Register('r8l', 4, 0x1044),
        Register('r9', 8, 0x1048),
        Register('r9h', 4, 0x1048),
        Register('r9l', 4, 0x104c),
        Register('r10', 8, 0x1050),
        Register('r10h', 4, 0x1050),
        Register('r10l', 4, 0x1054),
        Register('r11', 8, 0x1058),
        Register('r11h', 4, 0x1058),
        Register('r11l', 4, 0x105c),
        Register('r12', 8, 0x1060),
        Register('r12h', 4, 0x1060),
        Register('r12l', 4, 0x1064),
        Register('sp', 8, 0x1068),
        Register('sph', 4, 0x1068),
        Register('spl', 4, 0x106c),
        Register('lr', 8, 0x1070),
        Register('lrh', 4, 0x1070),
        Register('lrl', 4, 0x1074),
        Register('pc', 8, 0x1078, alias_names=('ip',)),
        Register('pch', 4, 0x1078),
        Register('pcl', 4, 0x107c),
        Register('c', 1, 0x1100),
        Register('z', 1, 0x1101),
        Register('n', 1, 0x1102),
        Register('v', 1, 0x1103)
    ]

register_arch(['toy:be:64:default'], 64, Endness.BE, ArchPcode_Toy_BE_64_default)
