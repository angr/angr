###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_HCS12_BE_24_default(ArchPcode):
    name = 'HCS12:BE:24:default'
    pcode_arch = 'HCS12:BE:24:default'
    description = 'HCS12X Microcontroller Family'
    bits = 24
    ip_offset = 0x24
    sp_offset = 0x2a
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('gpage', 1, 0x10),
        Register('direct', 1, 0x11),
        Register('rpage', 1, 0x16),
        Register('epage', 1, 0x17),
        Register('ppage', 1, 0x30),
        Register('d', 2, 0x0),
        Register('a', 1, 0x0),
        Register('b', 1, 0x1),
        Register('ix', 2, 0x10),
        Register('ixh', 1, 0x10),
        Register('ixl', 1, 0x11),
        Register('iy', 2, 0x12),
        Register('iyh', 1, 0x12),
        Register('iyl', 1, 0x13),
        Register('tmp2', 2, 0x14),
        Register('tmp2h', 1, 0x14),
        Register('tmp2l', 1, 0x15),
        Register('tmp3', 2, 0x16),
        Register('tmp3h', 1, 0x16),
        Register('tmp3l', 1, 0x17),
        Register('tmp1', 2, 0x18),
        Register('tmp1h', 1, 0x18),
        Register('tmp1l', 1, 0x19),
        Register('pce', 3, 0x23),
        Register('pc', 2, 0x24, alias_names=('ip',)),
        Register('pch', 1, 0x24),
        Register('pcl', 1, 0x25),
        Register('sp', 2, 0x2a),
        Register('sph', 1, 0x2a),
        Register('spl', 1, 0x2b),
        Register('ccrw', 2, 0x30),
        Register('ccrh', 1, 0x30),
        Register('ccr', 1, 0x31),
        Register('physpage', 3, 0x32),
        Register('contextreg', 4, 0x40),
        Register('r0', 2, 0x100),
        Register('r0.h', 1, 0x100),
        Register('r0.l', 1, 0x101),
        Register('r1', 2, 0x102),
        Register('r1.h', 1, 0x102),
        Register('r1.l', 1, 0x103),
        Register('r2', 2, 0x104),
        Register('r2.h', 1, 0x104),
        Register('r2.l', 1, 0x105),
        Register('r3', 2, 0x106),
        Register('r3.h', 1, 0x106),
        Register('r3.l', 1, 0x107),
        Register('r4', 2, 0x108),
        Register('r4.h', 1, 0x108),
        Register('r4.l', 1, 0x109),
        Register('r5', 2, 0x10a),
        Register('r5.h', 1, 0x10a),
        Register('r5.l', 1, 0x10b),
        Register('r6', 2, 0x10c),
        Register('r6.h', 1, 0x10c),
        Register('r6.l', 1, 0x10d),
        Register('r7', 2, 0x10e),
        Register('r7.h', 1, 0x10e),
        Register('r7.l', 1, 0x10f),
        Register('xpc', 2, 0x110),
        Register('xccr', 2, 0x112),
        Register('xc', 1, 0x120),
        Register('xv', 1, 0x121),
        Register('xz', 1, 0x122),
        Register('xn', 1, 0x123)
    ]

register_arch(['hcs12:be:24:default'], 24, Endness.BE, ArchPcode_HCS12_BE_24_default)
