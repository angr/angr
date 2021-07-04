###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_80251_BE_24_default(ArchPcode):
    name = '80251:BE:24:default'
    pcode_arch = '80251:BE:24:default'
    description = '80251 Microcontroller Family'
    bits = 16
    ip_offset = 0x44
    sp_offset = 0x3c
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('dr0', 4, 0x0),
        Register('wr0', 2, 0x0),
        Register('r0', 1, 0x0),
        Register('r1', 1, 0x1),
        Register('wr2', 2, 0x2),
        Register('r2', 1, 0x2),
        Register('r3', 1, 0x3),
        Register('dr4', 4, 0x4),
        Register('wr4', 2, 0x4),
        Register('r4', 1, 0x4),
        Register('r5', 1, 0x5),
        Register('wr6', 2, 0x6),
        Register('r6', 1, 0x6),
        Register('r7', 1, 0x7),
        Register('dr8', 4, 0x8),
        Register('wr8', 2, 0x8),
        Register('r8', 1, 0x8),
        Register('r9', 1, 0x9),
        Register('ab', 2, 0xa),
        Register('b', 1, 0xa),
        Register('acc', 1, 0xb),
        Register('dr12', 4, 0xc),
        Register('wr12', 2, 0xc),
        Register('r12', 1, 0xc),
        Register('r13', 1, 0xd),
        Register('wr14', 2, 0xe),
        Register('r14', 1, 0xe),
        Register('r15', 1, 0xf),
        Register('dr16', 4, 0x10),
        Register('wr16', 2, 0x10),
        Register('r16', 1, 0x10),
        Register('r17', 1, 0x11),
        Register('wr18', 2, 0x12),
        Register('r18', 1, 0x12),
        Register('r19', 1, 0x13),
        Register('dr20', 4, 0x14),
        Register('wr20', 2, 0x14),
        Register('r20', 1, 0x14),
        Register('r21', 1, 0x15),
        Register('wr22', 2, 0x16),
        Register('r22', 1, 0x16),
        Register('r23', 1, 0x17),
        Register('dr24', 4, 0x18),
        Register('wr24', 2, 0x18),
        Register('r24', 1, 0x18),
        Register('r25', 1, 0x19),
        Register('wr26', 2, 0x1a),
        Register('r26', 1, 0x1a),
        Register('r27', 1, 0x1b),
        Register('dr28', 4, 0x1c),
        Register('wr28', 2, 0x1c),
        Register('r28', 1, 0x1c),
        Register('r29', 1, 0x1d),
        Register('wr30', 2, 0x1e),
        Register('r30', 1, 0x1e),
        Register('r31', 1, 0x1f),
        Register('dpx', 4, 0x38),
        Register('r56', 1, 0x38),
        Register('dpxl', 1, 0x39),
        Register('dptr', 2, 0x3a),
        Register('dph', 1, 0x3a),
        Register('dpl', 1, 0x3b),
        Register('spx', 4, 0x3c),
        Register('r60', 1, 0x3c),
        Register('r61', 1, 0x3d),
        Register('sph', 1, 0x3e),
        Register('sp', 3, 0x40),
        Register('pc', 3, 0x44, alias_names=('ip',)),
        Register('psw', 1, 0x48),
        Register('contextreg', 4, 0x50),
        Register('jumptableguard1', 1, 0x70),
        Register('jumptableguard2', 1, 0x71)
    ]

register_arch(['80251:be:24:default'], 16, Endness.BE, ArchPcode_80251_BE_24_default)
