###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_V850_LE_32_default(ArchPcode):
    name = 'V850:LE:32:default'
    pcode_arch = 'V850:LE:32:default'
    description = 'Renesas V850 family'
    bits = 32
    ip_offset = 0x100
    sp_offset = 0xc
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('r0r1', 8, 0x0),
        Register('r0', 4, 0x0),
        Register('r1', 4, 0x4),
        Register('r2sp', 8, 0x8),
        Register('r2', 4, 0x8),
        Register('sp', 4, 0xc),
        Register('r4r5', 8, 0x10),
        Register('gp', 4, 0x10),
        Register('tp', 4, 0x14),
        Register('r6r7', 8, 0x18),
        Register('r6', 4, 0x18),
        Register('r7', 4, 0x1c),
        Register('r8r9', 8, 0x20),
        Register('r8', 4, 0x20),
        Register('r9', 4, 0x24),
        Register('r10r11', 8, 0x28),
        Register('r10', 4, 0x28),
        Register('r11', 4, 0x2c),
        Register('r12r13', 8, 0x30),
        Register('r12', 4, 0x30),
        Register('r13', 4, 0x34),
        Register('r14r15', 8, 0x38),
        Register('r14', 4, 0x38),
        Register('r15', 4, 0x3c),
        Register('r16r17', 8, 0x40),
        Register('r16', 4, 0x40),
        Register('r17', 4, 0x44),
        Register('r18r19', 8, 0x48),
        Register('r18', 4, 0x48),
        Register('r19', 4, 0x4c),
        Register('r20r21', 8, 0x50),
        Register('r20', 4, 0x50),
        Register('r21', 4, 0x54),
        Register('r22r23', 8, 0x58),
        Register('r22', 4, 0x58),
        Register('r23', 4, 0x5c),
        Register('r24r25', 8, 0x60),
        Register('r24', 4, 0x60),
        Register('r25', 4, 0x64),
        Register('r26r27', 8, 0x68),
        Register('r26', 4, 0x68),
        Register('r27', 4, 0x6c),
        Register('r28r29', 8, 0x70),
        Register('r28', 4, 0x70),
        Register('r29', 4, 0x74),
        Register('ep', 4, 0x78),
        Register('lp', 4, 0x7c),
        Register('eipc', 4, 0x80),
        Register('eipsw', 4, 0x84),
        Register('fepc', 4, 0x88),
        Register('fepsw', 4, 0x8c),
        Register('ecr', 4, 0x90),
        Register('psw', 4, 0x94),
        Register('fpsr', 4, 0x98),
        Register('fpepc', 4, 0x9c),
        Register('fpst', 4, 0xa0),
        Register('fpcc', 4, 0xa4),
        Register('fpcfg', 4, 0xa8),
        Register('sccfg', 4, 0xac),
        Register('scbp', 4, 0xb0),
        Register('eiic', 4, 0xb4),
        Register('feic', 4, 0xb8),
        Register('dbic', 4, 0xbc),
        Register('ctpc', 4, 0xc0),
        Register('ctpsw', 4, 0xc4),
        Register('dbpc', 4, 0xc8),
        Register('dbpsw', 4, 0xcc),
        Register('ctbp', 4, 0xd0),
        Register('dir', 4, 0xd4),
        Register('dbg22', 4, 0xd8),
        Register('dbg23', 4, 0xdc),
        Register('dbg24', 4, 0xe0),
        Register('dbg25', 4, 0xe4),
        Register('dbg26', 4, 0xe8),
        Register('dbg27', 4, 0xec),
        Register('eiwr', 4, 0xf0),
        Register('fewr', 4, 0xf4),
        Register('dbwr', 4, 0xf8),
        Register('bsel', 4, 0xfc),
        Register('pc', 4, 0x100, alias_names=('ip',))
    ]

register_arch(['v850:le:32:default'], 32, Endness.LE, ArchPcode_V850_LE_32_default)
