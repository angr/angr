###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_CR16C_LE_16_default(ArchPcode):
    name = 'CR16C:LE:16:default'
    pcode_arch = 'CR16C:LE:16:default'
    description = "National Semiconductor's CompactRISC CR16C little endian"
    bits = 16
    ip_offset = 0x32
    sp_offset = 0x24
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('r1r0', 4, 0x0),
        Register('r0', 2, 0x0),
        Register('r2r1', 4, 0x2),
        Register('r1', 2, 0x2),
        Register('r3r2', 4, 0x4),
        Register('r2', 2, 0x4),
        Register('r4r3', 4, 0x6),
        Register('r3', 2, 0x6),
        Register('r5r4', 4, 0x8),
        Register('r4', 2, 0x8),
        Register('r6r5', 4, 0xa),
        Register('r5', 2, 0xa),
        Register('r7r6', 4, 0xc),
        Register('r6', 2, 0xc),
        Register('r8r7', 4, 0xe),
        Register('r7', 2, 0xe),
        Register('r9r8', 4, 0x10),
        Register('r8', 2, 0x10),
        Register('r10r9', 4, 0x12),
        Register('r9', 2, 0x12),
        Register('r11r10', 4, 0x14),
        Register('r10', 2, 0x14),
        Register('r12lr11', 4, 0x16),
        Register('r11', 2, 0x16),
        Register('r12', 4, 0x18),
        Register('r12_l', 2, 0x18),
        Register('r12_h', 2, 0x1a),
        Register('r13', 4, 0x1c),
        Register('r13_l', 2, 0x1c),
        Register('r13_h', 2, 0x1e),
        Register('ra', 4, 0x20),
        Register('ra_l', 2, 0x20),
        Register('ra_h', 2, 0x22),
        Register('sp', 4, 0x24),
        Register('sp_l', 2, 0x24),
        Register('sp_h', 2, 0x26),
        Register('pc', 4, 0x32, alias_names=('ip',)),
        Register('isp', 4, 0x3c),
        Register('isph', 2, 0x3c),
        Register('ispl', 2, 0x3e),
        Register('usp', 4, 0x40),
        Register('usph', 2, 0x40),
        Register('uspl', 2, 0x42),
        Register('intbase', 4, 0x44),
        Register('intbaseh', 2, 0x44),
        Register('intbasel', 2, 0x46),
        Register('psr', 2, 0x50),
        Register('cfg', 2, 0x64),
        Register('dbs', 2, 0x6e),
        Register('dsr', 2, 0x70),
        Register('dcr', 4, 0x72),
        Register('dcrh', 2, 0x72),
        Register('dcrl', 2, 0x74),
        Register('car0', 4, 0x76),
        Register('car0h', 2, 0x76),
        Register('car0l', 2, 0x78),
        Register('car1', 4, 0x7a),
        Register('car1h', 2, 0x7a),
        Register('car1l', 2, 0x7c),
        Register('dbs_1', 4, 0x82),
        Register('dsr_1', 4, 0x86),
        Register('cfg_1', 4, 0x8a),
        Register('psr_1', 4, 0x8e)
    ]

register_arch(['cr16c:le:16:default'], 16, Endness.LE, ArchPcode_CR16C_LE_16_default)
