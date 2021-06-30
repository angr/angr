###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_avr8_LE_16_atmega256(ArchPcode):
    name = 'avr8:LE:16:atmega256'
    pcode_arch = 'avr8:LE:16:atmega256'
    description = 'AVR8 for an Atmega 256'
    bits = 24
    ip_offset = 0x42
    sp_offset = 0x3d
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('sp', 2, 0x3d),
        Register('spl', 1, 0x3d),
        Register('sph', 1, 0x3e),
        Register('pc', 3, 0x42, alias_names=('ip',)),
        Register('cflg', 1, 0x80),
        Register('zflg', 1, 0x81),
        Register('nflg', 1, 0x82),
        Register('vflg', 1, 0x83),
        Register('sflg', 1, 0x84),
        Register('hflg', 1, 0x85),
        Register('tflg', 1, 0x86),
        Register('iflg', 1, 0x87),
        Register('skip', 1, 0x88),
        Register('contextreg', 4, 0x90),
        Register('r1r0', 2, 0x0),
        Register('r0', 1, 0x0),
        Register('r1', 1, 0x1),
        Register('r3r2', 2, 0x2),
        Register('r2', 1, 0x2),
        Register('r3', 1, 0x3),
        Register('r5r4', 2, 0x4),
        Register('r4', 1, 0x4),
        Register('r5', 1, 0x5),
        Register('r7r6', 2, 0x6),
        Register('r6', 1, 0x6),
        Register('r7', 1, 0x7),
        Register('r9r8', 2, 0x8),
        Register('r8', 1, 0x8),
        Register('r9', 1, 0x9),
        Register('r11r10', 2, 0xa),
        Register('r10', 1, 0xa),
        Register('r11', 1, 0xb),
        Register('r13r12', 2, 0xc),
        Register('r12', 1, 0xc),
        Register('r13', 1, 0xd),
        Register('r15r14', 2, 0xe),
        Register('r14', 1, 0xe),
        Register('r15', 1, 0xf),
        Register('r19r18r17r16', 4, 0x10),
        Register('r17r16', 2, 0x10),
        Register('r16', 1, 0x10),
        Register('r17', 1, 0x11),
        Register('r19r18', 2, 0x12),
        Register('r18', 1, 0x12),
        Register('r19', 1, 0x13),
        Register('r23r22r21r20', 4, 0x14),
        Register('r21r20', 2, 0x14),
        Register('r20', 1, 0x14),
        Register('r21', 1, 0x15),
        Register('r23r22', 2, 0x16),
        Register('r22', 1, 0x16),
        Register('r23', 1, 0x17),
        Register('w', 2, 0x18),
        Register('wlo', 1, 0x18),
        Register('whi', 1, 0x19),
        Register('x', 2, 0x1a),
        Register('xlo', 1, 0x1a),
        Register('xhi', 1, 0x1b),
        Register('y', 2, 0x1c),
        Register('ylo', 1, 0x1c),
        Register('yhi', 1, 0x1d),
        Register('z', 2, 0x1e),
        Register('zlo', 1, 0x1e),
        Register('zhi', 1, 0x1f),
        Register('rampd', 1, 0x58),
        Register('rampx', 1, 0x59),
        Register('rampy', 1, 0x5a),
        Register('rampz', 1, 0x5b),
        Register('eind', 1, 0x5c),
        Register('sreg', 1, 0x5f)
    ]

register_arch(['avr8:le:16:atmega256'], 24, Endness.LE, ArchPcode_avr8_LE_16_atmega256)
