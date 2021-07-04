###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_PIC_17_LE_16_PIC_17C7xx(ArchPcode):
    name = 'PIC-17:LE:16:PIC-17C7xx'
    pcode_arch = 'PIC-17:LE:16:PIC-17C7xx'
    description = 'PIC-17C7xx'
    bits = 16
    ip_offset = 0x0
    sp_offset = 0x4
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('indf0', 1, 0x0),
        Register('fsr0', 1, 0x1),
        Register('pclat', 2, 0x2),
        Register('pcl', 1, 0x2),
        Register('pclath', 1, 0x3),
        Register('alusta', 1, 0x4),
        Register('t0sta', 1, 0x5),
        Register('cpusta', 1, 0x6),
        Register('intsta', 1, 0x7),
        Register('indf1', 1, 0x8),
        Register('fsr1', 1, 0x9),
        Register('tmr0l', 1, 0xb),
        Register('tmr0h', 1, 0xc),
        Register('tblptr', 2, 0xd),
        Register('tblptrl', 1, 0xd),
        Register('tblptrh', 1, 0xe),
        Register('bsr', 1, 0xf),
        Register('porta', 1, 0x10),
        Register('ddrb', 1, 0x11),
        Register('portb', 1, 0x12),
        Register('rcsta1', 1, 0x13),
        Register('rcreg1', 1, 0x14),
        Register('txsta1', 1, 0x15),
        Register('txreg1', 1, 0x16),
        Register('spbrg1', 1, 0x17),
        Register('prod', 2, 0x18),
        Register('prodl', 1, 0x18),
        Register('prodh', 1, 0x19),
        Register('ddrc', 1, 0x110),
        Register('portc', 1, 0x111),
        Register('ddrd', 1, 0x112),
        Register('portd', 1, 0x113),
        Register('ddre', 1, 0x114),
        Register('porte', 1, 0x115),
        Register('pir1', 1, 0x116),
        Register('pie1', 1, 0x117),
        Register('tmr1', 1, 0x210),
        Register('tmr2', 1, 0x211),
        Register('tmr3l', 1, 0x212),
        Register('tmr3h', 1, 0x213),
        Register('pr1', 1, 0x214),
        Register('pr2', 1, 0x215),
        Register('pr3lca1l', 1, 0x216),
        Register('pr3hca1h', 1, 0x217),
        Register('pw1dcl', 1, 0x310),
        Register('pw2dcl', 1, 0x311),
        Register('pw1dch', 1, 0x312),
        Register('pw2dch', 1, 0x313),
        Register('ca2l', 1, 0x314),
        Register('ca2h', 1, 0x315),
        Register('tcon1', 1, 0x316),
        Register('tcon2', 1, 0x317),
        Register('pir2', 1, 0x410),
        Register('pie2', 1, 0x411),
        Register('rcsta2', 1, 0x413),
        Register('rcreg2', 1, 0x414),
        Register('txsta2', 1, 0x415),
        Register('txreg2', 1, 0x416),
        Register('spbrg2', 1, 0x417),
        Register('ddrf', 1, 0x510),
        Register('portf', 1, 0x511),
        Register('ddrg', 1, 0x512),
        Register('portg', 1, 0x513),
        Register('adcon0', 1, 0x514),
        Register('adcon1', 1, 0x515),
        Register('adres', 2, 0x516),
        Register('adresl', 1, 0x516),
        Register('adresh', 1, 0x517),
        Register('sspadd', 1, 0x610),
        Register('sspcon1', 1, 0x611),
        Register('sspcon2', 1, 0x612),
        Register('sspstat', 1, 0x613),
        Register('sspbuf', 1, 0x614),
        Register('pw3dcl', 1, 0x710),
        Register('pw3dch', 1, 0x711),
        Register('ca3l', 1, 0x712),
        Register('ca3h', 1, 0x713),
        Register('ca4l', 1, 0x714),
        Register('ca4h', 1, 0x715),
        Register('tcon3', 1, 0x716),
        Register('ddrh', 1, 0x810),
        Register('porth', 1, 0x811),
        Register('ddrj', 1, 0x812),
        Register('portj', 1, 0x813),
        Register('pc', 2, 0x0, alias_names=('ip',)),
        Register('stkptr', 1, 0x4),
        Register('fs32', 1, 0x5),
        Register('fs10', 1, 0x6),
        Register('ov', 1, 0x7),
        Register('z', 1, 0x8),
        Register('dc', 1, 0x9),
        Register('c', 1, 0xa),
        Register('tblat', 2, 0x10),
        Register('tblatl', 1, 0x10),
        Register('tblath', 1, 0x11),
        Register('wreg', 1, 0x20)
    ]

register_arch(['pic-17:le:16:pic-17c7xx'], 16, Endness.LE, ArchPcode_PIC_17_LE_16_PIC_17C7xx)
