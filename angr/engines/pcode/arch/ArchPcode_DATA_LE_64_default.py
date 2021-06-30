###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_DATA_LE_64_default(ArchPcode):
    name = 'DATA:LE:64:default'
    pcode_arch = 'DATA:LE:64:default'
    description = 'Raw Data File (Little Endian)'
    bits = 64
    ip_offset = 0x80000000
    sp_offset = 0x0
    bp_offset = sp_offset
    instruction_endness = Endness.LE
    register_list = [
        Register('sp', 8, 0x0),
        Register('r0', 8, 0x8),
        Register('contextreg', 4, 0x100)
    ]

register_arch(['data:le:64:default'], 64, Endness.LE, ArchPcode_DATA_LE_64_default)
