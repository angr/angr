###
### This file was automatically generated
###

from archinfo.arch import register_arch, Endness, Register

from .common import ArchPcode


class ArchPcode_JVM_BE_32_default(ArchPcode):
    name = 'JVM:BE:32:default'
    pcode_arch = 'JVM:BE:32:default'
    description = 'Generic JVM'
    bits = 32
    ip_offset = 0xc
    sp_offset = 0x8
    bp_offset = sp_offset
    instruction_endness = Endness.BE
    register_list = [
        Register('cat2_return_value', 8, 0x0),
        Register('return_value', 4, 0x4),
        Register('sp', 4, 0x8),
        Register('pc', 4, 0xc, alias_names=('ip',)),
        Register('switch_target', 4, 0x10),
        Register('return_address', 4, 0x14),
        Register('call_target', 4, 0x18),
        Register('lva', 4, 0x1c),
        Register('switch_ctrl', 16, 0x100)
    ]

register_arch(['jvm:be:32:default'], 32, Endness.BE, ArchPcode_JVM_BE_32_default)
