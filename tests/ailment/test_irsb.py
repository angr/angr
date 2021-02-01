import angr
import pyvex
import archinfo

import ailment

block_bytes = bytes.fromhex("554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF")
block_addr = 0x4006c6

def test_convert_from_vex_irsb():

    arch = archinfo.arch_from_id('AMD64')

    manager = ailment.Manager(arch=arch)

    irsb = pyvex.IRSB(block_bytes, block_addr, arch, opt_level=0)

    ablock = ailment.IRSBConverter.convert(irsb, manager)

    print(str(ablock))

def test_convert_from_pcode_irsb():

    arch = archinfo.arch_from_id('AMD64')

    manager = ailment.Manager(arch=arch)

    p = angr.load_shellcode(block_bytes, arch, block_addr, block_addr,
                            engine=angr.engines.UberEnginePcode)

    irsb = p.factory.block(block_addr).vex

    ablock = ailment.IRSBConverter.convert(irsb, manager)

    print(str(ablock))

if __name__ == "__main__":
    test_convert_from_vex_irsb()
    test_convert_from_pcode_irsb()
