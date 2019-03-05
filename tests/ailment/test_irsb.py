
import pyvex
import archinfo

import ailment


def test_convert_from_irsb():

    arch = archinfo.arch_from_id('AMD64')

    manager = ailment.Manager(arch=arch)

    block_bytes = bytes.fromhex("554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF")

    irsb = pyvex.IRSB(block_bytes, 0x4006c6, arch, opt_level=0)

    ablock = ailment.IRSBConverter.convert(irsb, manager)

    print(str(ablock))


if __name__ == "__main__":
    test_convert_from_irsb()
