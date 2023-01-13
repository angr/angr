import unittest

import ailment

try:
    import angr
    import archinfo
except ImportError:
    angr = None

try:
    import pyvex
except ImportError:
    pyvex = None


class TestIrsb(unittest.TestCase):
    # pylint: disable=missing-class-docstring
    block_bytes = bytes.fromhex(
        "554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF"
    )  # pylint: disable=line-too-long
    block_addr = 0x4006C6

    @unittest.skipUnless(pyvex, "pyvex required")
    def test_convert_from_vex_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    @unittest.skipUnless(angr and hasattr(angr.engines, "UberEnginePcode"), "angr and pypcode required")
    def test_convert_from_pcode_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        p = angr.load_shellcode(
            self.block_bytes, arch, self.block_addr, self.block_addr, engine=angr.engines.UberEnginePcode
        )
        irsb = p.factory.block(self.block_addr).vex
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid


if __name__ == "__main__":
    unittest.main()
