import os
import logging
import sys
import unittest

import angr

l = logging.getLogger("angr.tests")
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

insn_texts = {
    "i386": b"add eax, 0xf",
    "x86_64": b"add rax, 0xf",
    "ppc": b"addi %r1, %r1, 0xf",
    "armel": b"add r1, r1, 0xf",
    "armel_thumb": b"add.w r1, r1, #0xf",
    "mips": b"addi $1, $1, 0xf",
}


class TestKeyStone(unittest.TestCase):
    def _run_keystone(self, arch):
        proj_arch = arch
        is_thumb = False
        if arch == "armel_thumb":
            is_thumb = True
            proj_arch = "armel"
        p = angr.Project(os.path.join(test_location, proj_arch, "fauxware"), auto_load_libs=False)
        addr = p.loader.main_object.get_symbol("authenticate").rebased_addr

        sm = p.factory.simulation_manager()
        if arch in ["i386", "x86_64"]:
            sm.one_active.regs.eax = 3
        else:
            sm.one_active.regs.r1 = 3

        if is_thumb:
            addr |= 1
        block = p.factory.block(addr, insn_text=insn_texts[arch], thumb=is_thumb).vex

        assert block.instructions == 1

        sm.step(force_addr=addr, insn_text=insn_texts[arch], thumb=is_thumb)

        if arch in ["i386", "x86_64"]:
            assert sm.one_active.solver.eval(sm.one_active.regs.eax) == 0x12
        else:
            assert sm.one_active.solver.eval(sm.one_active.regs.r1) == 0x12

    def test_i386(self):
        # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
        # re-enabling this test on Windows.
        if not sys.platform.startswith("linux"):
            return

        self._run_keystone("i386")

    def test_x86_64(self):
        # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
        # re-enabling this test on Windows.
        if not sys.platform.startswith("linux"):
            return

        self._run_keystone("x86_64")

    def test_ppc(self):
        # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
        # re-enabling this test on Windows.
        if not sys.platform.startswith("linux"):
            return

        self._run_keystone("ppc")

    def test_armel(self):
        # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
        # re-enabling this test on Windows.
        if not sys.platform.startswith("linux"):
            return

        self._run_keystone("armel")

    def test_armel_thumb(self):
        # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
        # re-enabling this test on Windows.
        if not sys.platform.startswith("linux"):
            return

        self._run_keystone("armel_thumb")

    def test_mips(self):
        # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
        # re-enabling this test on Windows.
        if not sys.platform.startswith("linux"):
            return

        self._run_keystone("mips")


if __name__ == "__main__":
    unittest.main()
