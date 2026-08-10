#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import angr
from angr.analyses.cfg.indirect_jump_resolvers.arm_elf_fast import ArmElfFastResolver
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

FAUXWARE = os.path.join(test_location, "armel", "fauxware")

# armel/fauxware is loaded at 0x8000, so an address in it is also its offset in the file
LOAD_BASE = 0x8000

# strcmp's PLT stub, the sequence _resolve_put is written for:
#
#   8430  add ip, pc, #0
#   8434  add ip, ip, #0x8000
#   8438  ldr pc, [ip, #0xbd4]!
STRCMP_STUB = 0x8430

# Overwriting accepted(), a leaf function, puts an add of two registers in a block that still ends in
# an indirect jump through r12.
ACCEPTED = 0x85F0
REGISTER_ADD_BODY = bytes.fromhex(
    "11caa0e3"  # mov ip, #0x11000
    "023081e0"  # add r3, r1, r2
    "20c08ce2"  # add ip, ip, #0x20
    "04f0bce5"  # ldr pc, [ip, #4]!
)


class TestArmElfFastResolver(unittest.TestCase):
    def test_plt_stub_is_resolved(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        strcmp = proj.loader.find_symbol("strcmp")
        assert strcmp is not None
        stub = cfg.model.get_any_node(STRCMP_STUB)
        assert stub is not None
        assert sorted(successor.addr for successor in cfg.model.get_successors(stub)) == [strcmp.rebased_addr]

    def test_block_with_a_register_add_is_declined(self):
        with open(FAUXWARE, "rb") as f:
            image = bytearray(f.read())
        offset = ACCEPTED - LOAD_BASE
        image[offset : offset + len(REGISTER_ADD_BODY)] = REGISTER_ADD_BODY

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "fauxware-register-add")
            with open(path, "wb") as f:
                f.write(image)
            proj = angr.Project(path, auto_load_libs=False)
            # the register add used to raise IndexError here and abort the whole scan
            cfg = proj.analyses.CFGFast()

            # 0x11000 + 0x20 + 4 holds a code address, so adding up only the constants hands back a target
            # for a block whose r12 also depends on r1 and r2
            block = proj.factory.block(ACCEPTED, cross_insn_opt=False).vex  # how CFGFast lifts
            resolver = ArmElfFastResolver(proj)
            assert resolver.resolve(cfg, ACCEPTED, ACCEPTED, block, block.jumpkind) == (False, [])


if __name__ == "__main__":
    unittest.main()
