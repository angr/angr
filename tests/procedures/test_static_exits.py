#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# two consecutive blocks of authenticate() in i386/fauxware, the first ending in a call to open() and the second in a
# call to read(). This is the shape CFGFast._scan_procedure hands to static_exits: the block of the call site, preceded
# by the block that calls something else.
FIRST_BLOCK = 0x8048564
SECOND_BLOCK = 0x8048577
# the PLT stub of open(), which the first block calls
OPEN_PLT = 0x8048450
# the three addresses _start pushes before calling __libc_start_main
CSU_INIT = 0x80486F0
MAIN = 0x80485FC
CSU_FINI = 0x8048760


class TestStaticExits(unittest.TestCase):
    """
    CFGFast._scan_procedure hands the blocks leading to an ADDS_EXITS SimProcedure to its static_exits(), which
    executes them on a blank state to recover the arguments of the call.
    """

    def _project_and_blocks(self):
        ran: list[int] = []

        class CallTarget(angr.SimProcedure):
            def run(self):  # pylint:disable=arguments-differ
                ran.append(self.state.addr)
                return 0

        proj = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        # a relocatable object calls its imports directly, so the block before the call site regularly ends on a hooked
        # address; hooking the PLT stub that the first block calls reproduces that shape here
        proj.hook(OPEN_PLT, CallTarget())
        blocks = [proj.factory.block(FIRST_BLOCK).vex, proj.factory.block(SECOND_BLOCK).vex]
        return proj, blocks, ran

    @staticmethod
    def _procedure(proj: angr.Project, name: str) -> angr.SimProcedure:
        lib = next(lib for lib in angr.SIM_LIBRARIES["libc.so.6"] if lib.has_implementation(name))
        procedure = lib.get(name, proj.arch)
        procedure.project = proj
        procedure.arch = proj.arch
        return procedure

    def test_pthread_create_executes_the_blocks_it_is_given(self):
        proj, blocks, ran = self._project_and_blocks()

        exits = self._procedure(proj, "pthread_create").static_exits(blocks)

        assert not ran, "static_exits ran the SimProcedure hooked at the previous block's call target"
        assert [exit_["jumpkind"] for exit_ in exits] == ["Ijk_Call", "Ijk_Ret"]

    def test_libc_start_main_executes_the_blocks_it_is_given(self):
        proj, blocks, ran = self._project_and_blocks()

        exits = self._procedure(proj, "__libc_start_main").static_exits(blocks)

        assert not ran, "static_exits ran the SimProcedure hooked at the previous block's call target"
        assert [exit_["namehint"] for exit_ in exits] == ["main"]

    def test_libc_start_main_recovers_main_from_the_entry_block(self):
        proj = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)

        exits = self._procedure(proj, "__libc_start_main").static_exits([proj.factory.block(proj.entry).vex])

        assert [(exit_["namehint"], exit_["address"].concrete_value) for exit_ in exits] == [
            ("init", CSU_INIT),
            ("main", MAIN),
            ("fini", CSU_FINI),
        ]


if __name__ == "__main__":
    unittest.main()
