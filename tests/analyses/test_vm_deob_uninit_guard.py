#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest
from unittest import mock

import angr
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation

from tests.common import bin_location


class _Stop(Exception):
    pass


class TestExplorationUninitGuard(unittest.TestCase):
    """CNICdriver halt_cleanup_helper: VM4 tests the .data-tail global g_47e18; exploring with its load-time zero
    kept only the no-hook successor, so the re-arm path was never explored."""

    def test_guard_on_uninitialized_global_keeps_both_successors(self):
        path = os.path.join(bin_location, "tests", "x86_64", "windows", "fauxware.exe")
        proj = angr.Project(path, auto_load_libs=False)
        bss = 0x14000C400  # .data past its file contents
        captured = {}

        def capture(self, filename, start_addr, start_state, *args, **kwargs):
            captured["state"] = start_state
            raise _Stop

        state = proj.factory.blank_state(addr=proj.entry)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(VMDeobfuscation, "data_sensitive_graph", capture):
            with self.assertRaises(_Stop):
                proj.analyses.VMDeobfuscation(None, start_addr=proj.entry, start_state=state, artifacts_dir=d)
        st = captured["state"]

        # movabs rax, [bss]; test rax, rax; je +1; nop; ret
        code = b"\x48\xa1" + bss.to_bytes(8, "little") + bytes.fromhex("4885c0" "7401" "90" "c3")
        st.regs.ip = 0x1000
        irsb = proj.factory.block(0x1000, byte_string=code, opt_level=0).vex
        succs = proj.factory.successors(st, irsb=irsb)
        # both guards are satisfiable and symbolic, so the in-VM successor filter keeps both
        assert len(succs.successors) == 2
        assert all(s.solver.symbolic(s.scratch.guard) for s in succs.successors)


if __name__ == "__main__":
    unittest.main()
