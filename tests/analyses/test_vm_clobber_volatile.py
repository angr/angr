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
from angr.calling_conventions import SimCCMicrosoftAMD64

from tests.common import bin_location


class _Stub(angr.SimProcedure):
    def run(self):  # pylint:disable=arguments-differ
        return self.state.solver.BVS("ret", 64)


class TestClobberVolatile(unittest.TestCase):
    """CNICdriver halt_cleanup_helper: rdx after a stubbed call differs per path and poisons the merge at a join."""

    def _after_call(self, flag):
        proj = angr.load_shellcode(b"\xe8\x00\x10\x00\x00\xc3", arch="amd64", load_address=0x1000)  # call 0x2005
        proj.hook(0x2005, _Stub(cc=SimCCMicrosoftAMD64(proj.arch)))
        if flag is not None:
            proj.vm_deob_clobber_volatile = flag
        state = proj.factory.blank_state(addr=0x1000)
        state.regs.rdx, state.regs.r11, state.regs.rdi = 0x52F50, 7, 9
        for _ in range(2):
            state = proj.factory.successors(state).successors[0]
        assert state.addr == 0x1005
        return state

    def test_caller_saved_registers_are_clobbered(self):
        state = self._after_call(True)
        assert state.solver.eval_one(state.regs.rdx) == 0 and state.solver.eval_one(state.regs.r11) == 0
        assert state.solver.eval_one(state.regs.rdi) == 9  # callee-saved under the Microsoft x64 convention
        assert state.regs.rax.symbolic  # the return value

    def test_off_by_default(self):
        state = self._after_call(None)
        assert state.solver.eval_one(state.regs.rdx) == 0x52F50

    def test_vm_deobfuscation_turns_it_on_only_when_asked(self):
        path = os.path.join(bin_location, "tests", "x86_64", "windows", "fauxware.exe")

        class _Stop(Exception):
            pass

        def stop(*args, **kwargs):
            raise _Stop

        for asked in (False, True):
            proj = angr.Project(path, auto_load_libs=False)
            state = proj.factory.blank_state(addr=proj.entry)
            with tempfile.TemporaryDirectory() as d, mock.patch.object(VMDeobfuscation, "data_sensitive_graph", stop):
                with self.assertRaises(_Stop):
                    proj.analyses.VMDeobfuscation(
                        None, start_addr=proj.entry, start_state=state, artifacts_dir=d, clobber_volatile_regs=asked
                    )
            assert getattr(proj, "vm_deob_clobber_volatile", False) is asked


if __name__ == "__main__":
    unittest.main()
