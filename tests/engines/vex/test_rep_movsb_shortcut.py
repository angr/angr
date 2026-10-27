#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.engines.vex"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.state_plugins.solver import SimSolver

SRC = 0x10000
DST = 0x20000
DATA = b"pushan!!"


class TestRepMovsbShortcut(unittest.TestCase):
    def _step(self, arch, code, rep_off, selfmodifying_code, shortcut=True):
        proj = angr.load_shellcode(code, arch, load_address=0x1000, selfmodifying_code=selfmodifying_code)
        proj.enable_rep_movsb_shortcut = shortcut
        proj.rep_movsb_addr = {0x1000 + rep_off}
        state = proj.factory.blank_state(addr=0x1000)
        state.register_plugin("partial_symbolic_constraint_solver", SimSolver(claripy.SolverReplacement()))
        state.memory.store(SRC, DATA)
        for reg, val in (("ax", len(DATA)), ("cx", len(DATA)), ("si", SRC), ("di", DST)):
            setattr(state.regs, ("r" if arch == "AMD64" else "e") + reg, val)
        return proj.factory.successors(state).flat_successors

    def _check(self, arch, code, rep_off):
        for smc in (True, False):
            succs = self._step(arch, code, rep_off, smc)
            assert len(succs) == 1
            s = succs[0]
            assert s.addr == 0x1000 + rep_off + 2
            assert s.solver.eval(s.memory.load(DST, len(DATA)), cast_to=bytes) == DATA
            assert s.solver.eval(s.regs.ecx) == 0
            assert s.solver.eval(s.regs.esi) == SRC + len(DATA)
            assert s.solver.eval(s.regs.edi) == DST + len(DATA)

    def test_x86(self):
        self._check("X86", b"\xf3\xa4\x90", 0)

    def test_x86_mid_block(self):
        self._check("X86", b"\x89\xc1\xf3\xa4\x90", 2)  # mov ecx, eax; rep movsb

    def test_amd64(self):
        self._check("AMD64", b"\xf3\xa4\x90", 0)

    def test_amd64_mid_block(self):
        self._check("AMD64", b"\x48\x89\xc1\xf3\xa4\x90", 3)  # mov rcx, rax; rep movsb

    def test_shortcut_disabled(self):
        succs = self._step("AMD64", b"\xf3\xa4\x90", 0, True, shortcut=False)
        addrs = sorted(s.addr for s in succs)
        assert addrs == [0x1000]  # one iteration, loops back to itself


if __name__ == "__main__":
    unittest.main()
