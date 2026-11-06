#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import contextlib
import io
import types
import unittest

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver

ENTRY_SP = 0x7FFF0000


def _setup():
    proj = angr.load_shellcode(b"\x90\xc3", arch="amd64", load_address=0x1000)
    entry = proj.factory.blank_state(addr=0x1000)
    entry.regs.sp = ENTRY_SP
    fake = types.SimpleNamespace(
        project=proj,
        _initial_state=entry,
        artifacts=types.SimpleNamespace(open=lambda *a, **kw: contextlib.nullcontext(io.StringIO())),
    )
    for name in ("_entry_sp", "_call_by_ret_callee"):
        setattr(fake, name, types.MethodType(getattr(CFGVMDeobfuscation, name), fake))
    return fake


def _ret_state(fake, sp_after, jumpkind="Ijk_Ret"):
    state = fake.project.factory.blank_state(addr=0x1000)
    state.register_plugin("partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement()))
    state.regs.sp = sp_after
    state.regs.ip = claripy.BVS("arg0_40", 64, explicit_name=True)
    state.history.jumpkind = jumpkind
    return state


class TestCallByRetCallee(unittest.TestCase):
    def test_stubs_a_pushed_symbolic_target(self):
        fake = _setup()
        # the VM pushed a pointer read from the argument struct below the return address and rets to it
        callee = fake._call_by_ret_callee(_ret_state(fake, ENTRY_SP - 0x10), 0x2538F)
        assert callee is not None and callee != 0
        assert fake.project.is_hooked(callee)
        assert fake.project.hooked_by(callee).display_name == "unresolved_callee_2538f"
        # one stub per ret site
        assert fake._call_by_ret_callee(_ret_state(fake, ENTRY_SP - 0x30), 0x2538F) == callee

    def test_leaves_other_exits_alone(self):
        fake = _setup()
        # the function's own ret pops its return address at the entry sp
        assert fake._call_by_ret_callee(_ret_state(fake, ENTRY_SP + 8), 0x2538F) is None
        assert fake._call_by_ret_callee(_ret_state(fake, ENTRY_SP - 0x10, "Ijk_Boring"), 0x2538F) is None


if __name__ == "__main__":
    unittest.main()
