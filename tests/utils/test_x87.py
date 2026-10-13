#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any

import archinfo
import pyvex

from angr.sim_type import SimTypeInt
from angr.utils.x87 import X87StackModel, X87Tracker


def _ftop_after(arch: archinfo.Arch, code: bytes) -> int | None:
    irsb = pyvex.lift(code, 0x1000, arch, opt_level=1)
    off, size = arch.registers["ftop"]
    tracker = X87Tracker(irsb, 0, off, size, (arch.registers["fpreg"][0], arch.registers["fptag"][0]))
    for stmt in irsb.statements:
        if not tracker.step(stmt):
            break
    return None if tracker.ftop is None else tracker.ftop % 8


class TestX87Tracker(unittest.TestCase):
    def test_push(self):
        # fld1; ret
        assert _ftop_after(archinfo.ArchX86(), b"\xd9\xe8\xc3") == 7

    def test_state_reinitialization_empties_stack(self):
        # fld1; <op> [eax]/fninit; ret
        for arch in (archinfo.ArchX86(), archinfo.ArchAMD64()):
            for op in (b"\xdd\x30", b"\xdb\xe3"):  # fnsave, fninit
                assert _ftop_after(arch, b"\xd9\xe8" + op + b"\xc3") == 0, (arch.name, op.hex())


class TestX87StackModel(unittest.TestCase):
    def test_deep_callee_chain(self):
        class FunctionManager:
            def __init__(self):
                self.functions = {}

            def function(self, addr):
                return self.functions.get(addr)

            def contains_addr(self, addr):
                return addr in self.functions

        class Factory:
            def __init__(self, functions):
                self.functions = functions

            def block(self, addr, size=None):  # pylint: disable=unused-argument
                jumpkind = "Ijk_Ret" if self.functions[addr].call_target is None else "Ijk_Call"
                return SimpleNamespace(vex=SimpleNamespace(statements=(), jumpkind=jumpkind))

        class Function:
            def __init__(self, addr, call_target):
                self.addr = addr
                self.call_target = call_target
                self.block_addrs_set = {addr}
                self.prototype = SimpleNamespace(returnty=SimTypeInt())
                self.calling_convention = None
                self.is_simprocedure = False
                self.is_plt = False
                self.graph = SimpleNamespace(successors=lambda _: ())
                self.transition_graph = SimpleNamespace(out_edges=lambda *_, **__: ())
                self.node = SimpleNamespace(addr=addr, size=1)

            def get_node(self, addr):
                return self.node if addr == self.addr else None

            def get_call_target(self, addr):
                return self.call_target if addr == self.addr else None

        manager = FunctionManager()
        addresses = [0x1000 + i * 0x10 for i in range(2000)]
        manager.functions = {
            addr: Function(addr, addresses[i + 1] if i + 1 < len(addresses) else None)
            for i, addr in enumerate(addresses)
        }
        project: Any = SimpleNamespace(arch=archinfo.ArchX86())
        project.factory = Factory(manager.functions)
        kb: Any = SimpleNamespace(functions=manager)
        model = X87StackModel(project, kb, max_blocks=1, max_callee_blocks=1)

        root: Any = manager.functions[addresses[0]]
        assert model.scan(root) == ({}, 0)


if __name__ == "__main__":
    unittest.main()
