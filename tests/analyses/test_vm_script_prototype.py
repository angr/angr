#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

import archinfo

import angr
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.analyses.vm_deobfuscation.vm_deobfuscation import _hooked_callee_prototype, _script_prototype
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeTop


class TestScriptPrototype(unittest.TestCase):
    def setUp(self):
        self.arch = archinfo.ArchX86()
        # how an evaluation script declares a void callee
        self.void_proto = SimTypeFunction([SimTypePointer(SimTypeTop(), label="heap_t *"), SimTypeInt()], None)

    def test_none_returnty_becomes_void(self):
        proto = _script_prototype(self.void_proto, self.arch)
        assert isinstance(proto.returnty, SimTypeBottom)
        assert proto._arch is not None and proto._arch.name == self.arch.name
        assert all(a._arch is not None for a in proto.args)
        # the script's object is left alone
        assert self.void_proto.returnty is None
        assert _script_prototype(None, self.arch) is None

    def test_hooked_callee_prototype_none_returnty(self):
        hook = angr.SIM_PROCEDURES["stubs"]["Nop"](
            cc=angr.calling_conventions.SimCCCdecl(self.arch), prototype=self.void_proto
        )
        proto = _hooked_callee_prototype(hook, self.arch)
        assert isinstance(proto.returnty, SimTypeBottom)
        assert len(proto.args) == 2

    def test_call_expression_type_of_void_callee(self):
        callee = types.SimpleNamespace(prototype=self.void_proto.with_arch(self.arch))
        codegen = types.SimpleNamespace(next_ident=lambda name: name, next_node_idx=lambda: 0)
        call = CFunctionCall(0x402350, callee, [], codegen=codegen)
        assert isinstance(call.type, SimTypeBottom)


if __name__ == "__main__":
    unittest.main()
