#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

import archinfo

import angr
from angr.analyses.vm_deobfuscation.vm_deobfuscation import _hooked_callee_prototype
from angr.procedures.definitions import msvcr as msvcr_defs
from angr.sim_type import PointerDisposition, SimTypePointer


class TestHookedCalleePrototype(unittest.TestCase):
    def setUp(self):
        angr.procedures.definitions.load_win32api_definitions()
        self.arch = archinfo.ArchX86()

    def test_drops_pointer_dispositions(self):
        hook = angr.SIM_LIBRARIES.get("ws2_32.dll")[0].get_stub("select", self.arch)
        before = [a.disposition for a in hook.prototype.args if isinstance(a, SimTypePointer)]
        assert any(d != PointerDisposition.UNKNOWN for d in before)

        proto = _hooked_callee_prototype(hook, self.arch)
        assert len(proto.args) == len(hook.prototype.args)
        assert all(a.disposition == PointerDisposition.UNKNOWN for a in proto.args if isinstance(a, SimTypePointer))
        # the hook keeps its own prototype
        assert [a.disposition for a in hook.prototype.args if isinstance(a, SimTypePointer)] == before

    def test_guessed_stub_uses_library_declaration(self):
        msvcr_defs.publish_procedure_prototypes()
        guessed = angr.sim_type.SimTypeFunction([], angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar()))
        hook = types.SimpleNamespace(
            prototype=guessed, guessed_prototype=True, library_name="msvcr100.dll", display_name="memset"
        )
        proto = _hooked_callee_prototype(hook, self.arch)
        assert len(proto.args) == 3
        assert proto._arch is not None and proto._arch.name == self.arch.name

    def test_no_prototype(self):
        assert _hooked_callee_prototype(types.SimpleNamespace(prototype=None), self.arch) is None


if __name__ == "__main__":
    unittest.main()
