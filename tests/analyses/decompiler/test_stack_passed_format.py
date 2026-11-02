#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Format strings passed on the stack (i386 cdecl) determine the variadic arguments of a call."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import Call, Const, StackBaseOffset
from angr.ailment.statement import SideEffectStatement, Store
from angr.analyses.decompiler.callsite_maker import CallSiteMaker
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestStackPassedFormat(unittest.TestCase):
    """i386 cdecl passes the format on the stack."""

    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(test_location, "i386", "test_loops")

    def _decompile(self, vm: bool, callee_proto=None):
        proj = angr.Project(self.path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        if callee_proto is not None:
            for func in list(cfg.kb.functions.values()):
                if func.name == "printf":
                    # not a printf-like name: the variadic arguments cannot be determined
                    func.name = "vlog"
                    func.prototype = callee_proto.with_arch(proj.arch)
        dec = proj.analyses.Decompiler(cfg.kb.functions["main"], cfg=cfg.model, vm_deobfuscation=vm, fail_fast=True)
        assert dec.codegen is not None
        loop = re.search(r"for \(j = 0;.*?\n    }", dec.codegen.text, re.DOTALL)
        assert loop is not None, dec.codegen.text
        return loop.group(0)

    def test_constant_stack_format_gets_its_arguments(self):
        for vm in (False, True):
            loop = self._decompile(vm)
            assert re.search(r'printf\("%d ", [^,;]+\[j\]\);', loop), loop


class TestStackStoreInBlock(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "X86")
        self.m = ailment.Manager()

    def _csm(self, statements):
        csm = CallSiteMaker.__new__(CallSiteMaker)
        csm.project = self.proj
        csm.block = Block(0x1000, 16, statements=statements)
        return csm

    def _store(self, off, value, size=4):
        return Store(
            self.m.next_atom(),
            StackBaseOffset(self.m.next_atom(), 32, off),
            Const(self.m.next_atom(), value, 32),
            size,
            "Iend_LE",
            ins_addr=0x1000,
        )

    def _call(self):
        return SideEffectStatement(
            self.m.next_atom(), Call(self.m.next_atom(), Const(self.m.next_atom(), 0x2000, 32)), ins_addr=0x100C
        )

    def test_finds_last_store(self):
        csm = self._csm([self._store(-8, 1), self._store(-12, 2), self._store(-8, 3), self._call()])
        assert csm._stack_store_data_in_block(-8, 4).value == 3

    def test_overlapping_store_or_call_in_between(self):
        csm = self._csm([self._store(-8, 1), self._store(-6, 2, size=1), self._call()])
        assert csm._stack_store_data_in_block(-8, 4) is None
        csm = self._csm([self._store(-8, 1), self._call(), self._call()])
        assert csm._stack_store_data_in_block(-8, 4) is None


if __name__ == "__main__":
    unittest.main()
