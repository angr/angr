#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.ailment import Manager
from angr.ailment.expression import Const, DirtyExpression, Register
from angr.ailment.statement import CAS, DirtyStatement, WeakAssignment
from angr.analyses.decompiler.structured_codegen.go import GoStructuredCodeGenerator, go_type_str
from angr.sim_type import (
    SimStruct,
    SimTypeBottom,
    SimTypeChar,
    SimTypeDouble,
    SimTypeFixedSizeArray,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypePointer,
    SimTypeShort,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# what the backend emits for a node it has no handler for
PLACEHOLDER = "unsupported instruction"


def _render(node):
    return "".join(chunk for chunk, _ in node.c_repr_chunks())


class TestGoTypeSpelling(unittest.TestCase):
    ARCH = archinfo.ArchAMD64()

    def test_scalars(self):
        arch = self.ARCH
        assert go_type_str(SimTypeChar(signed=False).with_arch(arch)) == "byte"
        assert go_type_str(SimTypeChar(signed=True).with_arch(arch)) == "int8"
        assert go_type_str(SimTypeShort(signed=True).with_arch(arch)) == "int16"
        assert go_type_str(SimTypeInt(signed=False).with_arch(arch)) == "uint32"
        assert go_type_str(SimTypeLongLong(signed=True).with_arch(arch)) == "int64"
        assert go_type_str(SimTypeFloat().with_arch(arch)) == "float32"
        assert go_type_str(SimTypeDouble().with_arch(arch)) == "float64"
        assert go_type_str(SimTypeBottom(label="void")) == "any"
        # arch-less widths degrade to the untyped spelling instead of raising
        assert go_type_str(SimTypeShort(signed=True)) == "int"

    def test_composites(self):
        arch = self.ARCH
        assert go_type_str(SimTypePointer(SimTypeInt(signed=True)).with_arch(arch)) == "*int32"
        assert go_type_str(SimTypePointer(SimTypeBottom(label="void")).with_arch(arch)) == "unsafe.Pointer"
        assert go_type_str(SimTypeFixedSizeArray(SimTypeChar(signed=False), 16).with_arch(arch)) == "[16]byte"
        s = SimStruct({"x": SimTypeLong(signed=True), "y": SimTypeLong(signed=True)}, name="point").with_arch(arch)
        assert go_type_str(s) == "point"
        assert go_type_str(SimTypePointer(s)) == "*point"
        f = SimTypeFunction([SimTypeInt(signed=True)], SimTypeLongLong(signed=True)).with_arch(arch)
        assert go_type_str(SimTypePointer(f).with_arch(arch)) == "func(int32) int64"
        assert go_type_str(SimTypeFunction([], SimTypeBottom(label="void"))) == "func()"


class TestGoCodegenHandlers(unittest.TestCase):
    """
    _handle_AILBlock() substitutes a placeholder for any statement the backend has no handler for, so a missing
    handler silently drops whatever the statement contained.
    """

    @classmethod
    def setUpClass(cls):
        # any binary will do: we only need a constructed Go code generator to drive handlers with
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model, flavor="go", fail_fast=True)
        assert dec.codegen is not None
        assert isinstance(dec.codegen, GoStructuredCodeGenerator)
        cls.proj = proj
        cls.codegen = dec.codegen

    def _reg(self, m, name, bits=64):
        offset = self.proj.arch.registers[name][0]
        return Register(m.next_atom(), offset, bits, reg_name=name)

    def test_handler_table_covers_everything_the_c_backend_covers(self):
        proj = self.proj
        cfg = proj.kb.cfgs.get_most_accurate()
        c_dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg, flavor="pseudocode", fail_fast=True)
        assert c_dec.codegen is not None

        missing = set(c_dec.codegen._handlers) - set(self.codegen._handlers)
        assert not missing, f"Go backend has no handler for {sorted(str(k) for k in missing)}"

    def test_dirty_statement(self):
        m = Manager()
        dirty = DirtyExpression(m.next_atom(), "amd64g_dirtyhelper_RDTSC", [], bits=64)
        stmt = DirtyStatement(m.next_atom(), dirty, ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "amd64g_dirtyhelper_RDTSC" in out
        assert PLACEHOLDER not in out

    def test_weak_assignment(self):
        m = Manager()
        stmt = WeakAssignment(m.next_atom(), self._reg(m, "rax"), self._reg(m, "rbx"), ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "=" in out
        assert PLACEHOLDER not in out

    def test_cas(self):
        m = Manager()
        stmt = CAS(
            m.next_atom(),
            Const(m.next_atom(), 0x1000, 64),
            Const(m.next_atom(), 1, 32),
            None,
            Const(m.next_atom(), 0, 32),
            None,
            self._reg(m, "eax", bits=32),
            None,
            "Iend_LE",
            ins_addr=0x400100,
        )

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "atomic_compare_exchange" in out
        assert PLACEHOLDER not in out


if __name__ == "__main__":
    unittest.main()
