#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from collections import OrderedDict

import archinfo

import angr
from angr.ailment import Manager
from angr.ailment.expression import BinaryOp, Const, DirtyExpression, Register, UnaryOp
from angr.ailment.statement import CAS, DirtyStatement, WeakAssignment
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.go import GoStructuredCodeGenerator, GoVariable, go_type_str
from angr.go.sim_type import GoSimStruct
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
from angr.sim_variable import SimRegisterVariable
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# what the backend emits for a node it has no handler for
PLACEHOLDER = "unsupported instruction"


def _render(node):
    return "".join(chunk for chunk, _ in node.c_repr_chunks())


class TestGoTypeSpelling(unittest.TestCase):
    ARCH = archinfo.ArchAMD64()

    def test_type_spelling(self):
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

    def test_statement_handlers(self):
        proj = self.proj
        cfg = proj.kb.cfgs.get_most_accurate()
        c_dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg, flavor="pseudocode", fail_fast=True)
        assert isinstance(c_dec.codegen, CStructuredCodeGenerator)

        missing = set(c_dec.codegen._handlers) - set(self.codegen._handlers)
        assert not missing, f"Go backend has no handler for {sorted(str(k) for k in missing)}"

        m = Manager()
        dirty = DirtyExpression(m.next_atom(), "amd64g_dirtyhelper_RDTSC", [], bits=64)
        stmt = DirtyStatement(m.next_atom(), dirty, ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "amd64g_dirtyhelper_RDTSC" in out
        assert PLACEHOLDER not in out

        stmt = WeakAssignment(m.next_atom(), self._reg(m, "rax"), self._reg(m, "rbx"), ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "=" in out
        assert PLACEHOLDER not in out

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

    def test_operator_precedence(self):
        m = Manager()
        regs = {n: self._reg(m, r) for n, r in (("a", "rax"), ("b", "rbx"), ("c", "rcx"))}
        names = {_render(self.codegen._handle(r, is_expr=True)): n for n, r in regs.items()}

        def bop(op, lhs, rhs):
            return BinaryOp(m.next_atom(), op, [lhs, rhs], False, bits=1 if op.startswith("Cmp") else 64)

        def render(expr):
            out = _render(self.codegen._handle(expr, is_expr=True))
            for rendered, name in names.items():
                out = out.replace(rendered, name)
            return out

        a, b, c = regs["a"], regs["b"], regs["c"]
        c63 = Const(m.next_atom(), 63, 64)
        cases = [
            # same level, right nesting: Go is left-associative
            (bop("And", a, bop("Sar", b, c63)), "a & (b >> 63)"),
            (bop("Sar", bop("And", a, b), c63), "a & b >> 63"),
            (bop("Shl", a, bop("Shl", b, c)), "a << (b << c)"),
            (bop("Mul", a, bop("Mod", b, c)), "a * (b % c)"),
            (bop("Sub", a, bop("Add", b, c)), "a - (b + c)"),
            (bop("Add", a, bop("Sub", b, c)), "a + (b - c)"),
            (bop("Or", a, bop("Xor", b, c)), "a | (b ^ c)"),
            (bop("Sub", bop("Sub", a, b), c), "a - b - c"),
            # same associative operator
            (bop("Add", a, bop("Add", b, c)), "a + b + c"),
            (bop("And", a, bop("And", b, c)), "a & b & c"),
            (bop("Xor", a, bop("Xor", b, c)), "a ^ b ^ c"),
            # different levels
            (bop("Add", a, bop("And", b, bop("Sar", c, c63))), "a + b & (c >> 63)"),
            (bop("Mul", bop("Add", a, b), c), "(a + b) * c"),
            (bop("Add", a, bop("Mul", b, c)), "a + b * c"),
            (bop("CmpLT", a, bop("Add", b, c)), "a < b + c"),
            (bop("CmpNE", bop("And", a, b), c), "a & b != c"),
            (bop("LogicalAnd", bop("CmpLT", a, b), bop("CmpLT", b, c)), "a < b && b < c"),
            (bop("CmpEQ", a, bop("CmpEQ", b, c)), "a == (b == c)"),
            # unary operators must not fuse into `--`
            (UnaryOp(m.next_atom(), "Neg", UnaryOp(m.next_atom(), "Neg", a, bits=64), bits=64), "-(-a)"),
            (UnaryOp(m.next_atom(), "Neg", bop("Add", a, b), bits=64), "-(a + b)"),
        ]
        for expr, expected in cases:
            assert render(expr) == expected

    def test_access_before_first_field(self):
        # a struct whose first field sits past offset 0 (e.g. layouts read with go1.18's doubled offsetAnon) once
        # crashed the field lookup with max() over nothing; such loads fall back to pointer arithmetic
        arch = self.proj.arch
        st = GoSimStruct(
            OrderedDict([("a", SimTypeLongLong()), ("b", SimTypeLongLong())]), go_name="main.t", go_size=24
        ).with_arch(arch)
        st.offsets = {"a": 8, "b": 16}
        var = SimRegisterVariable(arch.registers["rdi"][0], 8, name="p")
        ptr = GoVariable(var, variable_type=SimTypePointer(st).with_arch(arch), codegen=self.codegen)
        i64 = SimTypeLongLong().with_arch(arch)

        def access(off):
            return _render(self.codegen._access_constant_offset(ptr, off, i64, False))

        assert access(0) == "*(*int64)(p)"
        assert access(4) == "*(*int64)((*int8)(p) + 4)"
        assert access(8) == "p.a"
        assert access(16) == "p.b"


if __name__ == "__main__":
    unittest.main()
