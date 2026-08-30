#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from types import SimpleNamespace

import angr
from angr.ailment import Expr, Stmt
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpression,
    CGoto,
    CStructuredCodeGenerator,
    CUnaryOp,
    type_to_c_repr_chunks,
)
from angr.sim_type import (
    SimCppClass,
    SimTypeBottom,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
    parse_cpp_file,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _RenderedExpression(CExpression):
    def __init__(self, text, ty=None, *, codegen):
        super().__init__(codegen=codegen)
        self.text = text
        self._type = ty

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield self.text, self


class TestConvertRendering(unittest.TestCase):
    """How CStructuredCodeGenerator renders Convert expressions of assorted widths."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        cls.codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen

    def _render(self, from_bits: int, to_bits: int, value: int = 0x1234) -> str:
        conv = Expr.Convert(0, from_bits, to_bits, False, Expr.Const(0, value, from_bits))
        return self.codegen._handle(conv).c_repr()

    def test_truncation_to_unrepresentable_width_is_masked(self):
        # No C type is 5, 3 or 1 bits wide. A cast would round up to the next real type and keep
        # bits the conversion discards, so these have to be spelled as a mask instead.
        assert self._render(32, 5) == "4660 & 31"
        assert self._render(32, 3) == "4660 & 7"
        assert self._render(32, 1) == "4660 & 1"

    def test_truncation_to_representable_width_is_a_cast(self):
        assert self._render(32, 8) == "(char)4660"
        assert self._render(32, 16) == "(unsigned short)4660"

    def test_widening_is_always_a_cast(self):
        # Rounding up only loses information when truncating, so widening keeps casting even to a
        # width no C type has.
        assert self._render(1, 5, value=1) == "(char)1"
        assert self._render(8, 12, value=3) == "(unsigned short)3"
        assert self._render(32, 64, value=3) == "(unsigned long long)3"


class TestGotoRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codegen = SimpleNamespace(
            comment_gotos=False,
            map_addr_to_label={},
            next_ident=lambda name: name,
            next_node_idx=lambda: 0,
        )

    def test_integer_and_pointer_targets_are_cast_to_void_pointer(self):
        target_types = {
            "integer_target": SimTypeInt(signed=False),
            "pointer_target": SimTypePointer(SimTypeInt(signed=False)),
        }

        for name, target_type in target_types.items():
            with self.subTest(target_type=name):
                target = _RenderedExpression(name, target_type, codegen=self.codegen)
                chunks = list(CGoto(target, None, codegen=self.codegen).c_repr_chunks())

                self.assertEqual("".join(text for text, _ in chunks), f"goto *((void *)({name}));\n")
                self.assertIn((name, target), chunks)

    def test_computed_goto_preserves_dereferenced_target(self):
        target = CUnaryOp("Dereference", _RenderedExpression("target", codegen=self.codegen), codegen=self.codegen)
        chunks = CGoto(target, None, codegen=self.codegen).c_repr_chunks()

        self.assertEqual("".join(text for text, _ in chunks), "goto *((void *)(*(target)));\n")

    def test_constant_jump_is_a_direct_goto(self):
        chunks = CGoto(0x400000, None, codegen=self.codegen).c_repr_chunks()

        self.assertEqual("".join(text for text, _ in chunks), "goto LABEL_0x400000;\n")


class TestStoreWidth(unittest.TestCase):
    """A store's emitted C must write as many bytes as the AIL store writes."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

    def _dst_bits(self, idx: int, value_type, value_bits: int, size: int) -> int:
        # the destination is what _access renders as *(T*)addr, so its type is the width written
        data = Expr.Const(idx, 0, value_bits, type=value_type)
        stmt = Stmt.Store(idx, Expr.Const(idx, 0x400000, 64), data, size, "Iend_LE")
        assignment = self.codegen._handle(stmt, is_expr=False)
        assert isinstance(assignment, CAssignment)
        assert assignment.lhs.type is not None
        return assignment.lhs.type.size

    def test_value_typed_narrower_than_the_store(self):
        assert self._dst_bits(1, SimTypeInt(signed=False), 64, 8) == 64

    def test_value_typed_wider_than_the_store(self):
        assert self._dst_bits(2, SimTypeLongLong(signed=False), 8, 1) == 8

    def test_value_with_no_inferred_type(self):
        assert self._dst_bits(3, SimTypeBottom(), 128, 16) == 128

    def test_value_typed_correctly_is_left_alone(self):
        assert self._dst_bits(4, SimTypeLongLong(signed=False), 64, 8) == 64


class TestClassDefinitionRendering(unittest.TestCase):
    """How type_to_c_repr_chunks spells the class-key of a rendered C++ class definition."""

    @staticmethod
    def _render(ty) -> str:
        return "".join(text for text, _ in type_to_c_repr_chunks(ty, full=True))

    def test_elaborated_class_name_keeps_one_class_key(self):
        # angr's own C++ parser keeps the class-key in the name on its class branch, so the
        # definition used to come out as "class class DemoNs::DemoType".
        decls, _ = parse_cpp_file("void f(class DemoNs::DemoType *p);", with_param_names=True)
        assert decls is not None
        prototype = decls["f"]
        assert isinstance(prototype, SimTypeFunction)
        pointer = prototype.args[0]
        assert isinstance(pointer, SimTypePointer)
        ty = pointer.pts_to
        assert isinstance(ty, SimCppClass)
        assert ty.name == "class DemoNs::DemoType"
        assert self._render(ty) == "class DemoNs::DemoType {\n} DemoNs::DemoType;\n\n"

    def test_plain_class_name_is_unchanged(self):
        ty = SimCppClass(unique_name="DemoNs::DemoType", name="DemoNs::DemoType", members={"x": SimTypeInt()})
        assert self._render(ty) == "class DemoNs::DemoType {\n    int x;\n} DemoNs::DemoType;\n\n"


if __name__ == "__main__":
    unittest.main()
