#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import os
import re
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import archinfo

import angr
from angr.ailment import Expr, Stmt
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CGoto,
    CReturn,
    CStructField,
    CStructuredCodeGenerator,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
    c_return_type,
    qualifies_for_simple_cast,
    type_layout_key,
    type_to_c_repr_chunks,
)
from angr.calling_conventions import SimComboArg
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimUnion,
    TypeRef,
    parse_cpp_file,
)
from angr.sim_variable import SimRegisterVariable
from tests.common import WORKER, bin_location, load_project_with_scoped_cfg, print_decompilation_result

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

    codegen: CStructuredCodeGenerator

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

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

    def test_widening_sizeless_child_uses_ail_source_width(self):
        unknown_type = SimTypeBottom().with_arch(self.codegen.project.arch)
        child = CBinaryOp(
            "Shr",
            CConstant(1, unknown_type, codegen=self.codegen),
            CConstant(2, unknown_type, codegen=self.codegen),
            codegen=self.codegen,
        )
        assert child.type.size is None

        conv = Expr.Convert(0, 1, 64, True, Expr.Const(0, 1, 1))
        with patch.object(self.codegen, "_handle", return_value=child):
            rendered = self.codegen._handle_Expr_Convert(conv)

        assert isinstance(rendered, CTypeCast)
        assert isinstance(rendered.expr, CTypeCast)
        assert rendered.expr.dst_type.size == conv.from_bits
        assert getattr(rendered.expr.dst_type, "signed", None) is True
        assert rendered.c_repr() == "(long long)(int1_t)(1 >> 2)"

    def test_widening_zero_width_child_uses_ail_source_width(self):
        fieldless_type = SimStruct({}, name="fieldless").with_arch(self.codegen.project.arch)
        child = CConstant(1, fieldless_type, codegen=self.codegen)
        assert child.type.size == 0

        conv = Expr.Convert(0, 32, 64, True, Expr.Const(0, 1, 32))
        with patch.object(self.codegen, "_handle", return_value=child):
            rendered = self.codegen._handle_Expr_Convert(conv)

        assert isinstance(rendered, CTypeCast)
        assert isinstance(rendered.expr, CTypeCast)
        assert rendered.expr.dst_type.size == conv.from_bits
        assert getattr(rendered.expr.dst_type, "signed", None) is True
        assert rendered.c_repr() == "(long long)(int)1"

    def test_widening_known_child_keeps_inferred_width(self):
        known_type = self.codegen.default_simtype_from_bits(16, signed=False)
        child = CConstant(1, known_type, codegen=self.codegen)
        conv = Expr.Convert(0, 32, 64, True, Expr.Const(0, 1, 32))
        with patch.object(self.codegen, "_handle", return_value=child):
            rendered = self.codegen._handle_Expr_Convert(conv)

        assert isinstance(rendered, CTypeCast)
        assert isinstance(rendered.expr, CTypeCast)
        assert rendered.expr.dst_type.size == known_type.size
        assert getattr(rendered.expr.dst_type, "signed", None) is True
        assert rendered.c_repr() == "(long long)(short)1"


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


class TestDereferenceRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = angr.load_shellcode(b"\xc3", arch="x86")
        cfg = project.analyses.CFGFast(normalize=True)
        codegen = project.analyses.Decompiler(0, cfg=cfg.model).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

    def _var(self, name: str, ty: SimType) -> CVariable:
        return CVariable(SimRegisterVariable(0, 4, name=name), variable_type=ty, codegen=self.codegen)

    def test_operand_is_parenthesized_only_when_precedence_requires_it(self):
        arch = self.codegen.project.arch
        int_t = SimTypeInt().with_arch(arch)
        int_p = SimTypePointer(int_t).with_arch(arch)
        char_p = SimTypePointer(SimTypeChar()).with_arch(arch)
        struct_t = SimStruct({"q": int_p}, name="S").with_arch(arch)
        p = self._var("p", int_p)
        pp = self._var("pp", SimTypePointer(int_p).with_arch(arch))
        x = self._var("x", int_t)
        s = self._var("s", SimTypePointer(struct_t).with_arch(arch))
        one = CConstant(1, int_t, codegen=self.codegen)
        p_plus_one = CBinaryOp("Add", p, one, codegen=self.codegen)
        q = CVariableField(
            s, CStructField(struct_t, 0, "q", codegen=self.codegen), var_is_ptr=True, codegen=self.codegen
        )

        def deref(operand: CExpression) -> CUnaryOp:
            return CUnaryOp("Dereference", operand, codegen=self.codegen)

        for operand, text in (
            (p, "*p"),
            (deref(pp), "**pp"),
            (q, "*s->q"),
            (CUnaryOp("Reference", x, codegen=self.codegen), "*&x"),
            (CTypeCast(int_p, char_p, p, codegen=self.codegen), "*(char *)p"),
            (CTypeCast(int_p, char_p, p_plus_one, codegen=self.codegen), "*(char *)(p + 1)"),
            (p_plus_one, "*(p + 1)"),
            (CITE(x, p, p, codegen=self.codegen), "*(x ? p : p)"),
            (_RenderedExpression("opaque", codegen=self.codegen), "*(opaque)"),
        ):
            with self.subTest(text=text):
                assert deref(operand).c_repr() == text

    def test_sign_operators_parenthesize_only_binary_and_same_operator_operands(self):
        arch = self.codegen.project.arch
        int_t = SimTypeInt().with_arch(arch)
        x = self._var("x", int_t)
        y = self._var("y", int_t)
        one = CConstant(1, int_t, codegen=self.codegen)
        minus_one = CConstant(-1, int_t, codegen=self.codegen)
        x_plus_y = CBinaryOp("Add", x, y, codegen=self.codegen)

        def unary(op: str, operand: CExpression) -> CUnaryOp:
            return CUnaryOp(op, operand, codegen=self.codegen)

        for op, operand, text in (
            ("Neg", x, "-x"),
            ("Neg", x_plus_y, "-(x + y)"),
            ("Neg", unary("Neg", x), "-(-x)"),
            ("Neg", unary("BitwiseNeg", x), "-~x"),
            ("Neg", one, "-(1)"),
            ("Neg", minus_one, "-(-1)"),
            ("BitwiseNeg", x, "~x"),
            ("BitwiseNeg", x_plus_y, "~(x + y)"),
            ("BitwiseNeg", unary("BitwiseNeg", x), "~(~x)"),
            ("BitwiseNeg", unary("Neg", x), "~-x"),
            ("BitwiseNeg", one, "~1"),
            ("Not", x, "!x"),
            ("Not", x_plus_y, "!(x + y)"),
            ("Not", unary("Not", x), "!!x"),
            ("Not", CITE(x, x, y, codegen=self.codegen), "!(x ? x : y)"),
            ("Dereference", unary("Neg", x), "*-x"),
        ):
            with self.subTest(text=text):
                assert unary(op, operand).c_repr() == text

    def test_decompiled_dereferences_have_no_redundant_parentheses(self):
        # MSVC-inlined strlen/memcpy: "*(v)" loop guards and "*((char *)v)" byte copies
        bin_path = os.path.join(
            test_location, "i386", "windows", "9f2ef84bde1e4ef445708cc5a605a09226363d502b1f5b5bf4a1cfc6dd5fc41e"
        )
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x401D60, project_kwargs={"auto_load_libs": False}, expand_call_tree=False, run_ccc=False
        )
        dec = proj.analyses[angr.analyses.Decompiler].prep(fail_fast=True)(cfg.functions[0x401D60], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        assert re.search(r"\(v\d+ -= 1, v\d+ = v\d+ \+ 1, \*v\d+\)\);", t) is not None
        assert "*(char *)g_407728" in t
        assert "*(int *)" in t
        assert "*((" not in t
        assert re.search(r"\*\(v\d+\)", t) is None


class TestRightShiftRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = angr.load_shellcode(b"\xc3", arch="x86")
        cfg = project.analyses.CFGFast(normalize=True)
        codegen = project.analyses.Decompiler(0, cfg=cfg.model).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

    def test_shift_signedness_is_local_to_the_operand(self):
        for type_class, width in ((SimTypeInt, 32), (SimTypeLongLong, 64)):
            for signed in (False, True):
                for op in ("Shr", "Sar"):
                    for alias in (False, True):
                        with self.subTest(width=width, signed=signed, op=op, alias=alias):
                            value_type = type_class(signed=signed).with_arch(self.codegen.project.arch)
                            if alias:
                                value_type = TypeRef("status_t", value_type)
                            lhs = _RenderedExpression("status()", value_type, codegen=self.codegen)
                            rhs = _RenderedExpression(str(width - 1), value_type, codegen=self.codegen)
                            expression = CBinaryOp(op, lhs, rhs, codegen=self.codegen)
                            desired_signed = op == "Sar"
                            if signed != desired_signed:
                                cast = type_class(signed=desired_signed).c_repr()
                                expected = f"({cast})(status()) >> {width - 1}"
                            else:
                                expected = f"status() >> {width - 1}"
                            assert expression.c_repr() == expected
                            assert lhs.type is value_type

    def test_cast_preserves_shift_count_parentheses(self):
        value_type = SimTypeInt(signed=True).with_arch(self.codegen.project.arch)
        lhs = _RenderedExpression("status()", value_type, codegen=self.codegen)
        amount = _RenderedExpression("amount", value_type, codegen=self.codegen)
        mask = _RenderedExpression("31", value_type, codegen=self.codegen)
        rhs = CBinaryOp("And", amount, mask, codegen=self.codegen)
        expression = CBinaryOp("Shr", lhs, rhs, codegen=self.codegen)
        assert expression.c_repr() == "(unsigned int)(status()) >> (amount & 31)"

    def test_same_precedence_rhs_is_parenthesized(self):
        # a < (b < c) and a << (b << c) are not a < b < c / a << b << c; a + (b + c) needs no parentheses
        value_type = SimTypeInt(signed=False).with_arch(self.codegen.project.arch)
        a, b, c = (_RenderedExpression(n, value_type, codegen=self.codegen) for n in "abc")
        for op, text in (
            ("CmpLT", "a < (b < c)"),
            ("CmpEQ", "a == (b == c)"),
            ("Shl", "a << (b << c)"),
            ("Add", "a + b + c"),
        ):
            with self.subTest(op=op):
                rhs = CBinaryOp(op, b, c, codegen=self.codegen)
                assert CBinaryOp(op, a, rhs, codegen=self.codegen).c_repr() == text

    def test_decompile_signed_call_logical_shift(self):
        for directory, type_class, width in (
            ("i386", SimTypeInt, 32),
            ("x86_64/decompiler", SimTypeLongLong, 64),
        ):
            with self.subTest(width=width):
                project = angr.Project(
                    os.path.join(test_location, directory, "right_shift_signed_calls"), auto_load_libs=False
                )
                cfg = project.analyses.CFGFast(normalize=True)
                source = cfg.kb.functions[f"signed_status{width}"]
                prototype = SimTypeFunction([], type_class(signed=True)).with_arch(project.arch)
                assert isinstance(prototype, SimTypeFunction)
                source.prototype = prototype
                source.calling_convention = project.factory.cc()
                result = project.analyses[angr.analyses.Decompiler].prep(fail_fast=True)(
                    cfg.kb.functions[f"logical{width}"], cfg=cfg.model
                )
                assert result.codegen is not None and result.codegen.text is not None
                text = result.codegen.text
                cast = type_class(signed=False).c_repr()
                assert f"({cast})(signed_status{width}()) >> {width - 1}" in text
                assert text.count(f"signed_status{width}(") == 1
                assert source.prototype == prototype
                assert not result.structuring_failures


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


class TestAnonymousAggregateRendering(unittest.TestCase):
    """How type_to_c_repr_chunks renders anonymous aggregates that contain themselves."""

    @staticmethod
    def _render(ty) -> str:
        return "".join(text for text, _ in type_to_c_repr_chunks(ty, full=True))

    def test_nested_anonymous_structs_are_rendered_inline(self):
        inner = SimStruct({"x": SimTypeInt()}, name="<anon>")
        middle = SimStruct({"deep": inner}, name="<anon>")
        outer = SimStruct({"mid": middle, "y": SimTypeInt()}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    struct {\n"
            "        struct {\n"
            "            int x;\n"
            "        } deep;\n"
            "    } mid;\n"
            "    int y;\n"
            "} outer;\n\n"
        )

    def test_a_reused_anonymous_struct_is_rendered_in_full_each_time(self):
        # only the enclosing aggregates count as a cycle: the same object used by two sibling
        # fields is rendered twice, in full
        anon = SimStruct({"x": SimTypeInt()}, name="<anon>")
        outer = SimStruct({"a": anon, "b": anon}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    struct {\n"
            "        int x;\n"
            "    } a;\n"
            "    struct {\n"
            "        int x;\n"
            "    } b;\n"
            "} outer;\n\n"
        )

    def test_self_referential_anonymous_struct_terminates(self):
        # Type inference can hand codegen an anonymous aggregate that reaches itself. Anonymous
        # aggregates are rendered inline, so there is no name to refer back to and the render
        # descended until the interpreter stopped it.
        anon = SimStruct({}, name="<anon>")
        anon.fields["loop"] = anon
        anon.fields["x"] = SimTypeInt()
        outer = SimStruct({"mid": anon}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    struct {\n"
            "        struct { /* recursive */ } loop;\n"
            "        int x;\n"
            "    } mid;\n"
            "} outer;\n\n"
        )

    def test_self_referential_anonymous_union_terminates(self):
        anon = SimUnion({}, name="<anon>")
        anon.members["loop"] = anon
        anon.members["x"] = SimTypeInt()
        outer = SimStruct({"mid": anon}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    union {\n"
            "        union { /* recursive */ } loop;\n"
            "        int x;\n"
            "    } mid;\n"
            "} outer;\n\n"
        )


class TestMultiRegisterReturn(unittest.TestCase):
    """A return value the calling convention splits across registers must reach the C in one piece."""

    # _handle memoizes on the AIL node, so every node any test builds needs an idx of its own
    _idx = itertools.count(1)

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

    def setUp(self):
        self._original_prototype = self.codegen._func.prototype

    def tearDown(self):
        self.codegen._func.prototype = self._original_prototype

    def _set_returnty(self, returnty) -> None:
        self.codegen._func.prototype = SimTypeFunction([], returnty)

    def _render(self, *pieces: Expr.Expression) -> str:
        stmt = Stmt.Return(next(self._idx), list(pieces))
        rendered = self.codegen._handle(stmt, is_expr=False)
        assert isinstance(rendered, CReturn)
        return rendered.c_repr().strip()

    def _const(self, value: int, bits: int) -> Expr.Const:
        return Expr.Const(next(self._idx), value, bits, type=SimTypeNum(bits, signed=False))

    def test_no_return_expression_is_a_bare_return(self):
        assert self._render() == "return;"

    def test_one_return_expression_is_unchanged(self):
        assert self._render(self._const(1, 64)) == "return 1;"

    def test_two_registers_are_concatenated_most_significant_first(self):
        # SimComboArg lists its locations least significant first, so the second expression is the high half
        # and Concat, which puts the high half first, takes it first.
        self._set_returnty(SimTypeNum(128, signed=True))
        assert self._render(self._const(1, 64), self._const(2, 64)) == "return CONCAT(2, 1);"

    def test_more_than_two_pieces_are_all_placed(self):
        self._set_returnty(SimTypeNum(96, signed=True))
        assert (
            self._render(self._const(1, 32), self._const(2, 32), self._const(3, 32))
            == "return CONCAT(3, CONCAT(2, 1));"
        )

    def test_an_aggregate_return_type_keeps_the_old_conservative_behaviour(self):
        # a homogeneous float aggregate spread over several registers is not a scalar with a high and a low
        # half, so the pieces must not be concatenated. angr/angr#6851 tracks carrying those through as one
        # typed value.
        self._set_returnty(SimStruct({"a": SimTypeFloat(), "b": SimTypeFloat()}))
        with self.assertLogs("angr.analyses.decompiler.structured_codegen.c", level="WARNING"):
            assert self._render(self._const(1, 32), self._const(2, 32)) == "return 1;"

    def test_a_return_type_that_does_not_account_for_every_piece_keeps_the_old_behaviour(self):
        # the decompiler rewrites the prototype after ReturnMaker has filled the return expressions in, so a
        # 64-bit return type beside two 64-bit expressions means the extra expression is not part of it.
        self._set_returnty(SimTypeLongLong(signed=False))
        with self.assertLogs("angr.analyses.decompiler.structured_codegen.c", level="WARNING"):
            assert self._render(self._const(1, 64), self._const(2, 64)) == "return 1;"

    def test_a_missing_prototype_keeps_the_old_behaviour(self):
        self.codegen._func.prototype = None
        with self.assertLogs("angr.analyses.decompiler.structured_codegen.c", level="WARNING"):
            assert self._render(self._const(1, 64), self._const(2, 64)) == "return 1;"


class TestMultiRegisterReturnEndToEnd(unittest.TestCase):
    """The two-word value a Go function returns in rax:rbx must survive into the C."""

    def test_a_two_word_go_return_keeps_its_high_half(self):
        # runtime.decoderune is Go's func decoderune(s string, k int) (r rune, size int). It recovers a 128-bit
        # return type, so SimCC.return_val answers SimComboArg([<rax>, <rbx>]) and ReturnMaker gives every return
        # two expressions. The C used to declare int128_t and return only rax, losing every decoded size.
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)
        # decoderune plus one of its callers: the return type comes out of call-site analysis, so a region
        # holding the function alone recovers it as void
        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            start_at_entry=False,
            regions=[(0x45B220, 0x45B220 + 0x200), (0x4ADEE0, 0x4ADEE0 + 0x200)],
        )
        func = cfg.functions[0x45B220]
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None
        print_decompilation_result(dec)

        prototype = func.prototype
        assert prototype is not None and prototype.returnty is not None
        assert prototype.returnty.size == 128
        cc = func.calling_convention
        assert cc is not None
        return_val = cc.return_val(prototype.returnty)
        assert isinstance(return_val, SimComboArg)
        assert len(return_val.locations) == 2

        # every return carries the second location's value instead of dropping it
        text = dec.codegen.text or ""
        returns = [line.strip() for line in text.splitlines() if line.strip().startswith("return ")]
        assert len(returns) == 6
        for line in returns:
            assert re.match(r"^return CONCAT\(.+, .+\);$", line), line
        # decoderune's error path is Go's `return RuneError, 1`, so rax holds 0xfffd and rbx the size.
        # rbx is the second location, which is the high half, so it is the first operand.
        assert "return CONCAT(a2 + 1, 0xfffd);" in text, text


class TestConvertOfZeroWidthChild(unittest.TestCase):
    """A widening cast whose child is rendered with a type that has no width."""

    def test_widening_a_child_typed_as_a_fieldless_struct(self):
        # Go's runtime.setThreadCPUProfiler calls timer_create, and the kernel prototype spells that
        # syscall's second argument as SimStruct({}, name="sigevent"). A struct with no fields has
        # size 0, so a stack variable reaches the code generator with a type whose size is 0 rather
        # than None. The intermediate sign-extension cast then asked for an integer of that width and
        # got int0_t, and MakeTypecastsImplicit.collapse asserted on its size, so the whole function
        # produced no C at all.
        bin_path = os.path.join(test_location, "x86_64", "langdetect_go")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x430CA0, project_kwargs={"auto_load_libs": False})

        dec = proj.analyses.Decompiler(cfg.functions[0x430CA0], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None
        print_decompilation_result(dec)

        text = dec.codegen.text or ""
        assert text.strip()
        assert "int0_t" not in text, text


if __name__ == "__main__":
    unittest.main()


class TestSimpleCastQualification(unittest.TestCase):
    def test_sizeless_types_do_not_qualify_but_pointers_still_do(self):
        # a SimTypeNum without a size asserted when asked for one (git merge_ort_nonrecursive_internal); the
        # register-sized types take their size from the architecture, so a stored-size rule would have rejected
        # every pointer-integer cast
        arch = archinfo.ArchAMD64()
        ptr = SimTypePointer(SimTypeInt()).with_arch(arch)
        longlong = SimTypeLongLong().with_arch(arch)
        assert qualifies_for_simple_cast(ptr, longlong)
        assert qualifies_for_simple_cast(SimTypeNum(64).with_arch(arch), ptr)
        assert not qualifies_for_simple_cast(SimTypeInt().with_arch(arch), ptr)
        # SimTypeNum(None): the constructor is annotated int, so the size is cleared after construction
        sizeless = SimTypeNum(64)
        sizeless._size = None
        sizeless = sizeless.with_arch(arch)
        assert not qualifies_for_simple_cast(sizeless, longlong)
        assert not qualifies_for_simple_cast(longlong, sizeless)


class TestTypeLayoutKey(unittest.TestCase):
    """
    type_layout_key() keys a type by its memory layout so that struct definitions are emitted in an order that is
    deterministic and survives renames.
    """

    @staticmethod
    def _struct(name: str, fields: dict, arch) -> SimStruct:
        s = SimStruct(fields, name=name)
        s._arch = arch
        return s

    def test_shared_members_do_not_blow_up(self):
        # the key used to enumerate every path through the type graph, so a struct whose two fields point at the
        # same struct cost 2**depth
        arch = archinfo.ArchAMD64()
        cur: SimType = self._struct("leaf", {"a": SimTypeInt().with_arch(arch)}, arch)
        for i in range(25):
            ptr = SimTypePointer(cur)
            ptr._arch = arch
            cur = self._struct(f"s{i}", {"x": ptr, "y": ptr}, arch)

        start = time.time()
        key = type_layout_key(cur)
        assert time.time() - start < 5
        assert len(key) < 200

    def test_mutually_recursive_structs_do_not_blow_up(self):
        # ... and every simple path through a cycle, which is worse: a clique of n structs cost about n!
        arch = archinfo.ArchAMD64()
        structs = [self._struct(f"c{i}", {}, arch) for i in range(25)]
        for s in structs:
            for j, other in enumerate(structs):
                ptr = SimTypePointer(other)
                ptr._arch = arch
                s.fields[f"f{j}"] = ptr

        start = time.time()
        keys = [type_layout_key(s) for s in structs]
        assert time.time() - start < 5
        # these structs are isomorphic, so they all key the same
        assert len(set(keys)) == 1

    def test_key_ignores_names_but_not_layout(self):
        arch = archinfo.ArchAMD64()
        a = self._struct("alpha", {"x": SimTypeInt().with_arch(arch), "y": SimTypeInt().with_arch(arch)}, arch)
        renamed = self._struct("zulu", {"p": SimTypeInt().with_arch(arch), "q": SimTypeInt().with_arch(arch)}, arch)
        different = self._struct("alpha", {"x": SimTypeLongLong().with_arch(arch)}, arch)

        assert type_layout_key(a) == type_layout_key(renamed)
        assert type_layout_key(a) != type_layout_key(different)

    def test_key_does_not_depend_on_visit_order(self):
        arch = archinfo.ArchAMD64()
        structs = []
        for i in range(5):
            inner = self._struct(f"inner{i}", {"v": SimTypeInt().with_arch(arch)}, arch)
            ptr = SimTypePointer(inner)
            ptr._arch = arch
            structs.append(self._struct(f"outer{i}", {"p": ptr}, arch))

        forward = [type_layout_key(s) for s in structs]
        backward = [type_layout_key(s) for s in reversed(structs)]
        assert backward[::-1] == forward


class TestArrayReturnType(unittest.TestCase):
    """C has no array return type, so the C view adjusts one to a pointer."""

    arch = archinfo.ArchAMD64()

    def test_a_scalar_return_type_is_handed_back_unchanged(self):
        ty = SimTypeInt(signed=False).with_arch(self.arch)
        assert c_return_type(ty) is ty

    def test_a_pointer_return_type_is_handed_back_unchanged(self):
        ty = SimTypePointer(SimTypeInt()).with_arch(self.arch)
        assert c_return_type(ty) is ty

    def test_an_array_return_type_becomes_a_pointer_to_its_element(self):
        # the extent of an array is written after the declared name, which in a return type is
        # where the function name goes
        ty = SimTypeArray(SimTypeInt(signed=False), 2).with_arch(self.arch)
        adjusted = c_return_type(ty)
        assert isinstance(adjusted, SimTypePointer)
        assert adjusted.c_repr(name="") == "unsigned int *"
        assert adjusted._arch is self.arch

    def test_an_array_of_a_named_element_keeps_the_element(self):
        ty = SimTypeArray(SimTypeChar(), 16).with_arch(self.arch)
        assert c_return_type(ty).c_repr(name="") == "char *"

    def test_a_nested_array_reaches_the_innermost_element(self):
        # SimTypePointer renders a pointer to an array without the star, so decaying one dimension
        # would print an array again
        ty = SimTypeArray(SimTypeArray(SimTypeInt(signed=False), 3), 2).with_arch(self.arch)
        adjusted = c_return_type(ty)
        assert isinstance(adjusted, SimTypePointer)
        assert isinstance(adjusted.pts_to, SimTypeInt)
        assert adjusted.c_repr(name="") == "unsigned int *"

    def test_a_length_less_array_still_becomes_a_pointer(self):
        ty = SimTypeArray(SimTypeInt(signed=False)).with_arch(self.arch)
        assert c_return_type(ty).c_repr(name="") == "unsigned int *"

    def test_a_recovered_array_return_type_renders_as_a_pointer(self):
        # sub_141e0 fills a 24-byte stack slot with 8-byte handles and returns it, and type
        # inference gives its return variable HANDLE[3]. Nothing here injects the type.
        proj = angr.Project(os.path.join(test_location, "x86_64", "windows", "dirtymoe.sys"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)
        func = cfg.functions[0x141E0]

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None
        prototype = func.prototype
        assert prototype is not None
        assert isinstance(prototype.returnty, SimTypeArray)

        text = dec.codegen.text or ""
        signature = next(line for line in text.splitlines() if "sub_141e0(" in line)
        assert signature.startswith("HANDLE * sub_141e0(")
