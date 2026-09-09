#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import os
import re
import unittest
from types import SimpleNamespace

import angr
from angr.ailment import Expr, Stmt
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpression,
    CGoto,
    CReturn,
    CStructuredCodeGenerator,
    CUnaryOp,
    type_to_c_repr_chunks,
)
from angr.calling_conventions import SimComboArg
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimTypeBottom,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimUnion,
    parse_cpp_file,
)
from tests.common import WORKER, bin_location, print_decompilation_result

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


if __name__ == "__main__":
    unittest.main()
