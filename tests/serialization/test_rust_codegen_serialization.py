#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import inspect
import os
import unittest

import angr
from angr.ailment import Manager
from angr.ailment.block import Block as AilBlock
from angr.ailment.expression import Const, Convert, Let, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Jump, Store
from angr.analyses.decompiler.structured_codegen import rust as rust_codegen
from angr.analyses.decompiler.structured_codegen.c_serialize import _SERIALIZE_KIND_BY_CLASS
from angr.analyses.decompiler.structured_codegen.rust import (
    RustAILBlock,
    RustArray,
    RustAssignment,
    RustBinaryOp,
    RustBreak,
    RustConstant,
    RustConstruct,
    RustContinue,
    RustDirtyExpression,
    RustDirtyStatement,
    RustDoWhileLoop,
    RustEnum,
    RustExpression,
    RustFakeVariable,
    RustForLoop,
    RustFunctionCall,
    RustFunctionLikeMacro,
    RustGoto,
    RustIfBreak,
    RustIfElse,
    RustIfLet,
    RustIncompleteSwitchCase,
    RustIndexedVariable,
    RustInfiniteLoop,
    RustITE,
    RustLabel,
    RustLet,
    RustLoop,
    RustMultiStatementExpression,
    RustPatternMatch,
    RustRegister,
    RustReturn,
    RustStatement,
    RustStatements,
    RustStringLiteral,
    RustStruct,
    RustStructField,
    RustStructuredCodeGenerator,
    RustSwitchCase,
    RustTypeCast,
    RustUnaryOp,
    RustUnsupportedStatement,
    RustVariable,
    RustVariableField,
    RustVectorConvert,
    RustVEXCCallExpression,
    RustWhileLoop,
)
from angr.analyses.decompiler.structured_codegen.rust_serialize import _PARSERS
from angr.angrdb import AngrDB
from angr.knowledge_plugins.structured_code import SpillingDecompilationDict
from angr.protos import codegen_pb2
from angr.rust.sim_type import EnumVariant, RustSimTypeInt
from angr.sim_type import SimStruct, SimTypeInt, SimTypePointer
from angr.sim_variable import SimStackVariable
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")
rust_location = os.path.join(test_location, "x86_64", "rust", "coreutils")


def _kinds(blob: bytes) -> list[str]:
    msg = codegen_pb2.Codegen()
    msg.ParseFromString(blob)
    return [codegen_pb2.CConstructKind.Name(n.kind) for n in msg.nodes]


class TestRustSerializerRegistration(unittest.TestCase):
    # Bases that are never instantiated directly and therefore need no serializer.
    ABSTRACT = (RustConstruct, RustStatement, RustExpression, RustLoop)

    def test_every_concrete_rustconstruct_is_registered(self):
        unregistered = [
            obj.__name__
            for obj in vars(rust_codegen).values()
            if inspect.isclass(obj)
            and issubclass(obj, RustConstruct)
            and obj not in self.ABSTRACT
            and obj not in _SERIALIZE_KIND_BY_CLASS
        ]
        assert not unregistered, f"RustConstruct subclasses missing from the serializer dispatch table: {unregistered}"

    def test_every_registered_kind_has_a_parser(self):
        for cls, kind in _SERIALIZE_KIND_BY_CLASS.items():
            if issubclass(cls, RustConstruct):
                assert kind in _PARSERS, f"{cls.__name__} has no Rust parser"


class TestRustCodegenRoundTrip(unittest.TestCase):
    """The Rust flavor used to have no serialization at all, so its caches took the metadata-only legacy path."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.proj.analyses.CompleteCallingConventions()
        cls.func = cls.proj.kb.functions.function(name="authenticate")
        cls.decompiler = cls.proj.analyses.Decompiler(
            cls.func, cfg=cls.cfg.model, flavor="rust", update_cache=True, generate_code=True
        )
        cls.codegen = cls.decompiler.codegen
        cls.text = cls.codegen.text

    def _parse(self, blob):
        return RustStructuredCodeGenerator.parse(blob, project=self.proj, kb=self.proj.kb, func=self.func)

    def test_codegen_roundtrip(self):
        blob = self.codegen.serialize()
        back = self._parse(blob)
        assert isinstance(back, RustStructuredCodeGenerator)
        assert back.text == self.text
        assert back.flavor == "rust"
        assert back.rust_func is not None
        assert back.rust_func.name == self.codegen.rust_func.name
        assert back.rust_func.addr == self.codegen.rust_func.addr
        assert _kinds(back.serialize()) == _kinds(blob)

    def test_roundtrip_is_stable(self):
        # a second round trip must not lose anything the first one kept
        blob2 = self._parse(self.codegen.serialize()).serialize()
        assert self._parse(blob2).serialize() == blob2

    def test_display_options_survive(self):
        back = self._parse(self.codegen.serialize())
        for attr in ("show_casts", "braces_on_own_lines", "comment_gotos", "cstyle_ifs", "omit_func_header"):
            assert getattr(back, attr) == getattr(self.codegen, attr), attr
        assert back._indent == self.codegen._indent

    def test_position_maps_survive(self):
        # only AST nodes are serialized; entries pointing at types or closing braces are rebuilt by re-rendering
        def node_entries(codegen):
            return [e for _, e in codegen.map_pos_to_node.items() if isinstance(e.obj, RustConstruct)]

        back = self._parse(self.codegen.serialize())
        assert node_entries(back)
        assert len(node_entries(back)) == len(node_entries(self.codegen))
        assert len(list(back.map_addr_to_pos.items())) == len(list(self.codegen.map_addr_to_pos.items()))
        assert back.map_ast_to_pos

    def test_cache_spills_instead_of_parking_in_memory(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=0)
        key = (self.func.addr, "rust")
        d[key] = self.decompiler.cache

        assert key in d._spilled
        assert not d._unspillable
        back = d[key]
        assert isinstance(back.codegen, RustStructuredCodeGenerator)
        assert back.codegen.text == self.text

    def test_angrdb_roundtrip(self):
        db_path = os.path.join(self.proj.loader.main_object.binary + ".rustcodegen.angrdb")
        try:
            AngrDB(self.proj).dump(db_path)
            reloaded = AngrDB().load(db_path)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
        cache = reloaded.kb.decompilations.get((self.func.addr, "rust"))
        assert cache is not None
        assert isinstance(cache.codegen, RustStructuredCodeGenerator)
        assert cache.codegen.text == self.text


class TestRustBinaryRoundTrip(unittest.TestCase):
    """Rust-only node types only show up when decompiling an actual Rust binary."""

    BINARY = os.path.join(rust_location, "nightly-2025-05-22-O3", "fmt")
    FUNC_ADDR = 0x496920

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(cls.BINARY):
            raise unittest.SkipTest(f"{cls.BINARY} not found")
        cls.proj, cfg = load_project_with_scoped_cfg(
            cls.BINARY,
            cls.FUNC_ADDR,
            project_kwargs={"auto_load_libs": False},
            expand_call_tree=False,
            run_ccc=False,
        )
        cls.func = cls.proj.kb.functions[cls.FUNC_ADDR]
        cls.codegen = cls.proj.analyses.Decompiler(cls.func, cfg=cfg.model, flavor="rust").codegen

    def test_rust_only_nodes_roundtrip(self):
        blob = self.codegen.serialize()
        kinds = set(_kinds(blob))
        assert {"CCK_RUST_STRUCT", "CCK_RUST_STRING_LITERAL"} <= kinds, kinds

        back = RustStructuredCodeGenerator.parse(blob, project=self.proj, kb=self.proj.kb, func=self.func)
        assert back.text == self.codegen.text
        blob2 = back.serialize()
        assert _kinds(blob2) == _kinds(blob)
        again = RustStructuredCodeGenerator.parse(blob2, project=self.proj, kb=self.proj.kb, func=self.func)
        assert again.serialize() == blob2


class TestEveryRustNodeKind(unittest.TestCase):
    """One node of every registered Rust class, round-tripped: real binaries do not reach all of them."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.func = cls.proj.kb.functions.function(name="authenticate")
        cls.codegen = cls.proj.analyses.Decompiler(cls.func, cfg=cfg.model, flavor="rust").codegen

    def _nodes(self):
        """One instance of every concrete Rust node class, as a flat list of statements."""
        cg = self.codegen
        m = Manager()
        int_ty = RustSimTypeInt(32, signed=True).with_arch(self.proj.arch)

        def const(v=1):
            return RustConstant(v, int_ty, codegen=cg)

        def vvar(varid=1, bits=32):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER)

        var = RustVariable(SimStackVariable(-8, 4, ident="s_0"), variable_type=int_ty, codegen=cg)
        fake = RustFakeVariable("fake", int_ty, codegen=cg)
        struct_ty = SimStruct({"f0": SimTypeInt()}, name="S").with_arch(self.proj.arch)
        field = RustStructField(struct_ty, 0, "f0", codegen=cg)
        variant = EnumVariant("Some", [(SimTypeInt().with_arch(self.proj.arch), "0")], 1, 4)
        empty = RustStatements([], codegen=cg)
        ail_block = AilBlock(0x400000, 4, statements=[Jump(0, Const(1, 0x400004, 64), ins_addr=0x400000)])
        convert = Convert(
            m.next_atom(),
            128,
            128,
            True,
            vvar(2, 128),
            from_type=Convert.TYPE_FP,
            to_type=Convert.TYPE_INT,
            vector_count=4,
        )

        exprs = [
            var,
            fake,
            const(),
            RustRegister("rax", codegen=cg),
            RustUnaryOp("Neg", const(), codegen=cg),
            RustBinaryOp("Add", const(1), const(2), codegen=cg),
            RustTypeCast(int_ty, SimTypePointer(SimTypeInt()).with_arch(self.proj.arch), const(), codegen=cg),
            RustITE(const(0), const(1), const(2), codegen=cg),
            RustIndexedVariable(var, const(0), variable_type=int_ty, codegen=cg),
            RustVariableField(var, field, var_is_ptr=True, codegen=cg),
            field,
            RustMultiStatementExpression(empty, const(), codegen=cg),
            RustVEXCCallExpression("amd64g_calculate_condition", [const(1), const(2)], codegen=cg),
            RustDirtyExpression(vvar(3), codegen=cg),
            RustVectorConvert(convert, const(), codegen=cg),
            RustStringLiteral(b"hello", codegen=cg),
            RustArray([const(1), const(2)], codegen=cg),
            RustStruct("S", {0: const(1)}, {0: "f0"}, codegen=cg),
            RustEnum("E", [const(1)], codegen=cg),
            RustLet(
                Let(
                    m.next_atom(),
                    [Assignment(m.next_atom(), vvar(4), Const(m.next_atom(), 5, 32))],
                    Const(m.next_atom(), 7, 32),
                ),
                codegen=cg,
            ),
            RustFunctionCall(0x400100, None, [const(1)], ret_expr=var, receiver=const(2), is_expr=True, codegen=cg),
        ]
        return [
            RustAssignment(var, const(), codegen=cg),
            RustReturn(const(), codegen=cg),
            RustBreak(codegen=cg),
            RustContinue(codegen=cg),
            RustLabel("lbl", 0x400000, 1, codegen=cg),
            RustGoto(0x400010, None, codegen=cg),
            RustIfBreak(const(1), codegen=cg),
            RustIfElse([(const(1), empty)], else_node=empty, codegen=cg),
            RustWhileLoop(const(1), empty, codegen=cg),
            RustDoWhileLoop(const(1), empty, codegen=cg),
            RustInfiniteLoop(empty, codegen=cg),
            RustForLoop(RustAssignment(var, const(0), codegen=cg), const(1), None, empty, codegen=cg),
            RustSwitchCase(const(1), [(0, empty), ((1, 2), empty)], default=empty, codegen=cg),
            RustIncompleteSwitchCase(empty, [(0x400020, empty)], codegen=cg),
            RustAILBlock(ail_block, codegen=cg),
            RustUnsupportedStatement(Store(0, Const(1, 0x400000, 64), Const(2, 0, 32), 4, "Iend_LE"), codegen=cg),
            RustDirtyStatement(RustDirtyExpression(vvar(6), codegen=cg), codegen=cg),
            RustIfLet((variant, (var,)), const(1), empty, empty, codegen=cg),
            RustPatternMatch(const(1), [((variant, (var,)), empty)], default=empty, codegen=cg),
            RustFunctionLikeMacro("println", [Const(m.next_atom(), 1, 32)], ("(", ")"), False, codegen=cg),
            RustStatements(exprs, codegen=cg),  # keeps the expressions reachable from the root
        ]

    def test_every_kind_roundtrips(self):
        cg = self.codegen
        # keep only the constructed AST: the decompiled one reaches constants whose reference values the wire format
        # does not carry (the C flavor drops those too), which would mask a real difference below
        cg.rust_func.statements = RustStatements(self._nodes(), codegen=cg)
        cg.cexterns = None
        cg.map_addr_to_label = {}
        cg.map_pos_to_node = cg.map_pos_to_addr = cg.map_addr_to_pos = None
        blob = cg.serialize()

        kinds = _kinds(blob)
        expected = {
            codegen_pb2.CConstructKind.Name(kind)
            for cls, kind in _SERIALIZE_KIND_BY_CLASS.items()
            if issubclass(cls, RustConstruct)
        }
        assert expected <= set(kinds), f"kinds never serialized: {sorted(expected - set(kinds))}"

        back = RustStructuredCodeGenerator.parse(blob, project=self.proj, kb=self.proj.kb, func=self.func)
        # nothing may be dropped or altered on the way back out
        assert back.serialize() == blob


if __name__ == "__main__":
    unittest.main()
