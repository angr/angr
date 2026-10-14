#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access,no-member
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import copy
import inspect
import json
import os
import unittest
from unittest import mock

import archinfo
import cle

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import DirtyExpression, Register
from angr.ailment.statement import Label
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.structured_codegen import go as go_codegen
from angr.analyses.decompiler.structured_codegen.c_serialize import _SERIALIZE_KIND_BY_CLASS
from angr.analyses.decompiler.structured_codegen.go import (
    GoConstruct,
    GoExpression,
    GoFunctionCall,
    GoLoop,
    GoStatement,
    GoStructuredCodeGenerator,
    GoVariable,
)
from angr.go.sim_type import (
    PREDECLARED,
    GoSimStruct,
    GoSimTypeFunction,
    GoSimTypeInterface,
    GoSimTypePointer,
    go_type_repr,
)
from angr.knowledge_plugins.structured_code import SpillingDecompilationDict
from angr.protos import codegen_pb2  # pylint:disable=no-name-in-module  # pyright: ignore[reportAttributeAccessIssue]
from angr.sim_type import SimType, SimTypeChar, SimTypeDouble, SimTypeInt, SimTypePointer, SimTypeRef
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


def _message(blob: bytes) -> codegen_pb2.Codegen:
    msg = codegen_pb2.Codegen()
    msg.ParseFromString(blob)
    return msg


def _assert_round_trips(codegen, proj, func) -> GoStructuredCodeGenerator:
    """Parse the codegen back and check it carries the same text, serializes to the same message, and re-renders to
    the same text. Messages are compared rather than bytes, because protobuf does not fix the order in which it
    writes map entries."""
    blob = codegen.serialize()
    back = GoStructuredCodeGenerator.parse(blob, project=proj, kb=proj.kb, func=func)
    assert back.text == codegen.text
    assert _message(back.serialize()) == _message(blob)
    back.regenerate_text()
    assert back.text == codegen.text
    return back


def _nodes(codegen, cls) -> list:
    """The rendered nodes of a class, without touching attributes that load anything."""
    return [n.obj for n in (codegen.map_pos_to_node or {}).values() if isinstance(n.obj, cls)]


# every Go-only node kind; the programs below must decompile to all of them between them
GO_ONLY_KINDS = frozenset(name for name, _ in codegen_pb2.CConstructKind.items() if name.startswith("CCK_GO_"))


class _GoProgramSerialization:
    """
    Go decompilations serialize, so kb.decompilations spills them instead of keeping every one in memory. One class
    per Go test program, each on its own scoped CFG; KINDS are the Go-only node kinds its functions decompile to.
    """

    ARCH = "x86_64"
    VERSION = "go1.22.5"
    PROGRAM: str
    FUNCS: tuple[str, ...]
    KINDS: frozenset[str] = frozenset()

    decompiled: list

    @classmethod
    def setUpClass(cls):
        path = os.path.join(test_location, cls.ARCH, "go", cls.VERSION, cls.PROGRAM)
        loader = cle.Loader(path, auto_load_libs=False)
        addrs = [loader.find_symbol(name).rebased_addr for name in cls.FUNCS]
        proj, cfg = load_project_with_scoped_cfg(path, addrs[0], extra_func_addrs=addrs[1:], call_tree_depth=0)
        cls.decompiled = []
        for addr in addrs:
            dec = proj.analyses.Decompiler(addr, cfg=cfg.model, flavor="go")
            assert isinstance(dec.codegen, GoStructuredCodeGenerator)
            cls.decompiled.append((proj, proj.kb.functions[addr], dec))

    def test_holds_its_go_only_kinds(self):
        kinds = set()
        for _, _, dec in self.decompiled:
            kinds |= {codegen_pb2.CConstructKind.Name(node.kind) for node in _message(dec.codegen.serialize()).nodes}
        missing = self.KINDS - kinds
        assert not missing, f"the target functions no longer decompile to {sorted(missing)}"

    def test_codegen_roundtrip(self):
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                back = _assert_round_trips(dec.codegen, proj, func)
                assert back.flavor == "go"
                assert back.cfunc is not None and dec.codegen.cfunc is not None
                assert back.cfunc.idx == dec.codegen.cfunc.idx

    def test_parsing_loads_no_functions(self):
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                blob = dec.codegen.serialize()
                lookup = proj.kb.functions.function
                with mock.patch.object(proj.kb.functions, "function", side_effect=lookup) as spy:
                    back = GoStructuredCodeGenerator.parse(blob, project=proj, kb=proj.kb, func=func)
                    assert spy.call_count == 0
                    # nor does serializing it again
                    assert _message(back.serialize()) == _message(blob)
                    assert spy.call_count == 0
                # a call's callee is loaded on first use, and keys map_ast_to_pos as the call's callee_func
                for call in _nodes(back, GoFunctionCall):
                    callee = call.callee_func
                    if callee is not None:
                        assert callee is proj.kb.functions.function(callee.addr)
                        assert callee in back.map_ast_to_pos

    def test_library_types_are_written_by_name(self):
        """A struct the binary or a library defines is never spelled out: the type pool refers to it by name and the
        parser rebuilds it from kb.go_signatures, so a function's types hold only what inference produced."""
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                blob = dec.codegen.serialize()
                sigs = proj.kb.go_signatures
                library_defs = []
                for entry in _message(blob).type_pool:
                    stack = [json.loads(entry)]
                    while stack:
                        d = stack.pop()
                        if isinstance(d, dict):
                            name = d.get("go_name")
                            if (
                                d.get("_t") == "go_struct"
                                and name is not None
                                and not name.startswith("struct_")
                                and sigs.named_type(name) is not None
                            ):
                                library_defs.append(name)
                            stack.extend(d.values())
                        elif isinstance(d, list):
                            stack.extend(d)
                assert not library_defs, f"library structs spelled out in the type pool: {sorted(set(library_defs))}"
                # and whatever came back by name is a real struct again, not a dangling reference
                back = GoStructuredCodeGenerator.parse(blob, project=proj, kb=proj.kb, func=func)
                for node in _nodes(back, GoVariable):
                    ty = node.type
                    while isinstance(ty, GoSimTypePointer):
                        ty = ty.pts_to
                    assert not isinstance(ty, SimTypeRef), f"{node.variable} came back as a bare reference to {ty}"
                # the rendering declares only the structs inference made up
                declared = [line for line in dec.codegen.text.splitlines() if line.startswith("type ")]
                assert all(line.startswith("type struct_") for line in declared), declared

    def test_decompilation_cache_restores_a_go_generator(self):
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                back = DecompilationCache.parse(dec.cache.serialize(), project=proj, kb=proj.kb, function=func)
                assert isinstance(back.codegen, GoStructuredCodeGenerator)
                assert back.codegen.text == dec.codegen.text

    def test_reloaded_cache_is_reused(self):
        # the Go passes must resolve by name when the cache is parsed, or the decompiler's parameter check rejects
        # every spilled-and-reloaded Go decompilation and decompiles afresh
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                back = DecompilationCache.parse(
                    dec.cache.serialize(), project=proj, kb=proj.kb, function=func, cfg=dec.cache.cfg
                )
                assert back.parameters["optimization_passes"] == dec.cache.parameters["optimization_passes"]
                proj.kb.decompilations[(func.addr, "go")] = back
                again = proj.analyses.Decompiler(func, cfg=dec.cache.cfg, flavor="go")
                assert again.codegen is back.codegen
                assert again.codegen.text == dec.codegen.text

    def test_cache_spills_instead_of_parking_in_memory(self):
        proj = self.decompiled[0][0]
        d = SpillingDecompilationDict(proj.kb, cache_limit=0)
        for _, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                key = (func.addr, "go")
                d[key] = dec.cache
                assert key in d._spilled
                assert not d._unspillable
                reloaded = d[key]
                assert isinstance(reloaded.codegen, GoStructuredCodeGenerator)
                assert reloaded.codegen.text == dec.codegen.text


class TestSlicesSerialization(_GoProgramSerialization, unittest.TestCase):
    PROGRAM = "slices"
    FUNCS = ("main.main",)
    KINDS = frozenset({"CCK_GO_STRING_LITERAL", "CCK_GO_STRUCT_LITERAL"})


class TestIfaceSerialization(_GoProgramSerialization, unittest.TestCase):
    PROGRAM = "iface"
    FUNCS = ("main.report", "main.unbox", "main.kind")
    KINDS = frozenset(
        {
            "CCK_GO_BOXED_VALUE",
            "CCK_GO_METHOD_CALL",
            "CCK_GO_MULTI_ASSIGNMENT",
            "CCK_GO_RANGE_LOOP",
            "CCK_GO_SLICE_LITERAL",
            "CCK_GO_STRING_LITERAL",
            "CCK_GO_TYPE_ASSERTION",
            "CCK_GO_TYPE_SWITCH",
        }
    )


class TestConcSerialization(_GoProgramSerialization, unittest.TestCase):
    PROGRAM = "conc"
    FUNCS = ("main.pick",)
    KINDS = frozenset({"CCK_GO_SELECT"})


class TestClosuresSerialization(_GoProgramSerialization, unittest.TestCase):
    PROGRAM = "closures"
    FUNCS = ("main.pick",)
    KINDS = frozenset({"CCK_GO_STRING_LITERAL", "CCK_GO_STRUCT_LITERAL"})


class TestBuiltinsSerialization(_GoProgramSerialization, unittest.TestCase):
    PROGRAM = "builtins"
    FUNCS = ("main.newNode",)

    def test_holds_a_struct_that_points_to_itself(self):
        # the codegen's types include a named struct that contains itself, written once and then referred to
        pool = _message(self.decompiled[0][2].codegen.serialize()).type_pool
        assert any('"_t": "_ref"' in entry for entry in pool)


class TestBasicsSerialization(_GoProgramSerialization, unittest.TestCase):
    PROGRAM = "basics"
    FUNCS = ("main.parse",)
    KINDS = frozenset({"CCK_GO_MULTI_ASSIGNMENT", "CCK_GO_STRUCT_LITERAL"})


class TestTypeswitchSerialization(_GoProgramSerialization, unittest.TestCase):
    # main.lookup holds a constant below min_data_addr that names a variable; its reference_values may only have
    # SimType keys, which the type pool can intern
    ARCH = "aarch64"
    VERSION = "go1.27.1"
    PROGRAM = "typeswitch"
    FUNCS = ("main.lookup",)
    KINDS = frozenset({"CCK_GO_MULTI_ASSIGNMENT", "CCK_GO_STRUCT_LITERAL"})


class TestGoOnlyKindCoverage(unittest.TestCase):
    def test_the_programs_cover_every_go_only_kind(self):
        programs = [
            cls for cls in globals().values() if isinstance(cls, type) and issubclass(cls, _GoProgramSerialization)
        ]
        covered = frozenset().union(*(cls.KINDS for cls in programs))
        assert covered == GO_ONLY_KINDS, sorted(GO_ONLY_KINDS - covered)


class TestGoNodesNoFixtureProduces(unittest.TestCase):
    """The node kinds and field values the fixtures above do not produce, built by hand under a real Go codegen."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        cls.func = cls.proj.kb.functions["main"]

    def _codegen(self) -> GoStructuredCodeGenerator:
        cg = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model, flavor="go", use_cache=False).codegen
        assert isinstance(cg, GoStructuredCodeGenerator)
        return cg

    def test_roundtrip(self):
        proj, func = self.proj, self.func
        cg = self._codegen()

        g = go_codegen
        cfunc = cg.cfunc
        assert cfunc is not None
        var = next(v for v in cfunc.variables_in_use.values() if isinstance(v, g.GoVariable))
        m = Manager()

        def const(value, ty=None):
            return g.GoConstant(value, ty or SimTypeInt(), codegen=cg)

        def body(*stmts):
            return g.GoStatements(list(stmts), codegen=cg)

        cond = g.GoBinaryOp("CmpEQ", var, const(1), codegen=cg)
        div = g.GoBinaryOp("Div", var, const(3), codegen=cg)
        div.signed = True
        assign = g.GoAssignment(var, div, codegen=cg)
        data = const(0x400800, SimTypePointer(SimTypeChar()).with_arch(proj.arch))
        data.string_data = "hello"
        rax = Register(m.next_atom(), proj.arch.registers["rax"][0], 64, reg_name="rax")
        rdtsc = DirtyExpression(m.next_atom(), "amd64g_dirtyhelper_RDTSC", [], bits=64)
        label = Label(m.next_atom(), "LABEL_400300", ins_addr=0x400300, block_idx=None)
        cfunc.statements = body(
            assign,
            copy.copy(assign),  # as ChannelRangeRecovery copies statements: same idx, two nodes
            g.GoLabel("LABEL_400200", codegen=cg),
            g.GoGoto(0x400200, None, codegen=cg),
            g.GoIfBreak(cond, codegen=cg),
            g.GoDoWhileLoop(cond, body(g.GoBreak(codegen=cg), g.GoContinue(codegen=cg)), codegen=cg),
            g.GoWhileLoop(None, body(), codegen=cg),
            g.GoSwitchCase(var, [(1, body()), ((2, -3), body())], body(), codegen=cg),
            # StringSwitchRecovery's labels: quoted literals, in a tuple even when there is one
            g.GoSwitchCase(var, [(('"a"',), body()), (('"b"', '"c"'), body())], None, codegen=cg),
            g.GoIncompleteSwitchCase(var, [(0x400100, body())], codegen=cg),
            g.GoAssignment(var, g.GoITE(cond, const(1), const(2), codegen=cg), codegen=cg),
            g.GoAssignment(var, g.GoMultiStatementExpression(body(), const(5), codegen=cg), codegen=cg),
            g.GoAssignment(
                var, g.GoVEXCCallExpression("amd64g_calculate_condition", [var, const(1)], codegen=cg), codegen=cg
            ),
            g.GoAssignment(var, g.GoRegister(rax, codegen=cg), codegen=cg),
            # a register variable with no mapped variable renders as the register's display name
            g.GoAssignment(var, g.GoRegister("rax", codegen=cg), codegen=cg),
            g.GoDirtyStatement(g.GoDirtyExpression(rdtsc, codegen=cg), codegen=cg),
            g.GoAILBlock(Block(0x400300, 4, statements=[]), codegen=cg),
            g.GoUnsupportedStatement(label, codegen=cg),
            g.GoExpressionStatement(
                g.GoFunctionCall("runtime.Gosched", None, [], codegen=cg), returning=None, codegen=cg
            ),
            g.GoAssignment(
                var, g.GoStructLiteral("main.point", {0: const(1), 8: const(2)}, {0: "x"}, codegen=cg), codegen=cg
            ),
            g.GoAssignment(var, const(1.5, SimTypeDouble()), codegen=cg),
            g.GoAssignment(var, data, codegen=cg),
            g.GoSelect(
                [
                    (g.GoSelectCase("send", channel=var, value=const(1)), body()),
                    (g.GoSelectCase("recv", channel=var, value=var, ok=var), body()),
                    (g.GoSelectCase("default"), body()),
                ],
                codegen=cg,
            ),
            g.GoReturn(None, codegen=cg),
        )
        cg.regenerate_text()

        back = _assert_round_trips(cg, proj, func)
        assert back.cfunc is not None
        stmts = back.cfunc.statements.statements
        first, second = stmts[:2]
        assert first is not second
        assert first.idx != second.idx
        assert [s.cases[0][0] for s in stmts if isinstance(s, g.GoSwitchCase)] == [1, ('"a"',)]
        assert next(s for s in stmts if isinstance(s, g.GoExpressionStatement)).returning is None
        literal = next(s.rhs for s in stmts if isinstance(s, g.GoAssignment) and isinstance(s.rhs, g.GoStructLiteral))
        assert literal.field_names == {0: "x"}


class TestGoTypeJson(unittest.TestCase):
    """The Go types a codegen holds survive SimType.to_json and SimType.from_json."""

    ARCH = archinfo.ArchAMD64()

    def _round_trip(self, ty: SimType) -> SimType:
        d = ty.to_json()
        back = SimType.from_json(json.loads(json.dumps(d)))
        assert back.to_json() == d
        return back

    def test_interface_method_list(self):
        error = PREDECLARED["error"](self.ARCH)
        back = self._round_trip(error)
        assert isinstance(back, GoSimTypeInterface)
        assert [name for name, _ in back.methods] == ["Error"]
        assert back.go_repr() == error.go_repr()

    def test_interface_tab_word(self):
        # the type parser points an interface's first word at the runtime's itab struct after constructing it
        itab = GoSimStruct({"hash": PREDECLARED["uint32"](self.ARCH)}, go_name="runtime.itab")
        area = GoSimTypeFunction([], PREDECLARED["int"](self.ARCH))
        shape = GoSimTypeInterface([("Area", area)], go_name="main.Shape")
        shape.fields["tab"] = GoSimTypePointer(itab)
        back = self._round_trip(shape.with_arch(self.ARCH))
        assert isinstance(back, GoSimTypeInterface)
        assert go_type_repr(back.fields["tab"]) == "*runtime.itab"

    def test_struct_that_points_to_itself(self):
        node = GoSimStruct(go_name="main.node")
        node.fields["next"] = GoSimTypePointer(node)
        node.fields["val"] = PREDECLARED["int"](self.ARCH)
        back = self._round_trip(node.with_arch(self.ARCH))
        assert isinstance(back, GoSimStruct)
        assert back.go_repr() == "main.node"
        assert list(back.fields) == ["next", "val"]
        assert go_type_repr(back.fields["next"]) == "*main.node"
        # the reference back to the struct resolves to the struct itself
        assert back.fields["next"].pts_to is back

    def test_interface_whose_method_returns_it(self):
        it = GoSimTypeInterface(go_name="main.Node")
        it.methods = [("Next", GoSimTypeFunction([], it))]
        back = self._round_trip(it.with_arch(self.ARCH))
        assert isinstance(back, GoSimTypeInterface)
        assert back.go_repr() == "main.Node"
        assert back.methods[0][1].returnty is back


class TestGoSerializerRegistration(unittest.TestCase):
    """Every concrete GoConstruct subclass must have a serializer/parser pair registered."""

    ABSTRACT = (GoConstruct, GoStatement, GoExpression, GoLoop)

    def test_every_concrete_goconstruct_is_registered(self):
        unregistered = [
            obj.__name__
            for obj in vars(go_codegen).values()
            if inspect.isclass(obj)
            and issubclass(obj, GoConstruct)
            and obj not in self.ABSTRACT
            and obj not in _SERIALIZE_KIND_BY_CLASS
        ]
        assert not unregistered, f"GoConstruct subclasses missing from the serializer dispatch table: {unregistered}"


if __name__ == "__main__":
    unittest.main()
