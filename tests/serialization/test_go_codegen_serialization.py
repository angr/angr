#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access,no-member
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import copy
import inspect
import json
import os
import unittest

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
    GoLoop,
    GoStatement,
    GoStructuredCodeGenerator,
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
from angr.sim_type import SimType, SimTypeChar, SimTypeDouble, SimTypeInt, SimTypePointer
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


class TestGoCodegenSerialization(unittest.TestCase):
    """Go decompilations serialize, so kb.decompilations spills them instead of keeping every one in memory."""

    # Go test programs, and functions whose output holds the Go-only node kinds and the Go types that need their own
    # JSON handling (an interface's method list, a struct that points to itself). typeswitch's main.lookup holds a
    # constant below min_data_addr that names a variable; its reference_values may only have SimType keys, which
    # the type pool can intern.
    TARGETS = {
        ("x86_64", "go1.22.5", "slices"): ("main.main",),
        ("x86_64", "go1.22.5", "iface"): ("main.report", "main.unbox", "main.kind"),
        ("x86_64", "go1.22.5", "conc"): ("main.pick",),
        ("x86_64", "go1.22.5", "closures"): ("main.pick",),
        ("x86_64", "go1.22.5", "builtins"): ("main.newNode",),
        ("x86_64", "go1.22.5", "basics"): ("main.parse",),
        ("aarch64", "go1.27.1", "typeswitch"): ("main.lookup",),
    }

    decompiled: list

    @classmethod
    def setUpClass(cls):
        cls.decompiled = []
        for (arch, version, program), names in cls.TARGETS.items():
            path = os.path.join(test_location, arch, "go", version, program)
            loader = cle.Loader(path, auto_load_libs=False)
            symbols = [loader.find_symbol(name) for name in names]
            addrs = [sym.rebased_addr for sym in symbols if sym is not None]
            assert len(addrs) == len(names)
            proj, cfg = load_project_with_scoped_cfg(path, addrs[0], extra_func_addrs=addrs[1:], call_tree_depth=1)
            for addr in addrs:
                dec = proj.analyses.Decompiler(addr, cfg=cfg.model, flavor="go")
                assert isinstance(dec.codegen, GoStructuredCodeGenerator)
                cls.decompiled.append((proj, proj.kb.functions[addr], dec))

    def test_targets_hold_the_go_only_kinds(self):
        kinds = set()
        for _, _, dec in self.decompiled:
            kinds |= {node.kind for node in _message(dec.codegen.serialize()).nodes}
        expected = {
            codegen_pb2.CCK_GO_RANGE_LOOP,
            codegen_pb2.CCK_GO_METHOD_CALL,
            codegen_pb2.CCK_GO_MULTI_ASSIGNMENT,
            codegen_pb2.CCK_GO_SELECT,
            codegen_pb2.CCK_GO_TYPE_SWITCH,
            codegen_pb2.CCK_GO_STRING_LITERAL,
            codegen_pb2.CCK_GO_STRUCT_LITERAL,
            codegen_pb2.CCK_GO_BOXED_VALUE,
            codegen_pb2.CCK_GO_TYPE_ASSERTION,
            codegen_pb2.CCK_GO_SLICE_LITERAL,
        }
        missing = {codegen_pb2.CConstructKind.Name(k) for k in expected - kinds}
        assert not missing, f"the target functions no longer decompile to {sorted(missing)}"

    def test_codegen_roundtrip(self):
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                back = _assert_round_trips(dec.codegen, proj, func)
                assert back.flavor == "go"
                assert back.cfunc is not None and dec.codegen.cfunc is not None
                assert back.cfunc.idx == dec.codegen.cfunc.idx

    def test_decompilation_cache_restores_a_go_generator(self):
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                back = DecompilationCache.parse(dec.cache.serialize(), project=proj, kb=proj.kb, function=func)
                assert isinstance(back.codegen, GoStructuredCodeGenerator)
                assert back.codegen.text == dec.codegen.text

    def test_cache_spills_instead_of_parking_in_memory(self):
        spill = {}
        for proj, func, dec in self.decompiled:
            with self.subTest(func=func.name):
                d = spill.setdefault(id(proj), SpillingDecompilationDict(proj.kb, cache_limit=0))
                key = (func.addr, "go")
                d[key] = dec.cache
                assert key in d._spilled
                assert not d._unspillable
                reloaded = d[key]
                assert isinstance(reloaded.codegen, GoStructuredCodeGenerator)
                assert reloaded.codegen.text == dec.codegen.text


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
