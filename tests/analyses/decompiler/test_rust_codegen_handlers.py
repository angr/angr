#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import (
    Const,
    DirtyExpression,
    Insert,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import CAS, DirtyStatement, Jump, Store, WeakAssignment
from angr.analyses.decompiler.structured_codegen.rust import RustExpression, RustStructuredCodeGenerator
from angr.analyses.decompiler.structurer_nodes import (
    IncompleteSwitchCaseHeadStatement,
    IncompleteSwitchCaseNode,
    SequenceNode,
)
from angr.rust.sim_type import RustSimTypeInt, RustSimTypeStrRef
from angr.sim_type import SimTypeBottom
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

# what the Rust backend emits for a node it has no handler for
PLACEHOLDER = "unsupported instruction"


def _render(node):
    return "".join(chunk for chunk, _ in node.c_repr_chunks())


class TestRustCodegenHandlers(unittest.TestCase):
    """
    _handle_AILBlock() substitutes a placeholder for any statement the backend has no handler for, so a missing
    handler silently drops whatever the statement contained.
    """

    @classmethod
    def setUpClass(cls):
        # any binary will do: we only need a constructed Rust code generator to drive handlers with
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None
        cls.proj = proj
        cls.codegen = dec.codegen

    def _manager(self):
        return Manager(arch=self.proj.arch)

    @staticmethod
    def _vvar(m, varid, bits=64, category=VirtualVariableCategory.REGISTER):
        return VirtualVariable(m.next_atom(), varid, bits, category)

    def test_handler_table_covers_everything_the_c_backend_covers(self):
        """A missing handler degrades silently, so guard the whole class rather than one node type at a time."""
        proj = self.proj
        cfg = proj.kb.cfgs.get_most_accurate()
        c_dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg, flavor="pseudocode", fail_fast=True)
        assert c_dec.codegen is not None

        missing = set(c_dec.codegen._handlers) - set(self.codegen._handlers)
        assert not missing, f"Rust backend has no handler for {sorted(str(k) for k in missing)}"

    def test_insert(self):
        m = self._manager()
        expr = Insert(
            m.next_atom(),
            self._vvar(m, 1),
            Const(m.next_atom(), 0, 8),
            self._vvar(m, 2, bits=32),
            "Iend_LE",
        )

        out = _render(self.codegen._handle(expr))
        assert "_INSERT(" in out
        assert PLACEHOLDER not in out

    def test_dirty_statement(self):
        m = self._manager()
        dirty = DirtyExpression(m.next_atom(), "amd64g_dirtyhelper_RDTSC", [], bits=64)
        stmt = DirtyStatement(m.next_atom(), dirty, ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "amd64g_dirtyhelper_RDTSC" in out
        assert PLACEHOLDER not in out

    def test_weak_assignment(self):
        m = self._manager()
        stmt = WeakAssignment(m.next_atom(), self._vvar(m, 1), self._vvar(m, 2), ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "=" in out
        assert PLACEHOLDER not in out

    def test_cas(self):
        m = self._manager()
        stmt = CAS(
            m.next_atom(),
            Const(m.next_atom(), 0x1000, 64),
            Const(m.next_atom(), 1, 32),
            None,
            Const(m.next_atom(), 0, 32),
            None,
            self._vvar(m, 2, bits=32),
            None,
            "Iend_LE",
            ins_addr=0x400100,
        )

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "atomic_compare_exchange" in out
        assert PLACEHOLDER not in out

    def test_incomplete_switch_case_head_statement(self):
        m = self._manager()
        case_blocks = [Block(0x400200 + i, 1, statements=[]) for i in range(2)]
        stmt = IncompleteSwitchCaseHeadStatement(
            m.next_atom(),
            self._vvar(m, 1),
            [
                (case_blocks[0], 0, 0x400300, None, 0x400210),
                (case_blocks[1], 1, 0x400400, None, 0x400220),
                (None, "default", 0x400500, None, 0x400230),
            ],
            ins_addr=0x400100,
        )

        out = _render(self.codegen._handle(stmt, is_expr=False))
        # every case target has to survive, plus the default
        assert "0x400300" in out
        assert "0x400400" in out
        assert "0x400500" in out
        assert PLACEHOLDER not in out

    def test_incomplete_switch_case_node(self):
        m = self._manager()
        head = Block(
            0x400100, 1, statements=[Jump(m.next_atom(), Const(m.next_atom(), 0x400200, 64), ins_addr=0x400100)]
        )
        cases = [
            SequenceNode(
                0x400200,
                nodes=[
                    Block(
                        0x400200,
                        1,
                        statements=[Jump(m.next_atom(), Const(m.next_atom(), 0x400300, 64), ins_addr=0x400200)],
                    )
                ],
            )
        ]
        node = IncompleteSwitchCaseNode(0x400100, head, cases)

        out = _render(self.codegen._handle(node, is_expr=False))
        assert "incomplete" in out
        assert "0x400200" in out
        assert PLACEHOLDER not in out

    def test_bbbq_rust_flavor_has_no_placeholders(self):
        bin_path = os.path.join(test_location, "x86_64", "bbbq")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x410920, expand_call_tree=False, run_ccc=False)
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(0x410920, cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert PLACEHOLDER not in text
        # the bit-insertions that used to be dropped are rendered now
        assert "_INSERT(" in text


class TestRustStoreWidth(unittest.TestCase):
    """A store's emitted Rust has to write as many bytes as the AIL store writes."""

    @classmethod
    def setUpClass(cls):
        # any binary will do: we only need a constructed Rust code generator to drive the handler with
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model, flavor="rust", fail_fast=True)
        assert isinstance(dec.codegen, RustStructuredCodeGenerator)
        cls.codegen = dec.codegen

    def _store(self, idx: int, value_type, value_bits: int, size: int):
        # the destination is what _access turns into the dereference, so its type is the width written
        data = Const(idx, 0, value_bits, type=value_type)
        # an address inside no section, so the constant handler cannot retype it as a string or a function pointer
        stmt = Store(idx, Const(idx, 0x7FFF00000000, 64), data, size, "Iend_LE")
        return self.codegen._handle(stmt, is_expr=False)

    def test_value_typed_narrower_than_the_store(self):
        assert self._store(1, RustSimTypeInt(size=32, signed=False), 32, 8).lhs.type.size == 64

    def test_value_typed_wider_than_the_store(self):
        assert self._store(2, RustSimTypeInt(size=64, signed=False), 64, 1).lhs.type.size == 8

    def test_value_with_no_inferred_type(self):
        # SimTypeBottom carries no size at all, so the store width is the only information there is
        store = self._store(3, SimTypeBottom(), 128, 16)
        assert store.lhs.type.size == 128
        # Rust has a native 128-bit integer, so the repaired width is spelled directly
        assert "u128" in _render(store)

    def test_value_typed_correctly_is_left_alone(self):
        assert self._store(4, RustSimTypeInt(size=64, signed=False), 64, 8).lhs.type.size == 64

    def test_aggregate_value_is_not_cast(self):
        # a scalar cast cannot change the width of a &str, so the mismatch is reported, not "repaired"
        store = self._store(5, RustSimTypeStrRef(), 128, 8)
        assert store.lhs.type.size == 128

    def test_value_with_no_type_at_all(self):
        """A value whose type comes back None must not take the handler down.

        RustIndexedVariable and RustBinaryOp both return None for a type they cannot work out.
        Guarding only the diagnostic, as the C backend does, moves the crash from the diagnostic
        into _access ("no type whatsoever for dereference"), so the value is retyped instead.
        """

        class Untyped(RustExpression):
            """stands in for any Rust expression whose type comes back None"""

            __slots__ = ()

            @property
            def type(self):
                return None

            def c_repr_chunks(self, indent=0, asexpr=False):
                yield "UNTYPED", self

        untyped = Untyped(codegen=self.codegen)
        real_handle = self.codegen._handle

        def handle(node, **kwargs):
            # the AIL layer does not preserve object identity, so key on the constant's value
            return untyped if getattr(node, "value", None) == 0xD1CE else real_handle(node, **kwargs)

        stmt = Store(6, Const(6, 0x7FFF00000000, 64), Const(6, 0xD1CE, 64), 8, "Iend_LE")
        with mock.patch.object(self.codegen, "_handle", handle):
            store = RustStructuredCodeGenerator._handle_Stmt_Store(self.codegen, stmt)
        assert store.lhs.type.size == 64


if __name__ == "__main__":
    unittest.main()
