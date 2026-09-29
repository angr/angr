#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from collections import defaultdict

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Load,
    Phi,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, SideEffectStatement, Store
from angr.analyses.decompiler.optimization_passes.inlined_string_transformation_simplifier import (
    InlinedStringTransformationSimplifier,
)

PRED, LOOP, SUCC = 0x1000, 0x1010, 0x1020
BUF = -16
KEY = 0x20
PLAINTEXT = b"TEST"
ENCODED = bytes(b ^ KEY for b in PLAINTEXT)


class _Builder:
    """
    Builds a predecessor -> self-loop -> successor graph that decodes a 4-byte stack buffer one byte per iteration.
    """

    def __init__(self):
        self.manager = Manager()
        self.initial, self.current, self.updated, self.loaded = (
            self.reg(0),
            self.reg(1),
            self.reg(2),
            self.reg(3, 8),
        )

    def atom(self) -> int:
        return self.manager.next_atom()

    def const(self, value: int, bits: int = 32) -> Const:
        return Const(self.atom(), value, bits)

    def reg(self, varid: int, bits: int = 32) -> VirtualVariable:
        return VirtualVariable(self.atom(), varid, bits, VirtualVariableCategory.REGISTER, 8)

    def sbo(self, offset: int) -> StackBaseOffset:
        return StackBaseOffset(self.atom(), 32, offset)

    def binop(self, op: str, a, b, bits: int = 32) -> BinaryOp:
        return BinaryOp(self.atom(), op, [a, b], bits=bits)

    def build(
        self,
        mode: str = "embedded",
        *,
        pred_stmts=None,
        load_addr=None,
        store_data=None,
        loop_extra=(),
        succ_stmts=(),
        bound: int = len(PLAINTEXT),
    ):
        pointer = mode == "pointer"
        if pred_stmts is None:
            pred_stmts = [
                Store(self.atom(), self.sbo(BUF), self.const(int.from_bytes(ENCODED, "little")), 4, "Iend_LE")
            ]
        pred = Block(
            PRED,
            1,
            statements=[
                *pred_stmts,
                Assignment(self.atom(), self.initial, self.sbo(BUF) if pointer else self.const(0)),
                Jump(self.atom(), self.const(LOOP)),
            ],
        )
        address = self.current if pointer else self.binop("Add", self.sbo(BUF), self.current)
        load = Load(self.atom(), load_addr if load_addr is not None else address, 1, "Iend_LE")
        stmts = [
            Assignment(
                self.atom(),
                self.current,
                Phi(self.atom(), 32, [((PRED, None), self.initial), ((LOOP, None), self.updated)]),
            )
        ]
        if mode == "split":
            stmts.append(Assignment(self.atom(), self.loaded, load))
            value = self.loaded
        else:
            value = load
        if store_data is None:
            store_data = self.binop("Xor", value, self.const(KEY, 8), 8)
        end = self.binop("Add", self.sbo(BUF), self.const(bound)) if pointer else self.const(bound)
        stmts += [
            *loop_extra,
            Store(self.atom(), address, store_data, 1, "Iend_LE"),
            Assignment(self.atom(), self.updated, self.binop("Add", self.current, self.const(1))),
            ConditionalJump(self.atom(), self.binop("CmpEQ", self.updated, end, 1), self.const(SUCC), self.const(LOOP)),
        ]
        loop = Block(LOOP, 1, statements=stmts)
        succ = Block(SUCC, 1, statements=list(succ_stmts))
        return networkx.DiGraph([(pred, loop), (loop, loop), (loop, succ)])


class _InspectTransformation(InlinedStringTransformationSimplifier):
    """Collect descriptors without rewriting the graph."""

    def analyze(self):
        self.descriptors = self._find_string_transformation_loops()


class TestInlinedStringTransformationSimplifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = angr.load_shellcode(b"\x90", arch="x86", load_address=PRED)
        cls.function = project.kb.functions.function(addr=PRED, create=True)

    def _descriptors(self, graph):
        return _InspectTransformation(self.function, Manager(), graph=graph).descriptors

    def _rewrite(self, graph) -> Block:
        blocks_by_addr = defaultdict(set)
        for node in graph:
            blocks_by_addr[node.addr].add(node)
        simplifier = InlinedStringTransformationSimplifier(
            self.function,
            Manager(),
            graph=graph,
            blocks_by_addr=blocks_by_addr,
            blocks_by_addr_and_idx={(node.addr, node.idx): node for node in graph},
        )
        out = simplifier.out_graph
        assert out is not None
        assert not any(node.addr == LOOP for node in out)
        pred = next(node for node in out if node.addr == PRED)
        succ = next(node for node in out if node.addr == SUCC)
        assert list(out.successors(pred)) == [succ]
        assert isinstance(pred.statements[-1], Jump) and pred.statements[-1].target.value == SUCC
        return pred

    @staticmethod
    def _byte_stores(block: Block) -> dict[int, int]:
        return {
            stmt.addr.offset: stmt.data.value
            for stmt in block.statements
            if isinstance(stmt, Store) and stmt.size == 1 and isinstance(stmt.addr, StackBaseOffset)
        }

    def _assert_decoded(self, pred: Block):
        assert self._byte_stores(pred) == {BUF + i: b for i, b in enumerate(PLAINTEXT)}
        # the initial 4-byte store is removed
        assert not any(isinstance(stmt, Store) and stmt.size == 4 for stmt in pred.statements)

    def test_load_embedded_in_store(self):
        self._assert_decoded(self._rewrite(_Builder().build("embedded")))

    def test_load_into_vvar_then_store(self):
        self._assert_decoded(self._rewrite(_Builder().build("split")))

    def test_pointer_carried_in_vvar(self):
        self._assert_decoded(self._rewrite(_Builder().build("pointer")))

    def test_const_pointer_is_not_a_stack_address(self):
        # a decoder over a global buffer must not be rewritten into stack stores
        b = _Builder()
        base = 0x7FFFFFE0
        graph = b.build(
            pred_stmts=[
                Store(b.atom(), b.const(base), b.const(int.from_bytes(ENCODED, "little")), 4, "Iend_LE"),
            ],
            load_addr=b.binop("Add", b.const(base), b.current),
        )
        assert not self._descriptors(graph)

    def test_store_depending_on_another_byte(self):
        # b[i] = b[i + 1] ^ KEY
        b = _Builder()
        graph = b.build(
            pred_stmts=[Store(b.atom(), b.sbo(BUF), b.const(int.from_bytes(ENCODED * 2, "little"), 64), 8, "Iend_LE")],
            load_addr=b.binop("Add", b.sbo(BUF + 1), b.current),
        )
        assert not self._descriptors(graph)

    def test_coincidentally_equal_values(self):
        # b[i] is loaded, but the stored value comes from an identical copy at c[i]
        b = _Builder()
        copy = BUF - 8
        graph = b.build(
            "split",
            pred_stmts=[
                Store(b.atom(), b.sbo(BUF), b.const(int.from_bytes(ENCODED, "little")), 4, "Iend_LE"),
                Store(b.atom(), b.sbo(copy), b.const(int.from_bytes(ENCODED, "little")), 4, "Iend_LE"),
            ],
            store_data=b.binop(
                "Xor", Load(b.atom(), b.binop("Add", b.sbo(copy), b.current), 1, "Iend_LE"), b.const(KEY, 8), 8
            ),
        )
        assert not self._descriptors(graph)

    def test_unknown_load(self):
        b = _Builder()
        unknown = Load(b.atom(), b.const(0x404000), 1, "Iend_LE")
        graph = b.build(
            store_data=b.binop("Xor", Load(b.atom(), b.binop("Add", b.sbo(BUF), b.current), 1, "Iend_LE"), unknown, 8)
        )
        assert not self._descriptors(graph)

    def test_call_in_loop(self):
        b = _Builder()
        call = SideEffectStatement(b.atom(), Call(b.atom(), b.const(0x401000), args=[], bits=None))
        assert not self._descriptors(b.build(loop_extra=[call]))

    def test_store_outside_region(self):
        b = _Builder()
        extra = Store(b.atom(), b.sbo(BUF - 32), b.const(0, 8), 1, "Iend_LE")
        assert not self._descriptors(b.build(loop_extra=[extra]))

    def test_unbounded_loop(self):
        assert not self._descriptors(_Builder().build(bound=0x10000))

    def test_live_out_counter_is_materialized(self):
        b = _Builder()
        use = Assignment(b.atom(), b.reg(10), b.binop("Add", b.updated, b.const(1)))
        pred = self._rewrite(b.build(succ_stmts=[use]))
        self._assert_decoded(pred)
        defs = [stmt for stmt in pred.statements if isinstance(stmt, Assignment) and stmt.dst.varid == b.updated.varid]
        assert len(defs) == 1 and isinstance(defs[0].src, Const) and defs[0].src.value == len(PLAINTEXT)

    def test_live_out_pointer_is_materialized(self):
        b = _Builder()
        use = Assignment(b.atom(), b.reg(10), Load(b.atom(), b.updated, 1, "Iend_LE"))
        pred = self._rewrite(b.build("pointer", succ_stmts=[use]))
        self._assert_decoded(pred)
        defs = [stmt for stmt in pred.statements if isinstance(stmt, Assignment) and stmt.dst.varid == b.updated.varid]
        assert len(defs) == 1
        assert isinstance(defs[0].src, StackBaseOffset) and defs[0].src.offset == BUF + len(PLAINTEXT)

    def test_live_out_unknown_value(self):
        b = _Builder()
        unknown = b.reg(11, 8)
        loop_extra = [Assignment(b.atom(), unknown, Load(b.atom(), b.const(0x404000), 1, "Iend_LE"))]
        use = Assignment(b.atom(), b.reg(10, 8), unknown)
        assert not self._descriptors(b.build(loop_extra=loop_extra, succ_stmts=[use]))

    def test_partially_covered_initial_store_is_kept(self):
        # the initial store also covers four bytes that the loop does not transform
        b = _Builder()
        init = Store(b.atom(), b.sbo(BUF), b.const(int.from_bytes(ENCODED + b"KEEP", "little"), 64), 8, "Iend_LE")
        pred = self._rewrite(b.build(pred_stmts=[init]))
        assert self._byte_stores(pred) == {BUF + i: b for i, b in enumerate(PLAINTEXT)}
        stores = [stmt for stmt in pred.statements if isinstance(stmt, Store)]
        # the 8-byte store stays in front of the new stores, which override its first four bytes
        assert stores[0] is init and len(stores) == 1 + len(PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
