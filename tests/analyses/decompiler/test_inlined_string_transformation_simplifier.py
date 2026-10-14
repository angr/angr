#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import operator
import unittest
from collections import defaultdict

import networkx

import angr
from angr import claripy
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
from angr.analyses.decompiler.optimization_passes import (
    inlined_string_transformation_simplifier as simplifier_module,
)
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

    def test_wide_shift_count_in_transformation(self):
        # A p-code INT_RIGHT takes its count from a varnode of any size, so a loaded byte can be
        # shifted by a 32-bit count. claripy refuses operands of different widths.
        b = _Builder()
        shifted = bytes(byte << 1 for byte in PLAINTEXT)
        graph = b.build(
            pred_stmts=[Store(b.atom(), b.sbo(BUF), b.const(int.from_bytes(shifted, "little")), 4, "Iend_LE")],
            store_data=b.binop(
                "Shr",
                Load(b.atom(), b.binop("Add", b.sbo(BUF), b.current), 1, "Iend_LE"),
                b.const(1, 32),
                8,
            ),
        )
        pred = self._rewrite(graph)
        assert self._byte_stores(pred) == {BUF + i: byte for i, byte in enumerate(PLAINTEXT)}


class TestUnifiedShiftWidths(unittest.TestCase):
    """The engine's shift and rotation helpers, over every width relation a count can have."""

    VALUE = 0xABCD
    BITS = 16

    def _value(self):
        return claripy.BVV(self.VALUE, self.BITS)

    @staticmethod
    def _shift(op, a, b, **kwargs):
        return simplifier_module._unified_shift(op, a, b, **kwargs)

    @staticmethod
    def _rotate(op, a, b):
        return simplifier_module._unified_rotate(op, a, b)

    def test_count_narrower_equal_and_wider_agree(self):
        # For a count the value's width can hold, every width spelling must give the same answer.
        for op, kwargs in (
            (operator.lshift, {}),
            (claripy.LShR, {}),
            (operator.rshift, {"signed": True}),
        ):
            expected = self._shift(op, self._value(), claripy.BVV(4, self.BITS), **kwargs)
            for count_bits in (8, 16, 32, 64):
                got = self._shift(op, self._value(), claripy.BVV(4, count_bits), **kwargs)
                assert got.size() == self.BITS
                assert got.concrete_value == expected.concrete_value, (op, count_bits)
        for op in (claripy.RotateLeft, claripy.RotateRight):
            expected = self._rotate(op, self._value(), claripy.BVV(4, self.BITS))
            for count_bits in (8, 16, 32, 64):
                got = self._rotate(op, self._value(), claripy.BVV(4, count_bits))
                assert got.size() == self.BITS
                assert got.concrete_value == expected.concrete_value, (op, count_bits)

    def test_count_the_value_width_cannot_hold(self):
        # 0x10000 does not fit in 16 bits, so truncating the count would answer `x` where every one
        # of these shifts gives 0 or a sign fill. The value is widened instead.
        count = claripy.BVV(0x10000, 32)
        assert self._shift(operator.lshift, self._value(), count).concrete_value == 0
        assert self._shift(claripy.LShR, self._value(), count).concrete_value == 0
        assert self._shift(operator.rshift, self._value(), count, signed=True).concrete_value == 0xFFFF
        positive = claripy.BVV(0x1234, self.BITS)
        assert self._shift(operator.rshift, positive, count, signed=True).concrete_value == 0
        # 0x10000 is a whole number of 16-bit rotations, so a rotation by it is the identity
        for op in (claripy.RotateLeft, claripy.RotateRight):
            assert self._rotate(op, self._value(), count).concrete_value == self.VALUE

    def test_rotation_count_wider_than_a_width_that_is_not_a_power_of_two(self):
        # Narrowing a count by truncation alone keeps it modulo a power of two, which is the
        # rotation's modulus only for a power-of-two width. 8 rotations of a 3-bit value is two.
        value = claripy.BVV(0b101, 3)
        for op, expected in ((claripy.RotateLeft, 0b110), (claripy.RotateRight, 0b011)):
            got = self._rotate(op, value, claripy.BVV(8, 32))
            assert got.size() == 3
            assert got.concrete_value == expected, (op, got.concrete_value)
            assert got.concrete_value == op(value, claripy.BVV(2, 3)).concrete_value

    def test_result_keeps_the_shifted_value_width(self):
        for count_bits in (8, 16, 32):
            count = claripy.BVV(4, count_bits)
            assert self._shift(claripy.LShR, self._value(), count).size() == self.BITS
            assert self._rotate(claripy.RotateLeft, self._value(), count).size() == self.BITS


if __name__ == "__main__":
    unittest.main()
