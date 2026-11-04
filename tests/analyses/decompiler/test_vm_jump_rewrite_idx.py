#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import networkx

from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Load, VEXCCallExpression
from angr.ailment.statement import ConditionalJump, Jump, Label, Return, Store
from angr.analyses.decompiler.vm_deobfuscation_simplifier import VMDeobfuscationSimplifierMixin

from .test_vm_deobfuscation_transforms import FLAGS, G, _c, _Host, _ids, _label
from .test_vm_transform_schedule import _jump, _store

# Jump rewrites must name the successor copy (idx) they target, not only its address.


def _ret(addr, idx):
    return Block(addr, 1, statements=[Return(next(_ids), [], ins_addr=addr)], idx=idx)


def _targets(stmt):
    return (stmt.true_target.value, stmt.true_target_idx), (stmt.false_target.value, stmt.false_target_idx)


class TestAndMultipleConditionsIdx(unittest.TestCase):
    def _run(self, merge_b_addr, merge_b_idx, body_b_addr, body_b_idx):
        node = Block(0x1000, 4, statements=[_jump(0x1000, 1, 0x3000, 0x2000)])
        body_a = Block(0x2000, 4, statements=[_store(0x2000), Jump(None, Const(None, 0x3000, 64))])
        merge_a = Block(
            0x3000,
            4,
            statements=[
                Label(None, "L3000"),
                ConditionalJump(
                    None,
                    BinaryOp(None, "CmpEQ", [Const(None, 7, 64), Const(None, 0, 64)], False, bits=1),
                    Const(None, merge_b_addr, 64),
                    Const(None, body_b_addr, 64),
                    true_target_idx=merge_b_idx,
                    false_target_idx=body_b_idx,
                ),
            ],
        )
        body_b = Block(
            body_b_addr,
            4,
            statements=[_store(body_b_addr), Jump(None, Const(None, merge_b_addr, 64), target_idx=merge_b_idx)],
            idx=body_b_idx,
        )
        merge_b = Block(
            merge_b_addr, 1, statements=[Label(None, "Lm"), Return(None, [], ins_addr=merge_b_addr)], idx=merge_b_idx
        )
        graph = networkx.DiGraph(
            [(node, body_a), (node, merge_a), (body_a, merge_a), (merge_a, body_b), (merge_a, merge_b), (body_b, merge_b)]
        )
        VMDeobfuscationSimplifierMixin.and_multiple_conditions(SimpleNamespace(_ail_manager=ailment.Manager()), graph)
        return next(b for b in graph if b.addr == 0x1000)

    def test_merged_guard_names_the_copies(self):
        node = self._run(0x5000, 2, 0x4000, 0)
        assert _targets(node.statements[-1]) == ((0x5000, 2), (0x4000, 0))

    def test_copies_at_one_address_keep_their_roles(self):
        node = self._run(0x5000, 2, 0x5000, 1)
        assert _targets(node.statements[-1]) == ((0x5000, 2), (0x5000, 1))


class TestCalculateFlagsSimplifierIdx(unittest.TestCase):
    def test_rewritten_check_keeps_target_idx(self):
        expr = VEXCCallExpression(next(_ids), "x86g_calculate_eflags_all", (_c(15, 32),), bits=32)
        for value in (2, 0x10, 0x20, 0x40):
            expr = BinaryOp(next(_ids), "Or", [expr, _c(value, 32)], False)
        cond = BinaryOp(next(_ids), "CmpEQ", [BinaryOp(next(_ids), "And", [expr, _c(64, 32)], False), _c(0, 32)], False)
        jump = ConditionalJump(
            next(_ids), cond, _c(0x400010), _c(0x400010), true_target_idx=1, false_target_idx=2, ins_addr=1
        )
        head = Block(0x400000, 4, statements=[jump])
        graph = networkx.DiGraph([(head, _ret(0x400010, 1)), (head, _ret(0x400010, 2))])
        graph = _Host().calculate_flags_simplifier(graph)
        new = next(b for b in graph if b.addr == 0x400000).statements[-1]
        assert new.condition.operands[0].operands[0].op != "Or"
        assert _targets(new) == ((0x400010, 1), (0x400010, 2))


class TestRemoveRedundantConditionalCheckIdx(unittest.TestCase):
    @staticmethod
    def _graph(check_first, head_true_is_setter=True):
        """
        g = 0; if (flags & 64) == 0 goto set else goto check
        set:   g = 1; goto check
        check: if g == 0 goto d.1 else goto d.2  (two copies at one address)
        """
        flags = BinaryOp(next(_ids), "And", [Load(next(_ids), _c(FLAGS), 4, "Iend_LE"), _c(64, 32)], False)
        cond = BinaryOp(next(_ids), "CmpEQ", [flags, _c(0, 32)], False)
        t, f = (0x400010, 0x400020) if head_true_is_setter else (0x400020, 0x400010)
        head = Block(
            0x400000,
            4,
            statements=[
                _label(0x400000),
                Store(next(_ids), _c(G), _c(0, 8), 1, "Iend_LE", ins_addr=0x400000),
                ConditionalJump(next(_ids), cond, _c(t), _c(f), ins_addr=0x400001),
            ],
        )
        set_g = Block(
            0x400010,
            4,
            statements=[
                _label(0x400010),
                Store(next(_ids), _c(G), _c(1, 8), 1, "Iend_LE", ins_addr=0x400010),
                Jump(next(_ids), _c(0x400020), ins_addr=0x400011),
            ],
        )
        g_is_zero = BinaryOp(next(_ids), "CmpEQ", [Load(next(_ids), _c(G), 1, "Iend_LE"), _c(0, 8)], False)
        check_jump = ConditionalJump(
            next(_ids), g_is_zero, _c(0x400030), _c(0x400030), true_target_idx=1, false_target_idx=2, ins_addr=0x400020
        )
        check = Block(0x400020, 4, statements=[_label(0x400020), check_jump])
        d1, d2 = _ret(0x400030, 1), _ret(0x400030, 2)
        head_edges = [(head, check), (head, set_g)] if check_first else [(head, set_g), (head, check)]
        graph = networkx.DiGraph([*head_edges, (set_g, check), (check, d1), (check, d2)])
        return graph

    def _run(self, check_first, head_true_is_setter):
        graph = _Host().remove_redundant_conditional_check(self._graph(check_first, head_true_is_setter))
        assert sorted((n.addr, n.idx) for n in graph) == [(0x400000, 0), (0x400030, 1), (0x400030, 2)]
        head = next(n for n in graph if n.addr == 0x400000)
        return _targets(head.statements[-1])

    def test_check_is_left_successor(self):
        # the setter arm takes the check's false target (d.2)
        assert self._run(True, True) == ((0x400030, 2), (0x400030, 1))
        assert self._run(True, False) == ((0x400030, 1), (0x400030, 2))

    def test_check_is_right_successor(self):
        assert self._run(False, True) == ((0x400030, 2), (0x400030, 1))
        assert self._run(False, False) == ((0x400030, 1), (0x400030, 2))


if __name__ == "__main__":
    unittest.main()
