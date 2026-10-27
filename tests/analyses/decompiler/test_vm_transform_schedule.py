#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import networkx

from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Load, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Store
from angr.analyses.decompiler.optimization_passes import OptimizationPassStage
from angr.analyses.decompiler.vm_deobfuscation_simplifier import VMDeobfuscationSimplifierMixin

NODE, BODY_A, MERGE_A, BODY_B, MERGE_B = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000
FLAG = 0x601000


def _vvar(varid):
    return VirtualVariable(None, varid, 64, VirtualVariableCategory.REGISTER, oident=16)


def _cond(varid):
    return BinaryOp(None, "CmpEQ", [_vvar(varid), Const(None, 0, 64)], False, bits=1)


def _jump(addr, cond_varid, true_target, false_target):
    return ConditionalJump(
        None, _cond(cond_varid), Const(None, true_target, 64), Const(None, false_target, 64), ins_addr=addr
    )


def _store(addr, data=None):
    data = Const(None, 1, 32) if data is None else data
    return Store(None, Const(None, FLAG, 64), data, 4, "Iend_LE", ins_addr=addr)


def _graph(arm_a=None, arm_b=None, merge_b_stmts=None):
    """node -> (body_a ->) merge_a -> (body_b ->) merge_b, both arms storing to FLAG."""
    node = Block(NODE, 4, statements=[_jump(NODE, 1, MERGE_A, BODY_A)])
    body_a = Block(BODY_A, 4, statements=[arm_a or _store(BODY_A), Jump(None, Const(None, MERGE_A, 64))])
    merge_a = Block(MERGE_A, 4, statements=[Label(None, "L3000"), _jump(MERGE_A, 2, MERGE_B, BODY_B)])
    body_b = Block(BODY_B, 4, statements=[arm_b or _store(BODY_B), Jump(None, Const(None, MERGE_B, 64))])
    merge_b = Block(
        MERGE_B, 4, statements=merge_b_stmts or [Label(None, "L5000"), Jump(None, Const(None, 0x6000, 64))]
    )
    graph = networkx.DiGraph()
    graph.add_edges_from(
        [(node, body_a), (node, merge_a), (body_a, merge_a), (merge_a, body_b), (merge_a, merge_b), (body_b, merge_b)]
    )
    return graph


def _run(graph):
    stub = SimpleNamespace(_ail_manager=ailment.Manager())
    return VMDeobfuscationSimplifierMixin.and_multiple_conditions(stub, graph)


def _block(graph, addr):
    return next((b for b in graph if b.addr == addr), None)


class TestAndMultipleConditions(unittest.TestCase):
    def test_merges_guards_around_identical_stores(self):
        out = _run(_graph())
        assert _block(out, BODY_A) is None and _block(out, MERGE_A) is None
        node = _block(out, NODE)
        jump = node.statements[-1]
        assert jump.condition.op == "LogicalAnd"
        assert jump.true_target.value == MERGE_B and jump.false_target.value == BODY_B
        assert {s.addr for s in out.successors(node)} == {MERGE_B, BODY_B}

    def test_rewrites_phi_sources_at_merge_b(self):
        phi = Assignment(None, _vvar(9), Phi(None, 64, [((MERGE_A, 0), _vvar(7)), ((BODY_B, 0), _vvar(7))]))
        out = _run(_graph(merge_b_stmts=[phi, Jump(None, Const(None, 0x6000, 64))]))
        srcs = {src for src, _ in _block(out, MERGE_B).statements[0].src.src_and_vvars}
        assert srcs == {(NODE, 0), (BODY_B, 0)}

    def test_different_arms_are_kept(self):
        out = _run(_graph(arm_b=_store(BODY_B, Const(None, 2, 32))))
        assert _block(out, BODY_A) is not None and _block(out, MERGE_A) is not None

    def test_non_idempotent_arm_is_kept(self):
        # *flag = *flag + 1 run twice is not run once
        inc = BinaryOp(None, "Add", [Load(None, Const(None, FLAG, 64), 4, "Iend_LE"), Const(None, 1, 32)], False)
        out = _run(_graph(arm_a=_store(BODY_A, inc), arm_b=_store(BODY_B, inc)))
        assert _block(out, BODY_A) is not None and _block(out, MERGE_A) is not None

    def test_vvar_defining_arm_is_kept(self):
        out = _run(
            _graph(
                arm_a=Assignment(None, _vvar(3), Const(None, 1, 64)),
                arm_b=Assignment(None, _vvar(3), Const(None, 1, 64)),
            )
        )
        assert _block(out, BODY_A) is not None and _block(out, MERGE_A) is not None


class TestSchedule(unittest.TestCase):
    def test_every_entry_is_a_transform(self):
        for name, _ in VMDeobfuscationSimplifierMixin.VM_DEOBF_TRANSFORMS:
            assert callable(getattr(VMDeobfuscationSimplifierMixin, name, None)), name

    def test_global_passes_run_at_after_global_simplification(self):
        calls = []

        def run_passes(graph, **kwargs):
            calls.append(kwargs)
            return False, graph

        stub = SimpleNamespace(_run_simplification_passes=run_passes, stack_items={}, arg_vvars={})
        graph = networkx.DiGraph()
        assert VMDeobfuscationSimplifierMixin.run_global_simplification_passes(stub, graph) is graph
        assert [c["stage"] for c in calls] == [OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION]


if __name__ == "__main__":
    unittest.main()
