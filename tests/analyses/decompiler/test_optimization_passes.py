#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import unittest
from types import SimpleNamespace

import networkx

import angr
from angr.ailment import Block
from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import BinaryOp, Call, Const, Load, Register, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, ConditionalJump, Return, Store, WeakAssignment
from angr.analyses.decompiler.optimization_passes import DetermineLoadSizes, FlipBooleanCmp
from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    StructuringOptimizationPass,
    StructuringOptimizationPassResult,
)
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode

log = logging.getLogger(__name__)
# log.setLevel(logging.DEBUG)


def c(v):
    """Simple AIL Const shorthand"""
    return Const(0, v, 32)


def r(o):
    """Simple AIL Register shorthand"""
    return Register(0, o, 32)


class _FixedPointLifecyclePass(StructuringOptimizationPass):
    def __init__(  # pylint:disable=super-init-not-called
        self,
        results,
        structurability_results=(),
        max_opt_iters=5,
        require_structurable_graph=True,
        recover_structure_fails=True,
        require_gotos=False,
        prevent_new_gotos=False,
    ):
        self._graph = networkx.DiGraph()
        self.out_graph = networkx.DiGraph()
        self._results = iter(results)
        self._structurability_results = iter(structurability_results)
        self._max_opt_iters = max_opt_iters
        self._require_structurable_graph = require_structurable_graph
        self._prevent_new_gotos = prevent_new_gotos
        self._must_improve_rel_quality = False
        self._simplify_ail = False
        self._require_gotos = require_gotos
        self._recover_structure_fails = recover_structure_fails
        self._readd_labels = False
        self.analysis_count = 0
        self.structurability_checks = 0

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        self.analysis_count += 1
        result = next(self._results)
        if result is StructuringOptimizationPassResult.UPDATED or result is True:
            assert self.out_graph is not None
            self.out_graph.add_node(Block(self.analysis_count, 0))
        return result

    def _graph_is_structurable(self, graph, readd_labels=False, initial=False):
        self.structurability_checks += 1
        structurable = next(self._structurability_results, True)
        if structurable:
            self._goto_manager = SimpleNamespace(gotos=set())
        return structurable


class _FixedPointStatementRollbackPass(_FixedPointLifecyclePass):
    def __init__(self):
        super().__init__(
            [StructuringOptimizationPassResult.UPDATED, StructuringOptimizationPassResult.UPDATED],
            [True, False],
        )

    def _analyze(self, cache=None):
        self.analysis_count += 1
        assert self.out_graph is not None
        if self.analysis_count == 1:
            self.out_graph.add_node(Block(1, 0, statements=[Return(0, [])]))
        else:
            node = next(iter(self.out_graph))
            node.statements[0] = Return(1, [])
        return StructuringOptimizationPassResult.UPDATED


class _FixedPointAttributeRollbackPass(_FixedPointLifecyclePass):
    def __init__(self):
        super().__init__(
            [StructuringOptimizationPassResult.UPDATED, StructuringOptimizationPassResult.UPDATED],
            [True, False],
        )

    def _analyze(self, cache=None):
        self.analysis_count += 1
        assert self.out_graph is not None
        if self.analysis_count == 1:
            src = Block(1, 0)
            dst = Block(2, 0)
            self.out_graph.graph["status"] = "accepted"
            self.out_graph.add_node(src, original_nodes=[src])
            self.out_graph.add_node(dst)
            self.out_graph.add_edge(src, dst, type="accepted")
        else:
            src, dst = sorted(self.out_graph, key=lambda node: node.addr)
            self.out_graph.graph["status"] = "rejected"
            self.out_graph.nodes[src]["original_nodes"] = []
            self.out_graph[src][dst]["type"] = "rejected"
        return StructuringOptimizationPassResult.UPDATED


# pylint:disable=protected-access
class TestStructuringOptimizationPass(unittest.TestCase):
    def test_fixed_point_retry_without_graph_update_is_not_output(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.RETRY, StructuringOptimizationPassResult.STOP]
        )

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 2)
        self.assertEqual(optimization_pass.structurability_checks, 0)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_graph_update_is_output(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.UPDATED, StructuringOptimizationPassResult.STOP]
        )

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 2)
        self.assertEqual(optimization_pass.structurability_checks, 1)
        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        self.assertEqual({node.addr for node in optimization_pass.out_graph}, {1})

    def test_fixed_point_rolled_back_graph_update_is_not_output(self):
        optimization_pass = _FixedPointLifecyclePass([StructuringOptimizationPassResult.UPDATED], [False])

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertEqual(optimization_pass.structurability_checks, 1)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_failed_graph_update_restores_last_accepted_graph_and_stops(self):
        optimization_pass = _FixedPointLifecyclePass(
            [
                StructuringOptimizationPassResult.UPDATED,
                StructuringOptimizationPassResult.UPDATED,
                StructuringOptimizationPassResult.UPDATED,
            ],
            [True, False],
        )

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 2)
        self.assertEqual(optimization_pass.structurability_checks, 2)
        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        self.assertEqual({node.addr for node in optimization_pass.out_graph}, {1})

    def test_fixed_point_failed_graph_update_without_recovery_discards_output(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.UPDATED],
            [False],
            recover_structure_fails=False,
        )

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertEqual(optimization_pass.structurability_checks, 1)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_update_skips_structurability_when_not_required(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.UPDATED, StructuringOptimizationPassResult.STOP],
            [False],
            require_structurable_graph=False,
        )

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 2)
        self.assertEqual(optimization_pass.structurability_checks, 0)
        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        self.assertEqual({node.addr for node in optimization_pass.out_graph}, {1})

    def test_fixed_point_stop_halts(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.STOP, StructuringOptimizationPassResult.UPDATED]
        )

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertEqual(optimization_pass.structurability_checks, 0)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_max_iters_one_retry_is_not_output(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.RETRY],
            max_opt_iters=1,
            require_structurable_graph=False,
        )

        optimization_pass._analyze_and_verify()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertEqual(optimization_pass.structurability_checks, 0)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_retries_are_bounded_by_max_iters(self):
        optimization_pass = _FixedPointLifecyclePass([StructuringOptimizationPassResult.RETRY] * 4, max_opt_iters=3)

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 3)
        self.assertEqual(optimization_pass.structurability_checks, 0)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_bool_results_remain_supported(self):
        optimization_pass = _FixedPointLifecyclePass([True, False], max_opt_iters=2)

        optimization_pass._fixed_point_analyze()

        self.assertEqual(optimization_pass.analysis_count, 2)
        self.assertEqual(optimization_pass.structurability_checks, 1)
        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        self.assertEqual({node.addr for node in optimization_pass.out_graph}, {1})

    def test_fixed_point_rejects_invalid_result(self):
        optimization_pass = _FixedPointLifecyclePass([None])

        with self.assertRaisesRegex(TypeError, "Unexpected structuring optimization pass result None"):
            optimization_pass._fixed_point_analyze()

    def test_single_iteration_rejects_invalid_result(self):
        optimization_pass = _FixedPointLifecyclePass(
            [None],
            max_opt_iters=1,
            require_structurable_graph=False,
        )

        with self.assertRaisesRegex(TypeError, "Unexpected structuring optimization pass result None"):
            optimization_pass._analyze_and_verify()

    def test_initial_structurability_failure_stops_goto_dependent_pass(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.UPDATED],
            [False],
            require_structurable_graph=False,
            require_gotos=True,
        )
        optimization_pass.out_graph = None

        optimization_pass._analyze_and_verify()

        self.assertEqual(optimization_pass.analysis_count, 0)
        self.assertEqual(optimization_pass.structurability_checks, 1)
        self.assertIsNone(optimization_pass.out_graph)

    def test_single_iteration_refreshes_structurability_for_goto_checks(self):
        optimization_pass = _FixedPointLifecyclePass(
            [StructuringOptimizationPassResult.UPDATED],
            [True, False],
            max_opt_iters=1,
            require_structurable_graph=False,
            prevent_new_gotos=True,
        )

        optimization_pass._analyze_and_verify()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertEqual(optimization_pass.structurability_checks, 2)
        self.assertIsNone(optimization_pass.out_graph)

    def test_fixed_point_rollback_restores_block_statements(self):
        optimization_pass = _FixedPointStatementRollbackPass()

        optimization_pass._fixed_point_analyze()

        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        node = next(iter(optimization_pass.out_graph))
        self.assertEqual(node.statements[0].idx, 0)

    def test_fixed_point_rollback_restores_graph_attributes(self):
        optimization_pass = _FixedPointAttributeRollbackPass()

        optimization_pass._fixed_point_analyze()

        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        src, dst = sorted(optimization_pass.out_graph, key=lambda node: node.addr)
        self.assertEqual(optimization_pass.out_graph.graph["status"], "accepted")
        self.assertEqual(optimization_pass.out_graph.nodes[src]["original_nodes"], [src])
        self.assertEqual(optimization_pass.out_graph[src][dst]["type"], "accepted")

    def test_single_iteration_bool_update_is_output(self):
        optimization_pass = _FixedPointLifecyclePass([True], max_opt_iters=1)

        optimization_pass._analyze_and_verify()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertIsNotNone(optimization_pass.out_graph)
        assert optimization_pass.out_graph is not None
        self.assertEqual({node.addr for node in optimization_pass.out_graph}, {1})

    def test_single_iteration_bool_no_update_is_not_output(self):
        optimization_pass = _FixedPointLifecyclePass([False], max_opt_iters=1)

        optimization_pass._analyze_and_verify()

        self.assertEqual(optimization_pass.analysis_count, 1)
        self.assertIsNone(optimization_pass.out_graph)


# pylint:enable=protected-access
class TestFlipBooleanCmp(unittest.TestCase):
    """
    Test FlipBooleanCmp optimization pass.
    """

    def test_type2_store_not_moved(self):
        """
        Ensure that:

            v0 = 123;
            if (v0 <= 1000)
                v0 = 456;
            g_deadbeef = v0;
            return;

        is not mistakenly transformed to:

            v0 = 123;
            if (v0 > 1000) {
                g_deadbeef = v0;
                return;
            }
            v0 = 456;
        """
        flip_size = 1

        block_0 = Block(
            0x400000,
            1,
            statements=[
                Assignment(0, r(0), c(0x123)),
                ConditionalJump(
                    1, BinaryOp(2, "CmpLE", [r(0), c(0x1000)], False), c(0x400023), c(0x400037), ins_addr=0x400001
                ),
            ],
        )
        block_1 = Block(0x400023, 1, statements=[Assignment(3, r(0), c(0x456)) for _ in range(flip_size)])
        block_2 = Block(
            0x400037,
            1,
            statements=[
                Store(4, c(0xDEADBEEF), r(0), 4, "Iend_LE"),  # Must not be moved
                Return(5, []),
            ],
        )

        graph = networkx.DiGraph()
        graph.add_edges_from([(block_0, block_1), (block_0, block_2), (block_1, block_2)])

        func = None
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        ri = proj.analyses.RegionIdentifier(func, graph=graph)
        rs = proj.analyses.RecursiveStructurer(ri.region, ail_manager=Manager())
        seq = rs.result

        assert isinstance(seq, SequenceNode)
        assert len(seq.nodes) == 3
        assert isinstance(seq.nodes[0], Block)
        assert isinstance(seq.nodes[1], ConditionNode)
        assert isinstance(seq.nodes[2], Block)
        assert isinstance(seq.nodes[2].statements[0], Store)
        assert isinstance(seq.nodes[2].statements[1], Return)

        pre_transform_seq_repr = seq.dbg_repr()
        log.debug("Before:\n%s", pre_transform_seq_repr)

        manager = Manager()
        FlipBooleanCmp(func, manager, flip_size=flip_size, seq=seq, graph=graph)

        post_transform_seq_repr = seq.dbg_repr()
        log.debug("After:\n%s", post_transform_seq_repr)

        assert pre_transform_seq_repr == post_transform_seq_repr

    def test_type2_call_not_moved(self):
        """
        Ensure that:

            v0 = 123;
            if (v0 <= 1000)
                v0 = 456;
            always_called(v0);
            return;

        is not mistakenly transformed to:

            v0 = 123;
            if (v0 > 1000) {
                always_called(v0);
                return;
            }
            v0 = 456;
        """
        flip_size = 1

        block_0 = Block(
            0x400000,
            1,
            statements=[
                Assignment(0, r(0), c(0x123)),
                ConditionalJump(
                    1, BinaryOp(2, "CmpLE", [r(0), c(0x1000)], False), c(0x400023), c(0x400037), ins_addr=0x400001
                ),
            ],
        )
        block_1 = Block(0x400023, 1, [Assignment(3, r(0), c(0x456)) for _ in range(flip_size)])
        block_2 = Block(
            0x400037,
            1,
            statements=[
                Call(4, "always_called", [r(0)]),  # Must not be moved
                Return(5, []),
            ],
        )

        graph = networkx.DiGraph()
        graph.add_edges_from([(block_0, block_1), (block_0, block_2), (block_1, block_2)])

        func = None
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        ri = proj.analyses.RegionIdentifier(func, graph=graph)
        rs = proj.analyses.RecursiveStructurer(ri.region, ail_manager=Manager())
        seq = rs.result

        assert isinstance(seq, SequenceNode)
        assert len(seq.nodes) == 3
        assert isinstance(seq.nodes[0], Block)
        assert isinstance(seq.nodes[1], ConditionNode)
        assert isinstance(seq.nodes[2], Block)
        assert isinstance(seq.nodes[2].statements[0], Call)
        assert isinstance(seq.nodes[2].statements[1], Return)

        pre_transform_seq_repr = seq.dbg_repr()
        log.debug("Before:\n%s", pre_transform_seq_repr)

        manager = Manager()
        FlipBooleanCmp(func, manager, flip_size=flip_size, seq=seq, graph=graph)

        post_transform_seq_repr = seq.dbg_repr()
        log.debug("After:\n%s", post_transform_seq_repr)

        assert pre_transform_seq_repr == post_transform_seq_repr


class TestDetermineLoadSizes(unittest.TestCase):
    """
    Test DetermineLoadSizes optimization pass.
    """

    STRING_ADDR = 0x400000

    def _make_project_and_func(self):
        proj = angr.load_shellcode(b"hello\x00", "AMD64", load_address=self.STRING_ADDR)
        return proj, proj.kb.functions.function(addr=self.STRING_ADDR, create=True)

    @staticmethod
    def _run(func, graph) -> Block:
        DetermineLoadSizes(func, Manager(), graph=graph)
        return next(iter(graph.nodes))

    def test_string_load_size_is_determined(self):
        # v0 =w *(0x400000) with an undetermined size is the string at 0x400000
        proj, func = self._make_project_and_func()
        vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
        load = Load(1, Const(2, self.STRING_ADDR, 64), UNDETERMINED_SIZE, "Iend_LE")
        graph = networkx.DiGraph()
        graph.add_node(
            Block(self.STRING_ADDR, 1, statements=[WeakAssignment(0, vvar, load, ins_addr=self.STRING_ADDR)])
        )

        stmt = self._run(func, graph).statements[0]
        assert isinstance(stmt, WeakAssignment)
        assert isinstance(stmt.src, Load)
        assert stmt.src.size == len(proj.loader.memory.load_null_terminated_bytes(self.STRING_ADDR))

    def test_string_load_size_is_determined_in_addition(self):
        # the C++ operator+ rewrite puts the load inside an addition
        proj, func = self._make_project_and_func()
        vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
        load = Load(1, Const(2, self.STRING_ADDR, 64), UNDETERMINED_SIZE, "Iend_LE")
        addition = BinaryOp(3, "Add", [vvar, load], False)
        graph = networkx.DiGraph()
        graph.add_node(
            Block(self.STRING_ADDR, 1, statements=[WeakAssignment(0, vvar, addition, ins_addr=self.STRING_ADDR)])
        )

        stmt = self._run(func, graph).statements[0]
        assert isinstance(stmt, WeakAssignment)
        assert isinstance(stmt.src, BinaryOp)
        assert isinstance(stmt.src.operands[1], Load)
        assert stmt.src.operands[1].size == len(proj.loader.memory.load_null_terminated_bytes(self.STRING_ADDR))

    def test_load_from_unmapped_address_is_left_alone(self):
        _, func = self._make_project_and_func()
        vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
        load = Load(1, Const(2, 0x800000, 64), UNDETERMINED_SIZE, "Iend_LE")
        graph = networkx.DiGraph()
        graph.add_node(
            Block(self.STRING_ADDR, 1, statements=[WeakAssignment(0, vvar, load, ins_addr=self.STRING_ADDR)])
        )

        stmt = self._run(func, graph).statements[0]
        assert isinstance(stmt, WeakAssignment)
        assert isinstance(stmt.src, Load)
        assert stmt.src.size == UNDETERMINED_SIZE


if __name__ == "__main__":
    unittest.main()
