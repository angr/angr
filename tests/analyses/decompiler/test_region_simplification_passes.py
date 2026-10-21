#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.ailment import Manager
from angr.analyses.decompiler.counters.seq_cf_structure_counter import ControlFlowStructureCounter
from angr.analyses.decompiler.optimization_passes.lowered_switch_simplifier import LoweredSwitchSimplifier
from angr.analyses.decompiler.optimization_passes.optimization_pass import StructuringOptimizationPass
from angr.analyses.decompiler.region_simplifiers import REGION_SIMPLIFICATION_PASSES
from angr.analyses.decompiler.region_simplifiers.switch_cluster_simplifier import SwitchClusterFinder
from angr.analyses.decompiler.structurer_nodes import (
    CascadingConditionNode,
    ConditionNode,
    LoopNode,
    MultiNode,
    SequenceNode,
    SwitchCaseNode,
)
from angr.analyses.decompiler.utils import copy_graph
from angr.analyses.decompiler.variable_map import variable_map_of
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


def _shape(node) -> tuple:
    """Node kinds and loop kinds of a structured region, without expressions or statements."""
    if isinstance(node, (SequenceNode, MultiNode)):
        return (type(node).__name__, tuple(_shape(n) for n in node.nodes))
    if isinstance(node, LoopNode):
        return ("Loop", node.sort, _shape(node.sequence_node))
    if isinstance(node, ConditionNode):
        return ("Condition", _shape(node.true_node), _shape(node.false_node))
    if isinstance(node, CascadingConditionNode):
        return ("Cascading", tuple(_shape(n) for _, n in node.condition_and_nodes), _shape(node.else_node))
    if isinstance(node, SwitchCaseNode):
        return ("Switch", tuple((k, _shape(n)) for k, n in node.cases.items()), _shape(node.default_node))
    return (type(node).__name__,)


class TestRegionSimplificationPasses(unittest.TestCase):
    def test_schedule(self):
        names = [p.name for p in REGION_SIMPLIFICATION_PASSES]
        expression_only = [p.name for p in REGION_SIMPLIFICATION_PASSES if not p.changes_structure]
        assert expression_only == ["OneUseExpressionFolding", "LoopCounterNaming"]
        # the goto manager must be produced before any skipped pass
        assert names.index("GotoSimplification") < names.index("OneUseExpressionFolding")
        assert StructuringOptimizationPass.PROBE_STRUCTURE_ONLY is True
        assert LoweredSwitchSimplifier.PROBE_STRUCTURE_ONLY is False

    def test_structure_only_mode_keeps_structure_and_gotos(self):
        bin_path = os.path.join(test_location, "x86_64", "cfg_switches")
        p, cfg = load_project_with_scoped_cfg(bin_path, 0x4006C2)
        func = cfg.kb.functions[0x4006C2]
        clinic = p.analyses.Clinic(func)
        arg_vvars = set(clinic.arg_vvars) if clinic.arg_vvars is not None else set()

        results = []
        for structure_only in (False, True):
            ri = p.analyses.RegionIdentifier(func, graph=copy_graph(clinic.graph))
            rs = p.analyses.RecursiveStructurer(ri.region, ail_manager=Manager())
            s = p.analyses.RegionSimplifier(
                func, rs.result, clinic._ail_manager, arg_vvars=arg_vvars, structure_only=structure_only
            )
            counter = ControlFlowStructureCounter(s.result)
            finder = SwitchClusterFinder(s.result, variable_map_of(clinic._ail_manager))
            results.append(
                (
                    s.goto_manager.gotos,
                    (counter.while_loops, counter.do_while_loops, counter.for_loops),
                    counter.ordered_labels,
                    dict(counter.goto_targets),
                    len(finder.var2switches),
                    _shape(s.result),
                )
            )

        assert results[0] == results[1]
        assert results[0][4] >= 1


if __name__ == "__main__":
    unittest.main()
