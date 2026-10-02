#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.analyses.decompiler.optimization_passes import LoweredSwitchSimplifier
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
from angr.utils.ail import is_phi_assignment
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

# a character-scanning loop carved out of busybox (compiled at -O0). the comparison chain that
# LoweredSwitchSimplifier recognizes contains back edges to the head comparison node, which used to cause
# an exponential state-space explosion in the cascade traversal.
#
# unsigned int check_name(char *s) {  // originally at 0x4a7f32
#     char c, seen_dot = 0;
#     while ((c = *s++)) {
#         if (c == '.') { if (seen_dot) return 0; seen_dot = 1; }
#         else if ((c <= '/' || c > '9') && (c <= '@' || c > 'Z')) return 0;
#     }
#     return 1;
# }
CHAR_SCAN_LOOP_CODE = bytes.fromhex(
    "48897c24e8c64424ff00488b4424e8488d500148895424e80fb600884424fe"
    "807c24fe00743f807c24fe2e7514807c24ff007406b800000000c3c64424ff"
    "01eb22807c24fe2f7e07807c24fe397ebb807c24fe407e07807c24fe5a7ead"
    "b800000000c3eba590b801000000c3"
)


class TestLoweredSwitchSimplifier(unittest.TestCase):
    def test_comparison_chain_with_back_edges_terminates(self):
        proj = angr.load_shellcode(CHAR_SCAN_LOOP_CODE, "AMD64", load_address=0x4A7F32)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions[0x4A7F32]
        all_optimization_passes = DECOMPILATION_PRESETS["full"].get_optimization_passes(
            "AMD64", "linux", additional_opts=[LoweredSwitchSimplifier]
        )

        # this decompilation must terminate (it used to take exponential time and memory)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "while" in dec.codegen.text

    def test_redundant_comparison_node_removed_by_an_earlier_one(self):
        # doshn() in file(1) built at -O0 has a comparison chain whose redundant comparison nodes point at one
        # another, so removing one of them orphans the next one the same loop still has to visit.
        proj, cfg = load_project_with_scoped_cfg(os.path.join(test_location, "x86_64", "file_gcc17_O0"), 0x423B74)

        dec = proj.analyses.Decompiler(cfg.functions[0x423B74], cfg=cfg)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "switch (" in dec.codegen.text

    def test_orphaned_chain_is_removed_entirely(self):
        # the same shape at -O2, where the orphaned chain is long enough that stopping at the immediate
        # successors leaves nodes unreachable from the function entry and the structurer gives up on them.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "x86_64", "file_gcc13.3.0_O2"), 0x4091D0, window=0x3000
        )

        dec = proj.analyses.Decompiler(cfg.functions[0x4091D0], cfg=cfg)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "switch (" in dec.codegen.text

    def test_folding_a_comparison_chain_repoints_the_phis_that_named_it(self):
        # dd(1) at -O2: the comparison node 0x406e97 folds into the switch head at 0x406e92, and the phi
        # variable in 0x406ee4 named 0x406e97, a block the fold removes.
        proj, cfg = load_project_with_scoped_cfg(os.path.join(test_location, "x86_64", "decompiler", "dd"), 0x406E10)

        mismatches = []
        original_analyze = LoweredSwitchSimplifier._analyze

        def analyze_and_check(pass_, cache=None):
            result = original_analyze(pass_, cache=cache)
            if pass_.out_graph is not None:
                mismatches.append(_phis_that_miss_a_predecessor(pass_.out_graph))
            return result

        with mock.patch.object(LoweredSwitchSimplifier, "_analyze", analyze_and_check):
            dec = proj.analyses.Decompiler(cfg.functions[0x406E10], cfg=cfg)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        # a run in which the pass never produced a graph would collect no mismatch either
        assert mismatches, "LoweredSwitchSimplifier produced no graph for this function"
        assert all(not m for m in mismatches), mismatches


def _phis_that_miss_a_predecessor(graph) -> list[str]:
    """Report every phi variable whose sources are not exactly the block's predecessors."""
    reported = []
    for block in graph.nodes():
        predecessors = {(pred.addr, pred.idx) for pred in graph.predecessors(block)}
        for stmt in block.statements:
            if is_phi_assignment(stmt):
                sources = {src for src, _ in stmt.src.src_and_vvars}
                if sources != predecessors:
                    reported.append(
                        f"{block.addr:#x}-{block.idx}: {stmt.dst} from {sources}, reached from {predecessors}"
                    )
    return reported


if __name__ == "__main__":
    unittest.main()
