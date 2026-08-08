#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest
from collections import OrderedDict

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump
from angr.analyses.decompiler.region_simplifiers.switch_cluster_simplifier import (
    CmpOp,
    ConditionalRegion,
    SwitchCaseRegion,
    simplify_switch_clusters,
)
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode, SwitchCaseNode
from angr.analyses.decompiler.utils import sequence_to_blocks
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

# codegen falls back to this form when a goto target has no label in the output
_DANGLING_GOTO = re.compile(r"goto (LABEL_0x\w+);")


class TestSwitchClusterSimplifier(unittest.TestCase):
    def test_merge_keeps_every_default_node_block(self):
        """
        Two switches on the same variable, each guarded by a condition, whose default-case nodes are separate copies
        sharing an address -- what SwitchDefaultCaseDuplicator plus structuring produce. The merged switch-case can
        only carry one default node, so merging here would drop the blocks under the other copy.
        """
        m = Manager(arch=None)

        def block(addr, target):
            return Block(addr, 1, statements=[Jump(m.next_atom(), Const(m.next_atom(), target, 64))])

        def switch(addr, case_ids, default_node):
            cases = OrderedDict(
                (case_id, SequenceNode(addr + 0x10 + i, nodes=[block(addr + 0x10 + i, 0x1000)]))
                for i, case_id in enumerate(case_ids)
            )
            return SwitchCaseNode(Const(m.next_atom(), 0, 32), cases, default_node, addr=addr)

        # both default nodes live at 0x500, but only one of them holds the code below the switch
        stub_default = SequenceNode(0x500, nodes=[block(0x500, 0x1000)])
        real_default = SequenceNode(0x500, nodes=[block(0x500, 0x600), block(0x600, 0x1000)])

        switch0, switch1 = switch(0x100, [0, 1], stub_default), switch(0x200, [2, 3], real_default)
        cond0 = ConditionNode(0xF0, None, Const(m.next_atom(), 1, 8), switch0)
        cond1 = ConditionNode(0xF8, None, Const(m.next_atom(), 1, 8), switch1)
        region = SequenceNode(0xF0, nodes=[cond0, cond1])

        var = "switch_variable"
        cond_regions = [
            ConditionalRegion(var, CmpOp.LT, 2, cond0, region),
            ConditionalRegion(var, CmpOp.GT, 1, cond1, region),
        ]
        switch_regions = [SwitchCaseRegion(var, switch0, cond0), SwitchCaseRegion(var, switch1, cond1)]
        simplify_switch_clusters(region, {var: cond_regions}, {var: switch_regions})

        # 0x600 only exists under real_default; losing it means the merge threw away a default node
        assert 0x600 in {bb.addr for bb in sequence_to_blocks(region)}

    def test_bbbq_switch_cluster_with_duplicated_default_nodes(self):
        """
        sub_410920 holds two switches on the same variable whose default-case nodes were duplicated: one copy heads
        the structured continuation of the function, the other is a two-block goto stub. Merging the switches keeps a
        single default node, so picking the stub used to drop everything below the other copy -- 247 of 332 blocks,
        leaving gotos to labels that appeared nowhere in the output.
        """
        bin_path = os.path.join(test_location, "x86_64", "bbbq")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x410920, expand_call_tree=False, run_ccc=False)
        dec = proj.analyses.Decompiler(0x410920, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        # every goto must reach a label that exists
        assert not _DANGLING_GOTO.findall(text)

        # the bulk of the function must be there: the switch cases, the loop below the default node, and the tail
        assert text.count("switch (") >= 1
        assert len(text.splitlines()) > 1000

        # piggybacking: a lock cmpxchg in this function is followed by the ITE that writes the memory value back into
        # the accumulator. CASIntrinsics used to skip that shape, and the surviving CAS statement aborted codegen.
        assert "atomic_compare_exchange" in text
        assert "CAS(" not in text


if __name__ == "__main__":
    unittest.main()
