#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump, Label
from angr.analyses import Decompiler
from angr.analyses.decompiler.clinic import Clinic, ClinicStage
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestMIPSBranchLikely(unittest.TestCase):
    def test_loop_head_ending_in_a_branch_likely(self):
        # The alignment loop of memchr ends in "beql $v0, $v1, 0x41dd54", whose delay slot "move $v0, $a0" sets the
        # return value when the byte matches. libVEX lifts the branch as a conditional jump followed by the delay slot,
        # so the loop head block did not end in a jump and Phoenix's while-true rewrite asserted.
        bin_path = os.path.join(test_location, "mips64", "ld.so.1")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x41DD00, project_kwargs={"auto_load_libs": False}, expand_call_tree=False, run_ccc=False
        )
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x41DD00], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not dec.structuring_failures
        # the alignment loop returns the pointer whose byte matched
        loop_bodies = re.findall(r"while \(1\)\s*\{([^{}]*)\}", dec.codegen.text)
        assert any(re.search(r"if \(\*\(char \*\)(\w+) == \w+\)\s+return \1;", body) for body in loop_bodies)

    def test_delay_slot_runs_on_the_taken_path(self):
        # "beql $a2, $a1, 0x412f44" at 0x412fc8 of _dl_sort_fini decrements s3 in its delay slot, which runs only when
        # the branch is taken. The decrement used to be printed after "if (...) goto ...; else goto ...;", where it was
        # dead code, and the taken path lost it.
        bin_path = os.path.join(test_location, "mips64", "ld.so.1")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x412CC0, project_kwargs={"auto_load_libs": False}, expand_call_tree=False, run_ccc=False
        )
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x412CC0], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        assert re.search(r"(v\d+) = (\(unsigned int\))?\1 - 1;\s+goto LABEL_412f44;", t) is not None
        assert re.search(r"else\s+goto LABEL_\w+;\n\s*v\d+ = ", t) is None

    def test_delay_slot_is_split_into_its_own_block(self):
        bin_path = os.path.join(test_location, "mips64", "ld.so.1")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x41DD00, project_kwargs={"auto_load_libs": False}, expand_call_tree=False, run_ccc=False
        )
        clinic = proj.analyses[Clinic].prep(fail_fast=True)(
            cfg.functions[0x41DD00], cfg=cfg.model, end_stage=ClinicStage.PRE_SSA_LEVEL0_FIXUPS
        )
        graph = clinic.graph
        assert graph is not None
        for block in graph:
            jump_idx = next((i for i, stmt in enumerate(block.statements) if isinstance(stmt, ConditionalJump)), None)
            if jump_idx is not None:
                assert all(isinstance(stmt, Label) for stmt in block.statements[jump_idx + 1 :]), hex(block.addr)

        # "beql $v0, $v1, 0x41dd54" at 0x41dd34: the not-taken path goes to 0x41dd3c, the taken path runs the delay
        # slot at 0x41dd38 and then goes to 0x41dd54
        delay_slot = next(block for block in graph if block.addr == 0x41DD38)
        assert delay_slot.original_size == 4
        (head,) = graph.predecessors(delay_slot)
        cond_jump = head.statements[-1]
        assert isinstance(cond_jump, ConditionalJump)
        assert isinstance(cond_jump.true_target, Const) and cond_jump.true_target.value == 0x41DD3C
        assert isinstance(cond_jump.false_target, Const) and cond_jump.false_target.value == 0x41DD38
        assert head.original_size is not None and head.addr + head.original_size == 0x41DD38
        jump = delay_slot.statements[-1]
        assert isinstance(jump, Jump) and isinstance(jump.target, Const) and jump.target.value == 0x41DD54
        assert [succ.addr for succ in graph.successors(delay_slot)] == [0x41DD54]


if __name__ == "__main__":
    unittest.main()
