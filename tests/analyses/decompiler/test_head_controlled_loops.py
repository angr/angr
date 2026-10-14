#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import re
import unittest

from angr.ailment import Block
from angr.ailment.expression import Const, Phi, Register, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Return
from angr.analyses import Decompiler
from angr.analyses.decompiler.clinic import ClinicStage
from angr.utils.ail import is_head_controlled_loop_block
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result, set_decompiler_option

test_location = os.path.join(bin_location, "tests")

l = logging.getLogger(__name__)


class TestHeadControlledLoops(unittest.TestCase):
    def test_head_controlled_loop_xchg_false_positive(self):
        # a bug in ssailification.RewritingEngine causes us to misinterpret an xchg (where VEX generates a conditional
        # jump to mimic CAS effects) as a head-controlled loop (e.g., for rep stosb). as a result of this bug, we will
        # see "12" or "0xc" in the decompilation result (for the instruction at 0x140003767), which is what we are
        # testing here. Note that "v3 + 12" is intended, but "0 + 12" or "12" is not.
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "9c75d43ec531c76caa65de86dcac0269d6727ba4ec74fe1cac1fda0e176fd2ab"
        )
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x1400036C0, project_kwargs={"auto_load_libs": False}, run_ccc=False
        )
        func = cfg.functions[0x1400036C0]
        assert func is not None
        dec = proj.analyses.Decompiler(
            func, cfg=cfg, options=set_decompiler_option(None, [("show_local_types", False)])
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        m = re.search(r"v\d+ \+ 12", t)
        if m is not None:
            t = dec.codegen.text.replace(m.group(0), "--REPLACED--")
        assert "12" not in t and "0xc" not in t

    def test_intra_block_conditional_jump_is_not_a_head_controlled_loop(self):
        # libVEX guards AArch64 ldar with an alignment-check exit (Ijk_SigBUS) that targets the instruction itself,
        # which becomes a mid-block conditional jump whose targets all lie inside the block. The rewriting engine
        # records no side-exit state for such jumps, so treating the block as a head-controlled loop crashed
        # ssailification with a KeyError when a stack phi was resolved through it.
        bin_path = os.path.join(test_location, "aarch64", "langdetect_go_go1.20.14")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path,
            0x29700,  # runtime.gcFlushBgCredit
            project_kwargs={"auto_load_libs": False},
            expand_call_tree=False,
            run_ccc=False,
        )
        func = cfg.functions[0x29700]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        # the load-acquire at 0x29738 reads a global; its alignment-check exit must leave no trace
        assert "g_18ca48" in t
        assert "LABEL_0x29738" not in t

    def test_repne_scasb_tail_exit_keeps_the_counter(self):
        # MSVC inlines strlen as "or ecx, -1; xor eax, eax; repne scasb; not ecx". libVEX lifts repne scasb into a
        # single self-looping block with an ecx==0 exit at its head and a ZF exit at its tail. The head-controlled-loop
        # handling in ssailification only knows the head exit, which left the back edge with a self-referencing phi:
        # the counter folded to its initial value, the guard became "if (0) break;" and strlen was lost.
        bin_path = os.path.join(
            test_location, "i386", "windows", "9f2ef84bde1e4ef445708cc5a605a09226363d502b1f5b5bf4a1cfc6dd5fc41e"
        )
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x401D60, expand_call_tree=False, run_ccc=False)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x401D60], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        assert "if (0)" not in t
        assert "~0xffffffff" not in t  # the counter was folded to its initial value
        # the loop counter survives into the strlen result: ~counter
        assert re.search(r"= ~v\d+;", t) is not None
        assert t.count("0xffffffff;") + t.count("-0x1;") == 3  # three inlined strlen sites keep their initializer
        # dephication copies the phi destination (vA = vB) because the pointer is read in the latch after its
        # increment; the copy-back for the exit phi (vB = vA) is a no-op and must not survive
        assert re.search(r"(v\d+) = (v\d+);\s*\2 = \1;", t) is None

    def test_side_exit_phi_takes_the_value_at_the_exit(self):
        # MIPS beql nullifies its delay slot when the branch is not taken, so libVEX lifts block 0x402480 of
        # print_unresolved as a side exit to 0x402494 followed by the delay-slot load into a3. The phi for a3 at
        # 0x402494 must take a3 as it was at that side exit, not the delay-slot value that only the taken branch sees.
        bin_path = os.path.join(test_location, "mips64", "ld.so.1")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x402468, project_kwargs={"auto_load_libs": False}, expand_call_tree=False, run_ccc=False
        )
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            cfg.functions[0x402468], cfg=cfg, clinic_end_stage=ClinicStage.SSA_LEVEL0_TRANSFORMATION
        )
        assert dec.clinic is not None and dec.clinic.graph is not None
        blocks = {(block.addr, block.idx): block for block in dec.clinic.graph}
        a3 = proj.arch.registers["a3"][0]

        def a3_defs(stmts):
            return [
                stmt.dst.varid
                for stmt in stmts
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.reg_offset == a3
            ]

        stmts = blocks[(0x402480, None)].statements
        jump_idx = next(i for i, stmt in enumerate(stmts) if isinstance(stmt, ConditionalJump))
        at_exit, delay_slot = a3_defs(stmts[:jump_idx]), a3_defs(stmts[jump_idx + 1 :])
        assert at_exit and delay_slot
        phi = next(
            stmt
            for stmt in blocks[(0x402494, None)].statements
            if isinstance(stmt, Assignment)
            and isinstance(stmt.src, Phi)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.reg_offset == a3
        )
        assert isinstance(phi.src, Phi)
        operand = dict(phi.src.src_and_vvars)[(0x402480, None)]
        assert operand is not None and operand.varid == at_exit[-1]

    def test_loop_head_ending_in_a_delay_slot(self):
        # The loop head at 0x417280 of _dl_check_caller ends in a MIPS beql, so its conditional jump is followed by the
        # delay-slot load and the block does not end in a jump. Phoenix's while-true rewrite asserted that it could take
        # a jump off the end of that block.
        bin_path = os.path.join(test_location, "mips64", "ld.so.1")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x4171E0, project_kwargs={"auto_load_libs": False}, expand_call_tree=False, run_ccc=False
        )
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x4171E0], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

    def test_is_head_controlled_loop_block_requires_an_out_of_block_target(self):
        def c(v):
            return Const(0, v, 64)

        def block(true_target, false_target):
            return Block(
                0x1000,
                12,
                statements=[
                    Assignment(0, Register(1, 0, 64), c(1)),
                    ConditionalJump(2, c(1), true_target, false_target, ins_addr=0x1004),
                    Assignment(3, Register(4, 8, 64), c(2)),
                    Return(5, []),
                ],
            )

        # both targets inside the block (an alignment-check exit): not a head-controlled loop
        assert not is_head_controlled_loop_block(block(c(0x1004), None))
        assert not is_head_controlled_loop_block(block(c(0x1004), c(0x1008)))
        # a target that leaves the block (rep stosX): a head-controlled loop
        assert is_head_controlled_loop_block(block(c(0x100C), c(0x1000)))
        assert is_head_controlled_loop_block(block(c(0x1004), c(0x2000)))


if __name__ == "__main__":
    unittest.main()
