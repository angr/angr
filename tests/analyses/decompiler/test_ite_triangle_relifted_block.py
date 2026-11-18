#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.ailment import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Assignment, Jump, Return, Store
from angr.analyses.decompiler.clinic import Clinic
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _jump(target, ins_addr=0x400100):
    return Jump(0, Const(1, target, 32), ins_addr=ins_addr)


class TestITETriangleRelistedBlock(unittest.TestCase):
    """
    _create_triangle_for_ite_expression truncates the head block at the ITE statement and leaves the end
    block to carry whatever the original block ended with. An end block with no statements cannot carry
    it, so the rewrite has to be declined rather than performed.
    """

    def test_a_statementless_end_block_refuses_the_rewrite(self):
        # graph recovery emits a zero-size block for a fall-through that no instruction backs
        patched = Block(0x400100, 4, statements=[_jump(0x400200)])
        relifted = Block(0x400104, 0, statements=[])

        assert Clinic._remove_redundant_jump_blocks_repatch_relifted_block(patched, relifted) is False

    def test_a_relifted_block_that_carries_the_jump_is_repatched(self):
        patched = Block(0x400100, 4, statements=[_jump(0x400200)])
        relifted = Block(0x400100, 4, statements=[_jump(0x400104)])

        assert Clinic._remove_redundant_jump_blocks_repatch_relifted_block(patched, relifted) is True
        assert relifted.statements[-1].likes(_jump(0x400200))

    def test_a_head_that_does_not_end_in_a_jump_is_accepted_unchanged(self):
        patched = Block(0x400100, 4, statements=[Assignment(0, Register(1, 8, 32), Const(2, 1, 32), ins_addr=0x400100)])
        relifted = Block(0x400100, 4, statements=[_jump(0x400104)])

        assert Clinic._remove_redundant_jump_blocks_repatch_relifted_block(patched, relifted) is True
        assert relifted.statements[-1].likes(_jump(0x400104))


class TestPcodeITEIsNotSplit(unittest.TestCase):
    """
    A p-code ITE stands for ops that a relative branch skips. Splitting its instruction into a diamond whose arms are
    relifts of the whole instruction would run those ops again in each arm.
    """

    @staticmethod
    def _graph(func_addr):
        proj = angr.Project(
            os.path.join(test_location, "hppa", "test-instr_hppa"),
            auto_load_libs=False,
            main_opts={"backend": "elf", "arch": archinfo.ArchPcode("pa-risc:BE:32:default")},
        )
        cfg = proj.analyses.CFGFast(
            normalize=True, function_starts=[func_addr], start_at_entry=False, force_complete_scan=False
        )
        graph = proj.analyses.Clinic(cfg.functions[func_addr], cfg=cfg.model).graph
        assert graph is not None
        return graph

    def test_an_instruction_that_returns_is_not_split(self):
        # In raise, the load at 0x1657c sits in the delay slot of the return, so its p-code ends in that return, and a
        # branch inside the instruction chooses between two register writes.
        graph = self._graph(0x16508)

        returning = [block for block in graph if any(isinstance(stmt, Return) for stmt in block.statements)]
        assert returning
        for block in returning:
            assert graph.out_degree(block) == 0, f"block {block.addr:#x} returns but has successors"

    def test_a_predicated_store_is_made_once(self):
        # `CMPICLR,= 0x0,r8,r0` nullifies the next instruction when r8 is 0, so `STW r22,0x0(r8)` at 0x177c0 stores
        # only when r8 is not 0.
        graph = self._graph(0x177BC)

        stores = [
            stmt
            for block in graph
            for stmt in block.statements
            if isinstance(stmt, Store) and stmt.tags.get("ins_addr") == 0x177C0
        ]
        assert len(stores) == 1


if __name__ == "__main__":
    unittest.main()
