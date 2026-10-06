#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Load, Tmp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Jump, Return
from angr.analyses.s_propagator import SPropagator
from angr.knowledge_plugins.functions import Function
from tests.common import WORKER, bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

# the two blocks of the hand-built graph in the tmp-propagation tests below
BLOCK_A = 0x401000
BLOCK_B = 0x401010


class TestPropagatorRules(unittest.TestCase):
    def test_propagator_do_not_propagate_constants_through_unsafe_stack_variables(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        func = cfg.functions[0x13640]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # incorrect propagation of stack variable at bp-0x10 will result in missing code blocks and function calls
        assert dec.codegen.text.count("ObfDereferenceObject(") == 1
        assert dec.codegen.text.count("ObReferenceObjectByPointer(") == 1
        assert dec.codegen.text.count("ExFreePoolWithTag") == 1

    def test_propagator_do_not_create_overly_deep_expressions(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "94def0c6290dbc32ebb9a6e72d2f76d0ffe66365606efeef952834768e47f1d8"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        func = cfg.functions[0x14000F190]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # ensure that each line contains at most five operators
        for line in dec.codegen.text.splitlines():
            if line.strip() == "":
                continue
            op_count = line.count("+") + line.count("-") + line.count("^") + line.count("ROL") + line.count("ROR")
            if "return" in line:
                assert op_count <= 12
            else:
                assert op_count <= 7

    def test_spropagator_do_not_propagate_vvars_defined_in_assignment_src(self):
        bin_path = os.path.join(
            test_location, "i386", "windows", "0c694dfa7ad465bded90c4faf63100c7008b5efc4bc49b38644a9770b42669b0"
        )
        proj, _ = load_project_with_scoped_cfg(bin_path, 0x4847D4, expand_call_tree=False, run_ccc=False)
        dec = proj.analyses.Decompiler(0x4847D4, fail_fast=True)
        # it should not raise any exceptions; it was triggering an assertion error before this fix at
        # ailment/expression.py:
        #
        # assert not isinstance(offset, Const) or offset.value * 8 + value.bits <= base.bits
        #
        # this is because we were trying to propagate Reference(vvar_780) to vvar_780 (16-byte) in a statement of
        # `vvar_781 = Reference(vvar_780)`, where both vvar_780 and vvar_781 are defined at the same statement.
        assert dec.codegen is not None and dec.codegen.text is not None

    @staticmethod
    def _load_propagated_across_two_blocks(tmp_address: bool) -> SPropagator:
        """
        Run SPropagator over two blocks where a register is defined by a Load in the first one and
        used once in the second one. With ``tmp_address`` the Load reads through a tmp computed in
        the first block, which is what a p-code effective-address calculation looks like.
        """
        proj = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        bits = proj.arch.bits

        def vvar(varid: int, vvar_bits: int = 32) -> VirtualVariable:
            return VirtualVariable(varid, varid, vvar_bits, VirtualVariableCategory.REGISTER, oident=16)

        addr = Tmp(90, 0, bits) if tmp_address else Const(90, 0x500000, bits)
        block_a = Block(
            BLOCK_A,
            8,
            statements=[
                # tmp 0 holds the address, and is defined in this block only
                Assignment(
                    0, Tmp(91, 0, bits), BinaryOp(92, "Add", [vvar(10, bits), vvar(11, bits)]), ins_addr=BLOCK_A
                ),
                Assignment(
                    1,
                    vvar(1),
                    Load(93, addr, 4, proj.arch.memory_endness, ins_addr=BLOCK_A + 4),
                    ins_addr=BLOCK_A + 4,
                ),
                Jump(2, Const(94, BLOCK_B, bits), ins_addr=BLOCK_A + 8),
            ],
            idx=None,
        )
        block_b = Block(
            BLOCK_B,
            8,
            statements=[
                Assignment(0, vvar(2), BinaryOp(95, "Add", [vvar(1), Const(96, 1, 32)]), ins_addr=BLOCK_B),
                Return(1, [vvar(2)], ins_addr=BLOCK_B + 4),
            ],
            idx=None,
        )
        graph = networkx.DiGraph()
        graph.add_edge(block_a, block_b)
        return SPropagator(
            proj,
            Function(proj.kb.functions, BLOCK_A),
            ail_manager=ailment.Manager(),
            func_graph=graph,
            only_consts=False,
        )

    @staticmethod
    def _replacements_in(prop: SPropagator, block_addr: int) -> dict:
        return {
            (loc, expr): value
            for loc, reps in prop.replacements.items()
            if loc.block_addr == block_addr
            for expr, value in reps.items()
        }

    def test_spropagator_do_not_propagate_loads_with_tmps_to_other_blocks(self):
        prop = self._load_propagated_across_two_blocks(tmp_address=True)
        landed = self._replacements_in(prop, BLOCK_B)
        assert all(not isinstance(getattr(value, "addr", None), Tmp) for value in landed.values()), (
            f"a Load with tmps inside is propagated to another block: {landed}"
        )


if __name__ == "__main__":
    unittest.main()
