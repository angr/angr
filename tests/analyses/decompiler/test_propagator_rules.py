#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import ailment
from angr.knowledge_plugins.key_definitions import atoms
from angr.utils.ssa import get_tmp_deflocs
from tests.common import WORKER, bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


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

    def test_spropagator_tmp_definition_from_ldrex(self):
        # Thumb-2 `ldrex r1, [r3]`: VEX models the load and its result as LLSC.
        project = angr.load_shellcode(b"\x53\xe8\x00\x1f", "ARMCortexM", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        ail_block = ailment.IRSBConverter.convert(project.factory.block(0x1001, size=4).vex, manager)

        tmp_def_stmt_idx, tmp_def_stmt = next(
            (stmt_idx, stmt)
            for stmt_idx, stmt in enumerate(ail_block.statements)
            if isinstance(stmt, ailment.Stmt.Assignment)
            and isinstance(stmt.dst, ailment.Expr.Tmp)
            and isinstance(stmt.src, ailment.Expr.DirtyExpression)
            and stmt.src.callee == "load_linked_le"
        )
        tmp_use_stmt = next(
            stmt
            for stmt in ail_block.statements[tmp_def_stmt_idx + 1 :]
            if isinstance(stmt, ailment.Stmt.Assignment)
            and isinstance(stmt.src, ailment.Expr.Tmp)
            and stmt.src.tmp_idx == tmp_def_stmt.dst.tmp_idx
        )

        tmp_deflocs = get_tmp_deflocs([ail_block])
        tmp_atom = atoms.Tmp(tmp_def_stmt.dst.tmp_idx, tmp_def_stmt.dst.bits)
        assert tmp_deflocs[(ail_block.addr, ail_block.idx)][tmp_atom] == tmp_def_stmt_idx

        propagator = project.analyses.SPropagator(ail_block, ail_manager=manager)

        assert not any(tmp_use_stmt.src in replacements for replacements in propagator.replacements.values())


if __name__ == "__main__":
    unittest.main()
