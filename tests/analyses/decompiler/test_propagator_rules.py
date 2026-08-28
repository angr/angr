#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import ailment
from angr.analyses.s_propagator import SPropagator
from tests.common import WORKER, bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPropagatorRules(unittest.TestCase):
    def test_spropagator_treats_store_conditional_as_memory_write(self):
        binary = os.path.join(test_location, "armel", "decompiler", "nuttx_O2_noinline")
        project = angr.Project(binary, auto_load_libs=False)
        manager = ailment.Manager(arch=project.arch)
        address = ailment.Expr.Const(0, 0x2000, project.arch.bits)
        load_tmp = ailment.Expr.Tmp(1, 0, 32)
        load_use = ailment.Expr.Tmp(2, 0, 32)
        dirty = ailment.Expr.DirtyExpression(
            3,
            "store_conditional_le",
            [address, ailment.Expr.Const(4, 1, 32)],
            mfx="Ifx_Write",
            maddr=address,
            msize=4,
            bits=1,
        )
        block = ailment.Block(
            0x1000,
            1,
            statements=[
                ailment.Stmt.Assignment(5, load_tmp, ailment.Expr.Load(6, address, 4, "Iend_LE"), ins_addr=0x1000),
                ailment.Stmt.Assignment(7, ailment.Expr.Tmp(8, 1, 1), dirty, ins_addr=0x1001),
                ailment.Stmt.Assignment(9, ailment.Expr.Register(10, 16, 32), load_use, ins_addr=0x1002),
            ],
        )

        propagator = SPropagator(project, block, ail_manager=manager)
        assert not any(load_use in replacements for replacements in propagator.replacements.values())

    def test_spropagator_preserves_nuttx_llsc_results(self):
        bin_path = os.path.join(test_location, "armel", "decompiler", "nuttx_O2_noinline")
        func_addr = 0x800D725
        proj, cfg = load_project_with_scoped_cfg(
            bin_path,
            func_addr,
            expand_call_tree=False,
            run_ccc=False,
        )

        dec = proj.analyses.Decompiler(cfg.functions[func_addr], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        code = dec.codegen.text
        assert code.count("load_linked_le(") == 1
        assert code.count("store_conditional_le(") == 1
        assert code.index("load_linked_le(") < code.index("store_conditional_le(")

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


if __name__ == "__main__":
    unittest.main()
