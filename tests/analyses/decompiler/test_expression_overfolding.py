#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import re
import unittest

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from angr.analyses.decompiler.region_simplifiers.region_simplifier import RegionSimplifier
from angr.analyses.decompiler.structurer_nodes import LoopNode, SequenceNode
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.getLogger(__name__)


class TestExpressionOverfolding(unittest.TestCase):
    def test_loop_body_assignment_used_by_loop_header_is_not_folded(self):
        for header_kind in ("condition", "iterator"):
            with self.subTest(header_kind=header_kind):
                manager = Manager()
                carrier = VirtualVariable(manager.next_atom(), 81, 32, VirtualVariableCategory.REGISTER, oident=20)
                header_var = VirtualVariable(manager.next_atom(), 19, 32, VirtualVariableCategory.REGISTER, oident=20)
                header_use_result = VirtualVariable(
                    manager.next_atom(), 68, 32, VirtualVariableCategory.REGISTER, oident=20
                )
                temporary = VirtualVariable(manager.next_atom(), 20, 32, VirtualVariableCategory.REGISTER, oident=20)
                temporary_result = VirtualVariable(
                    manager.next_atom(), 69, 32, VirtualVariableCategory.REGISTER, oident=20
                )
                body = Block(
                    0x80001CF,
                    8,
                    statements=[
                        Assignment(manager.next_atom(), header_var, carrier),
                        Assignment(manager.next_atom(), header_use_result, header_var),
                        Assignment(manager.next_atom(), temporary, carrier),
                        Assignment(manager.next_atom(), temporary_result, temporary),
                    ],
                )
                if header_kind == "condition":
                    condition = BinaryOp(
                        manager.next_atom(), "CmpNE", [header_var, Const(manager.next_atom(), 1, 32)], False
                    )
                    iterator = None
                else:
                    condition = None
                    iterator_var = VirtualVariable(
                        manager.next_atom(), 21, 32, VirtualVariableCategory.REGISTER, oident=20
                    )
                    iterator = Assignment(
                        manager.next_atom(),
                        iterator_var,
                        header_var,
                    )
                loop = LoopNode(
                    "do-while" if condition is not None else "for",
                    condition,
                    SequenceNode(0x80001CF, nodes=[body]),
                    addr=0x80001CF,
                    iterator=iterator,
                )
                region = SequenceNode(0x80001CF, nodes=[loop])
                simplifier = object.__new__(RegionSimplifier)
                simplifier.arg_vvars = set()
                simplifier.ail_manager = manager

                simplifier._fold_oneuse_expressions(region)  # pylint:disable=protected-access

                self.assertTrue(
                    any(
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and stmt.dst.varid == header_var.varid
                        for stmt in body.statements
                    )
                )
                self.assertFalse(
                    any(
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and stmt.dst.varid == temporary.varid
                        for stmt in body.statements
                    )
                )

    def test_arm_countdown_loop_condition_variable_is_defined(self):
        bin_path = os.path.join(test_location, "armel", "decompiler", "blink_main_countdown.elf")
        function_starts = [0x80001AD, 0x80001E1, 0x80001F5, 0x8000225, 0x8000229, 0x800022D]
        option = get_structurer_option()

        for structurer in ("Phoenix", "SAILR"):
            with self.subTest(structurer=structurer):
                proj = angr.Project(bin_path, auto_load_libs=False, load_debug_info=False)
                cfg = proj.analyses.CFGFast(normalize=True, fail_fast=True, function_starts=function_starts)
                dec = proj.analyses.Decompiler(
                    cfg.kb.functions[0x80001AD],
                    cfg=cfg.model,
                    preset="full",
                    options=[(option, structurer)],
                    fail_fast=True,  # pyright: ignore[reportCallIssue]
                    use_cache=False,
                    update_cache=False,
                )
                codegen = dec.codegen
                assert codegen is not None and codegen.text is not None
                code = codegen.text
                condition = re.search(r"while \(([A-Za-z_]\w*) != 1\);", code)
                assert condition is not None
                condition_variable = condition.group(1)
                self.assertRegex(code[: condition.start()], rf"\b{re.escape(condition_variable)}\s*=")

    def test_expression_overfolding_56f41bc3(self):
        bin_path = os.path.join(
            test_location, "i386", "windows", "56f41bc38419e26de02bfb9438d7ddefd8561c668018fd29dc56521c060ab3e3"
        )
        proj = angr.Project(bin_path)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            force_smart_scan=False,
            force_complete_scan=True,
            start_at_entry=False,
            function_starts=[0x401AEC],
            regions=[(0x401000, 0x40D8A4)],
            # this function is decoded out of data and runs through hundreds of zero bytes, which CFGFast refuses to
            # decode by default (see issue #6968). keep decoding them: the point here is the decompiler, not the CFG
            repeating_byte_run_threshold=0,
        )
        # note that 0x401aec is not a valid function, so when force_smart_scan is True, we will not find it
        func = cfg.functions[0x401AEC]
        assert func is not None
        assert func.block_addrs_set == {
            0x401AEC,
            0x401AF9,
            0x401B6A,
            0x401AFB,
            0x401B6E,
            0x401AFD,
            0x401B72,
            0x401AFF,
            0x401B76,
            0x401B01,
            0x401B7A,
            0x401B03,
            0x401B7E,
            0x401B05,
            0x401B82,
            0x401B86,
            0x401C30,
            0x401C34,
            0x401C38,
            0x401C3C,
            0x401C40,
            0x401C44,
            0x401C48,
            0x401C4C,
            0x401D0B,
            0x401D0F,
            0x401D13,
            0x401D17,
            0x401D1B,
            0x401D1F,
            0x401D23,
            0x401D27,
            0x401DD1,
            0x401DD5,
            0x401DD9,
            0x401DDD,
            0x401DE1,
            0x401DE5,
            0x401DE9,
            0x401DED,
            0x401E9C,
            0x401EA8,
            0x401EAC,
            0x401EB0,
            0x401EB4,
            0x401EB8,
            0x401EBC,
            0x401EC0,
            0x401F74,
            0x401F78,
            0x401F7C,
            0x401F80,
            0x401F84,
            0x401F88,
            0x401F8C,
            0x401F90,
        }
        # decompilation will time out if expression folding is not limited by expression depth
        dec = proj.analyses.Decompiler(func, show_progressbar=not WORKER, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        lines = t.split("\n")
        for line in lines:
            assert len(line.strip(" ")) < 200, f"Line is too long: {line}"


if __name__ == "__main__":
    unittest.main()
