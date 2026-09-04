#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses import CFGFast, CompleteCallingConventionsAnalysis, Decompiler
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestSwitchGotoInNestedLoop(unittest.TestCase):
    def test_goto_leaving_a_switch_from_inside_a_loop_stays_a_goto(self):
        # sub_41264c holds a switch whose case arm is a loop, and that loop jumps to the end of the switch at
        # 0x412704. Rewriting the jump into a break would leave the loop only, so the assignments that follow
        # the loop inside the arm would run and overwrite the values the jump carries out of the switch.
        bin_path = os.path.join(test_location, "armel", "ld-linux.so.3")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        proj.analyses[CompleteCallingConventionsAnalysis].prep()(
            cfg=cfg.model, recover_variables=True, analyze_callsites=True
        )

        f = cfg.functions[0x41264C]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(f, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        code = dec.codegen.text
        assert code.count("goto LABEL_412704;") == 1
        assert code.count("LABEL_412704:") == 1


if __name__ == "__main__":
    unittest.main()
