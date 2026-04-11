#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestExpressionOverfolding(unittest.TestCase):
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
            0x401B07,
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
