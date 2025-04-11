#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long,no-member
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import io
import os
import re
import sys
import unittest
from unittest import mock

import angr
from angr.__main__ import main
from angr.analyses.decompiler.utils import decompile_functions

from .common import bin_location


test_location = os.path.join(bin_location, "tests")


def run_cli(*args):
    with mock.patch("sys.argv", [sys.executable, *args]), mock.patch("sys.stdout", new=io.StringIO()) as fake_out:
        main()
        return fake_out.getvalue()


class TestCommandLineInterface(unittest.TestCase):
    def test_decompiling(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"
        f2 = "main"

        # test a single function
        assert run_cli(bin_path, "decompile", "--functions", f1) == decompile_functions(bin_path, [f1]) + "\n"

        # test multiple functions
        assert run_cli(bin_path, "decompile", "--functions", f1, f2) == decompile_functions(bin_path, [f1, f2]) + "\n"

    def test_structuring(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"

        dream_cli = run_cli(bin_path, "decompile", "--no-casts", "--functions", f1, "--structurer", "dream")
        sailr_cli = run_cli(bin_path, "decompile", "--functions", f1, "--structurer", "sailr")
        assert dream_cli.count("goto") == 0
        assert dream_cli != sailr_cli

    def test_base_addr_dec(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"
        proj = angr.Project(bin_path, auto_load_libs=False)
        default_base_addr = proj.loader.main_object.min_addr
        f1_default_addr = proj.loader.find_symbol(f1).rebased_addr
        f1_offset = f1_default_addr - default_base_addr

        # function resolving is based on symbol
        sym_based_dec = run_cli(bin_path, "decompile", "--functions", f1, "--preset", "full")
        # function resolving is based on the address (with default angr loading)
        base_addr_dec = run_cli(bin_path, "decompile", "--functions", hex(f1_default_addr), "--preset", "full")
        # function resolving is based on the address (with base address specified)
        offset_dec = run_cli(
            bin_path, "--base-addr", "0x0", "decompile", "--functions", hex(f1_offset), "--preset", "full"
        )

        # since the externs can be unpredictable, we only check the function name down
        sym_based_dec = re.sub(r"extern .*;", "", sym_based_dec).lstrip("\n")
        base_addr_dec = re.sub(r"extern .*;", "", base_addr_dec).lstrip("\n")
        offset_dec = re.sub(r"extern .*;", "", offset_dec).lstrip("\n")

        # we must also normalize label names (since they are based on the address)
        sym_based_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", sym_based_dec)
        base_addr_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", base_addr_dec)
        offset_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", offset_dec)

        assert sym_based_dec == base_addr_dec == offset_dec

    def test_disassembly(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        disasm = run_cli(bin_path, "disassemble")
        funcs = {
            "_init",
            "_start",
            "call_gmon_start",
            "__do_global_dtors_aux",
            "frame_dummy",
            "authenticate",
            "accepted",
            "rejected",
            "main",
            "__libc_csu_init",
            "__libc_csu_fini",
            "__do_global_ctors_aux",
            "_fini",
        }
        substrs = [f"{f}:" for f in funcs]
        substrs += "40071d  55              push    rbp"

        for s in substrs:
            assert s in disasm


if __name__ == "__main__":
    unittest.main()
