#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long,no-member
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
import subprocess
import re
import unittest

import angr
from angr.analyses.decompiler.utils import decompile_functions
from angr.misc.testing import is_testing

from .common import bin_location


test_location = os.path.join(bin_location, "tests")
WORKER = is_testing or bool(
    os.environ.get("WORKER", False)
)  # this variable controls whether we print the decompilation code or not


def run_cli(*args):
    proc = subprocess.run(["python3", "-m", "angr", *args], text=True, check=True, capture_output=True)
    return proc.stdout


class TestCommandLineInterface(unittest.TestCase):
    def test_decompiling(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"
        f2 = "main"

        # test a single function
        assert run_cli("decompile", bin_path, "--functions", f1) == decompile_functions(bin_path, [f1]) + "\n"

        # test multiple functions
        assert run_cli("decompile", bin_path, "--functions", f1, f2) == decompile_functions(bin_path, [f1, f2]) + "\n"

    def test_structuring(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"

        dream_cli = run_cli("decompile", bin_path, "--no-casts", "--functions", f1, "--structurer", "dream")
        sailr_cli = run_cli("decompile", bin_path, "--functions", f1, "--structurer", "sailr")
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
        sym_based_dec = run_cli("decompile", bin_path, "--functions", f1)
        # function resolving is based on the address (with default angr loading)
        base_addr_dec = run_cli("decompile", bin_path, "--functions", hex(f1_default_addr))
        # function resolving is based on the address (with base address specified)
        offset_dec = run_cli("decompile", bin_path, "--functions", hex(f1_offset), "--base-addr", hex(0))

        # since the externs can be unpredictable, we only check the function name down
        sym_based_dec = re.sub(r"extern .*;", "", sym_based_dec).lstrip("\n")
        base_addr_dec = re.sub(r"extern .*;", "", base_addr_dec).lstrip("\n")
        offset_dec = re.sub(r"extern .*;", "", offset_dec).lstrip("\n")

        # we must also normalize label names (since they are based on the address)
        sym_based_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", sym_based_dec)
        base_addr_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", base_addr_dec)
        offset_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", offset_dec)

        assert sym_based_dec == base_addr_dec == offset_dec


if __name__ == "__main__":
    unittest.main()
