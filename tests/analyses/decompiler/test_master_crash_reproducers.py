#!/usr/bin/env python3
from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

from angr.analyses.decompiler.decompiler import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg

# Each function below crashed the decompiler (fail_fast) on the shape named in the test, and was found by sweeping
# the test binaries for functions that take the guarded path.
LIBLZMA = os.path.join(bin_location, "tests", "x86_64", "liblzma.so.5.6.1")
MORTON = os.path.join(bin_location, "tests", "x86_64", "decompiler", "morton")
FAUXWARE_WIDE = os.path.join(bin_location, "tests", "x86_64", "windows", "fauxware-wide.exe")


def _decompile(bin_path: str, addr: int) -> str:
    proj, cfg = load_project_with_scoped_cfg(bin_path, addr)
    func = cfg.functions[addr]
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


class TestMasterCrashReproducers(TestCase):
    def test_a_vector_operation_the_light_engine_has_no_handler_for(self):
        # sub_4068c0 uses PermOrZeroV (pshufb); the AIL light engine raised KeyError on it
        _decompile(LIBLZMA, 0x4068C0)

    def test_a_goto_inside_a_switch_case_becomes_a_break(self):
        # formatted_print_percent: the break replacing the goto was inserted without the case's label
        _decompile(MORTON, 0x4055A5)


if __name__ == "__main__":
    unittest.main()
