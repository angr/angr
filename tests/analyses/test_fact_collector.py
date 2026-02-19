#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.calling_conventions import (
    SimCCCdecl,
    SimCCSystemVAMD64,
)

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestFactCollector(unittest.TestCase):
    def _run_fauxware(self, arch, function_and_cc_list):
        binary_path = os.path.join(test_location, arch, "fauxware")
        fauxware = angr.Project(binary_path, auto_load_libs=False)

        cfg = fauxware.analyses.CFG()

        for func_name, expected_cc in function_and_cc_list:
            authenticate = cfg.functions[func_name]
            ffc = fauxware.analyses.FunctionFactCollector(authenticate)

            cc_analysis = fauxware.analyses.CallingConvention(
                authenticate,
                cfg=cfg.model,
                analyze_callsites=True,
                input_args=ffc.input_args,
                retval_size=ffc.retval_size,
            )
            cc = cc_analysis.cc
            assert cc == expected_cc

    def test_fauxware_i386(self):
        self._run_fauxware("i386", [("authenticate", SimCCCdecl(archinfo.arch_from_id("i386")))])

    def test_fauxware_x86_64(self):
        amd64 = archinfo.arch_from_id("amd64")
        self._run_fauxware(
            "x86_64",
            [
                (
                    "authenticate",
                    SimCCSystemVAMD64(
                        amd64,
                    ),
                ),
            ],
        )


    def _check_caller_saved_excluded(self, arch_dir):
        """Helper: no caller-saved register offset may appear in callee_restored_regs."""
        from angr.calling_conventions import default_cc  # pylint:disable=import-outside-toplevel

        binary_path = os.path.join(test_location, arch_dir, "fauxware")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG()

        cc_cls = default_cc(proj.arch.name, platform=proj.simos.name if proj.simos is not None else None)
        assert cc_cls is not None
        cc = cc_cls(proj.arch)

        caller_saved_offsets = set()
        for reg_name in cc.CALLER_SAVED_REGS:
            if reg_name in proj.arch.registers:
                caller_saved_offsets.add(proj.arch.registers[reg_name][0])
        assert caller_saved_offsets, "expected at least one caller-saved register"

        for func in cfg.functions.values():
            ffc = proj.analyses.FunctionFactCollector(func)
            callee_restored = ffc._analyze_endpoints_for_restored_regs()
            overlap = callee_restored & caller_saved_offsets
            assert not overlap, (
                f"{func.name} @ {hex(func.addr)}: caller-saved offsets {overlap} "
                f"leaked into callee_restored_regs"
            )

    def test_caller_saved_regs_excluded_from_callee_restored_armel(self):
        """ARM: caller-saved regs (r0-r3, r12) must not appear in callee_restored_regs."""
        self._check_caller_saved_excluded("armel")


if __name__ == "__main__":
    unittest.main()
