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
                cfg=cfg,
                analyze_callsites=True,
                input_args=ffc.input_args,
                retval_size=fauxware.arch.bytes,
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


if __name__ == "__main__":
    unittest.main()
