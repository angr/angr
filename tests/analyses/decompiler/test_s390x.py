#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""s390x decompilation regression tests."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.calling_conventions import SimCCS390X, SimReferenceArgument, SimRegArg, SimStackArg
from angr.sim_type import parse_signature
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestS390XDecompilation(unittest.TestCase):
    def test_decompile_fauxware_authenticate(self):
        # SimCC._guess_arg_count used to instantiate cls.ARCH with Endness.LE, which ArchS390X rejects
        # ("Arch s390x must be big endian"), so no s390x function could get a calling convention.
        bin_path = os.path.join(test_location, "s390x", "fauxware")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x400A00, include_plt=True)

        func = cfg.functions["authenticate"]
        assert isinstance(func.calling_convention, SimCCS390X)

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        assert "authenticate(" in text
        assert "read(" in text

    def test_large_by_value_args_passed_by_reference(self):
        # long double, __int128-sized values and aggregates not sized 1/2/4/8 go by reference in a GPR
        proj_arch = SimCCS390X.ARCH()
        cc = SimCCS390X(proj_arch)
        proto = parse_signature(
            "int f(long double a, struct s3 { char c[3]; } b, struct s8 { int x; int y; } c, double d, "
            "struct s16 { long p; long q; } e, long g, long h);"
        ).with_arch(proj_arch)
        locs = cc.arg_locs(proto)
        assert isinstance(locs[0], SimReferenceArgument) and locs[0].ptr_loc == SimRegArg("r2", 8)
        assert isinstance(locs[1], SimReferenceArgument) and locs[1].ptr_loc == SimRegArg("r3", 8)
        assert locs[2] == SimRegArg("r4", 8)
        assert isinstance(locs[3], SimRegArg) and locs[3].reg_name == "f0"
        assert isinstance(locs[4], SimReferenceArgument) and locs[4].ptr_loc == SimRegArg("r5", 8)
        assert locs[5] == SimRegArg("r6", 8)
        # registers exhausted: the next argument (or reference pointer) takes a stack slot
        assert isinstance(locs[6], SimStackArg)
        # only the pointer occupies an argument location
        assert set(locs[0].get_footprint()) == {SimRegArg("r2", 8)}


if __name__ == "__main__":
    unittest.main()
