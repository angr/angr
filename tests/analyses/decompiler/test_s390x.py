#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""s390x decompilation regression tests."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.calling_conventions import SimCCS390X
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


if __name__ == "__main__":
    unittest.main()
