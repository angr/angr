#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses import Decompiler
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPartialStackWrites(unittest.TestCase):
    """
    Ssailification records every definition under each byte it covers, so looking a stack slot up by its offset can
    return a definition that merely overlaps it. The phi back-patch in RewritingAnalysis._post_analysis therefore
    drops a phi whose sources do not denote exactly the destination's storage; a stack slot written at one width in
    one predecessor and at another width in another predecessor is not one variable, and wiring the narrower
    definition in produces a phi whose sources disagree in width with its destination.
    """

    def test_stack_phi_sources_match_destination(self):
        bin_path = os.path.join(test_location, "x86_64", "test_arrays")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = cfg.functions[0x40059D]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert dec.clinic is not None and dec.clinic.graph is not None
        print_decompilation_result(dec)

        stack_phis = 0
        for block in dec.clinic.graph:
            for stmt in block.statements:
                if not (
                    isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi)
                ):
                    continue
                if stmt.dst.was_stack:
                    stack_phis += 1
                for _, src in stmt.src.src_and_vvars:
                    assert src is None or src.bits == stmt.dst.bits, (
                        f"phi for vvar {stmt.dst.varid} ({stmt.dst.bits} bits) has a {src.bits}-bit source"
                    )

        # the function must still produce stack phis, or the assertion above proves nothing
        assert stack_phis > 0


if __name__ == "__main__":
    unittest.main()
