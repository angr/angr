#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest
from unittest import mock

import angr
from angr.analyses.decompiler.clinic import Clinic
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.getLogger(__name__)


class TestUnifyLocalVariables(unittest.TestCase):
    def test_unify_local_variables_skip_outdated_eqs(self):
        bin_path = os.path.join(test_location, "x86_64", "split-rust")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER, fail_fast=True, normalize=True, regions=[(0x503FC0, 0x504200)]
        )
        proj.analyses.CompleteCallingConventions()
        func = cfg.functions[0x503FC0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg, options=[("semvar_naming", False)])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "a0[1]" in dec.codegen.text
        assert "a0[2]" in dec.codegen.text
        assert "a0[0]" in dec.codegen.text or "*a0" in dec.codegen.text


    def test_unification_and_folding_reach_a_fixpoint(self):
        # unification moved a register's use onto a stack copy (an outgoing argument slot) that expression folding
        # propagated back, every round, until _simplify_function gave up after max_iterations
        proj = angr.Project(os.path.join(test_location, "i386", "windows", "2.exe"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER, fail_fast=True, normalize=True, function_starts=[0x40A2A8]
        )
        rounds: list[list[bool]] = []
        simplify_function, simplify_once = Clinic._simplify_function, Clinic._simplify_function_once

        def counted_function(self, *args, **kwargs):
            rounds.append([])
            return simplify_function(self, *args, **kwargs)

        def counted_once(self, *args, **kwargs):
            r = simplify_once(self, *args, **kwargs)
            if rounds:
                rounds[-1].append(bool(r))
            return r

        with (
            mock.patch.object(Clinic, "_simplify_function", counted_function),
            mock.patch.object(Clinic, "_simplify_function_once", counted_once),
        ):
            dec = proj.analyses.Decompiler(cfg.functions[0x40A2A8], cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        # every multi-round simplification ends with a round that changes nothing
        unconverged = [r for r in rounds if len(r) > 1 and all(r)]
        assert not unconverged, rounds


if __name__ == "__main__":
    unittest.main()
