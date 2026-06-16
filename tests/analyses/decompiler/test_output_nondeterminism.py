#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import difflib
import os
import unittest

import angr
from tests.common import bin_location


class TestVariableNondeterminism(unittest.TestCase):
    def test_deterministic_decompilation_output_upon_multiple_attempts(self):
        """Regression test for https://github.com/angr/angr/issues/6440."""

        binary_path = os.path.join(bin_location, "tests", "x86_64", "fauxware")
        project = angr.Project(binary_path)
        project.analyses.CFGFast(normalize=True)
        project.analyses.CompleteCallingConventions(analyze_callsites=False)
        output = []
        for i in range(20):
            dec = project.analyses.Decompiler("main", options=[("constrain_callee_prototypes", False)])
            assert dec.codegen is not None and dec.codegen.text is not None
            output.append(dec.codegen.text)

            if i > 0 and output[0] != output[i]:
                diff = difflib.unified_diff(
                    output[0].splitlines(keepends=True),
                    output[i].splitlines(keepends=True),
                    fromfile="output[0]",
                    tofile=f"output[{i}]",
                )
                print("Diff:")
                print("".join(diff))
                print("=======")
                print("Output[0]:")
                print(output[0])
                print("-------")
                print(f"Output[{i}]:")
                print(output[i])
                print("=======")
                assert False, f"Output differs at iteration {i}"


if __name__ == "__main__":
    unittest.main()
