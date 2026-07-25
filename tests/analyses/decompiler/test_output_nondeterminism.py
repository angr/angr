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

    def test_redecompilation_is_idempotent_for_referenced_stack_arrays(self):
        """Regression: Re-decompiling a function must not rename its stack arrays.

        ``convert()`` in 1after909 has three ``char[2048]`` stack buffers that are passed by reference. The
        ``Reference(vvar)`` handler in variable recovery used to create a brand-new ``SimStackVariable`` for each of
        them on every run.
        """

        binary_path = os.path.join(bin_location, "tests", "x86_64", "1after909")
        project = angr.Project(binary_path)
        project.analyses.CFGFast(normalize=True)

        output = []
        for i in range(4):
            # drop the decompilation cache so that the whole pipeline (including variable recovery) reruns
            project.kb.decompilations.cached.clear()
            dec = project.analyses.Decompiler("convert")
            assert dec.codegen is not None and dec.codegen.text is not None
            output.append(dec.codegen.text)

            if i > 0 and output[0] != output[i]:
                diff = "".join(
                    difflib.unified_diff(
                        output[0].splitlines(keepends=True),
                        output[i].splitlines(keepends=True),
                        fromfile="output[0]",
                        tofile=f"output[{i}]",
                    )
                )
                assert False, f"Re-decompilation of convert() differs at iteration {i}:\n{diff}"

        # the stack arrays must carry generated names, not the default s_<offset> fallback
        assert "s_1818" not in output[0]
        assert "s_1018" not in output[0]
        assert "s_818" not in output[0]

    def test_redecompilation_does_not_duplicate_stack_variables(self):
        """
        Regression: The number of recovered stack variables must not grow when a function is decompiled repeatedly.
        """

        binary_path = os.path.join(bin_location, "tests", "x86_64", "1after909")
        project = angr.Project(binary_path)
        project.analyses.CFGFast(normalize=True)
        func = project.kb.functions["convert"]

        counts = []
        for _ in range(3):
            project.kb.decompilations.cached.clear()
            project.analyses.Decompiler(func)
            varman = project.kb.dec_variables[func.addr]
            counts.append(len(varman.get_variables("stack")))

        assert counts[0] == counts[1] == counts[2], f"stack variables accumulate across decompilations: {counts}"


if __name__ == "__main__":
    unittest.main()
