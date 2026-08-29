#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import difflib
import os
import re
import unittest

import angr
from angr.utils.loader import is_in_readonly_section, is_in_readonly_segment
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

    def test_data_references_do_not_depend_on_decompilation_order(self):
        """Regression test for the memory_data half of https://github.com/angr/angr/issues/7003."""

        binary_path = os.path.join(bin_location, "tests", "armel", "libsoap.so")
        soap_attribute = 0x4122A0
        # holds the same two string addresses in ordinary statements, where soap_attribute() reaches them
        # only through the condition of an if-else chain
        other = 0x412CC8
        # "=\"" -- referenced by soap_attribute() and by `other`, and by neither one's blocks
        shared_string = 0x4256C4

        def decompile(order: tuple[int, ...]) -> tuple[str, bool]:
            project = angr.Project(binary_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast(data_references=True, normalize=True)
            assert shared_string not in cfg.model.memory_data, "CFGFast already found the constant"
            texts = {}
            contributed = False
            for addr in order:
                dec = project.analyses.Decompiler(project.kb.functions[addr], cfg=cfg.model)
                assert dec.codegen is not None and dec.codegen.text is not None
                texts[addr] = dec.codegen.text
                if addr == soap_attribute and order[0] == soap_attribute:
                    # whether soap_attribute() contributes the constant itself, before anything else runs
                    contributed = shared_string in cfg.model.memory_data
            return texts[soap_attribute], contributed

        alone, contributed = decompile((soap_attribute, other))
        assert contributed, (
            f"decompiling {soap_attribute:#x} did not add {shared_string:#x} to memory_data, so whether it "
            f"renders as a literal depends on some other function having been decompiled first"
        )

        after_other, _ = decompile((other, soap_attribute))
        literals = re.compile(r'"(?:[^"\\]|\\.)*"')
        assert sorted(set(literals.findall(alone))) == sorted(set(literals.findall(after_other))), (
            f"the string literals in {soap_attribute:#x} depend on whether {other:#x} was decompiled first"
        )
        # all four are reached through call arguments inside conditions, which the collector used to walk past
        assert set(literals.findall(alone)) >= {'"xmlns:"', '" "', r'"=\""', r'"\""'}

    def test_data_references_are_not_added_for_writable_memory(self):
        """A constant pointing into writable memory must not gain a MemoryData entry.

        The bytes at such an address are whatever the program will later write there, so classifying them
        makes the code generator drop a typed global for a raw pointer dereference.
        """

        binary_path = os.path.join(bin_location, "tests", "armhf", "fauxware")
        # in .data; decompiling 0x104c9 used to classify it as a pointer array
        writable = 0x207D0

        project = angr.Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast(data_references=True, normalize=True)
        assert writable not in cfg.model.memory_data, "CFGFast already recorded the address"
        assert not is_in_readonly_section(project, writable) and not is_in_readonly_segment(project, writable)

        for func in sorted(project.kb.functions.values(), key=lambda f: f.addr):
            if func.is_simprocedure or func.is_plt or func.is_alignment or not func.size:
                continue
            project.analyses.Decompiler(func, cfg=cfg.model)

        assert writable not in cfg.model.memory_data, (
            f"decompilation added {writable:#x} to memory_data, but it is not in read-only memory"
        )

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
