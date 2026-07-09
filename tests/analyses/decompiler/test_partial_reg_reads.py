#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import re
import unittest

import networkx

import angr
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestPartialRegReads(unittest.TestCase):
    def test_partial_reg_read_after_full_reg_write(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions[0x132B0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # the variable used in the condition `if (v28 > 4)` (within the do-while loop) must be properly assigned before
        # the loop; so we should expect two assignments to this variable in the decompilation
        cond = re.search(r"if \((?P<var>\w+) > 4\)", dec.codegen.text)
        assert cond is not None
        var_name = cond.group("var")

        # also find the unicode variable on the stack
        unicode_var = re.search(r"UNICODE_STRING (?P<var>\w+);  // \[bp-0x50\]", dec.codegen.text)
        assert unicode_var is not None
        unicode_var_name = unicode_var.group("var")

        # let's build a graph of assignments
        g = networkx.MultiDiGraph()
        for match in re.finditer(r"(?P<dst>\S+) = (?P<src>\S+)[;,]", dec.codegen.text):
            dst = match.group("dst")
            src = match.group("src")
            g.add_edge(dst, src)

        assert var_name in g
        assert f"{unicode_var_name}.Length" in g

        # there should be two paths from var_name to unicode_var_name.Length, which represents two different
        # assignments (one before the do-while loop, one at the end of the do-while loop).
        simple_paths = list(networkx.all_simple_paths(g, var_name, f"{unicode_var_name}.Length"))
        assert len(simple_paths) == 2, (
            f"Expect two assignments to {var_name} from {unicode_var_name}.Length; found {len(simple_paths)}"
        )


class TestSubRegReadAfterCallClobber(unittest.TestCase):
    """
    A call clobbers caller-saved registers. Reading a high sub-register (e.g. dh, ch) of a clobbered register
    afterwards -- without a wider write that would redefine it -- must be treated as a fresh post-call value, not as a
    value coming from before the function. Otherwise SSA rewriting cannot find a virtual variable for the read and
    raises a KeyError under fail_fast. See ssailification traversal_engine.register_get / register_set / call handling.
    """

    @staticmethod
    def _decompile_shellcode(code: bytes):
        proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
        cfg = proj.analyses.CFGFast(
            normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=not WORKER
        )
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        func = cfg.functions[0x400000]
        dec = proj.analyses.Decompiler(func, cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec

    def test_high_subreg_read_after_call(self):
        # _start:  call helper; mov al, dh; ret       helper: xor edx, edx; ret
        # dh (reg offset 33) is read after the call clobbers rdx (base offset 32) and is never otherwise written.
        code = bytes.fromhex("e80300000088f0c331d2c3")
        self._decompile_shellcode(code)

    def test_high_subreg_read_after_partial_low_write(self):
        # _start:  call helper; mov cl, 1; mov al, ch; ret       helper: xor ecx, ecx; ret
        # The call clobbers rcx; the partial write to cl (offset 24) must not un-blackout ch (offset 25), which is
        # still clobbered when it is read.
        code = bytes.fromhex("e805000000b10188e8c331c9c3")
        self._decompile_shellcode(code)


if __name__ == "__main__":
    unittest.main()
