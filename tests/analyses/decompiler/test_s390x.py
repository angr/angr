#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""s390x decompilation regression tests."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.calling_conventions import SimCCS390X, SimReferenceArgument, SimRegArg, SimStackArg
from angr.sim_type import parse_signature


from angr.calling_conventions import SimCCS390X
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeInt
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

    def test_decompile_libstdcxx_hash_long_double(self):
        # std::hash<long double>::operator()(long double) used to crash SimCC.next_arg ("doesn't know how to store
        # large types"). "e"-mangled long double on s390x is the -mlong-double-64 one, so it arrives in f0.
        bin_path = os.path.join(test_location, "s390x", "libstdc++.so.6")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x4A5F50, window=0x200, expand_call_tree=False)
        func = cfg.functions[0x4A5F50]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "operator()(double a0)" in dec.codegen.text


    def test_decompile_libgcc_unwind_raise_exception_narrowed_callee_args(self):
        # Once sub_409608 is decompiled, its 3rd/4th args become `unsigned int`, so the first read of the r5 parameter
        # is its low half (r5_32 at offset 620 on big-endian) and the 64-bit read of r5 inside the loop came later.
        # Re-traversing the entry block reset the widened extern def of r5 back to 4 bytes, the parameter was resized
        # to r5_32, and the 64-bit read crashed ssailification with KeyError: 616.
        bin_path = os.path.join(test_location, "s390x", "libgcc_s.so.1")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x409B90)

        callee = cfg.functions[0x409608]
        assert callee.prototype is not None
        args = list(callee.prototype.args)
        args[2] = SimTypeInt(signed=False).with_arch(proj.arch)
        args[3] = SimTypeInt(signed=False).with_arch(proj.arch)
        callee.prototype = callee.prototype.__class__(args, callee.prototype.returnty).with_arch(proj.arch)
        callee.prototype_source = PrototypeSource.CCA_DECOMPILER

        func = cfg.functions[0x409B90]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        a3 = func.prototype.arg_names[3] if func.prototype.arg_names else "a3"
        # the 4th parameter stays full-width and reaches the call to sub_4084f8 unchanged
        assert f"sub_4084f8(&v23, &v29, v37, {a3});" in text
        # the narrowed call argument is the low half of r5, i.e., a truncation (not a load at &a3 + 4)
        assert f"(unsigned int){a3}," in text
        assert f"&{a3} + 4" not in text


if __name__ == "__main__":
    unittest.main()
