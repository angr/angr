#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
import struct
from unittest import TestCase, main

import archinfo

from angr.calling_conventions import (
    SimReferenceArgument,
    SimStackArg,
    SimTypeInt,
    SimTypeFixedSizeArray,
    SimCCSystemVAMD64,
    SimTypeFunction,
    SimRegArg,
    SimCCMicrosoftAMD64,
    SimCCRISCV64,
)
from angr.sim_type import parse_file, SimStructValue, SimTypeRef, SimCppClass
from angr.calling_conventions import default_cc
from angr import Project, load_shellcode, types

from .common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCallingConvention(TestCase):
    def test_SystemVAMD64_flatten_int(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)

        int_type = SimTypeInt().with_arch(arch)
        flattened_int = cc._flatten(int_type)
        self.assertTrue(all(isinstance(key, int) for key in flattened_int))
        self.assertTrue(all(isinstance(value, list) for value in flattened_int.values()))
        for v in flattened_int.values():
            for subtype in v:
                self.assertIsInstance(subtype, SimTypeInt)

    def test_SystemVAMD64_flatten_array(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)

        int_type = SimTypeInt().with_arch(arch)
        array_type = SimTypeFixedSizeArray(int_type, 20).with_arch(arch)
        flattened_array = cc._flatten(array_type)
        self.assertTrue(all(isinstance(key, int) for key in flattened_array))
        self.assertTrue(all(isinstance(value, list) for value in flattened_array.values()))
        for v in flattened_array.values():
            for subtype in v:
                self.assertIsInstance(subtype, SimTypeInt)

    def test_arg_locs_array(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)
        proto = SimTypeFunction([SimTypeFixedSizeArray(SimTypeInt().with_arch(arch), 2).with_arch(arch)], None)

        # It should not raise any exception!
        cc.arg_locs(proto)

    def test_struct_ffi(self):
        with open(os.path.join(test_location, "../tests_src/test_structs.c"), encoding="utf-8") as fp:
            decls = parse_file(fp.read())

        p = Project(os.path.join(test_location, "x86_64/test_structs.o"), auto_load_libs=False)

        def make_callable(name):
            return p.factory.callable(p.loader.find_symbol(name).rebased_addr, decls[0][name])

        test_small_struct_return = make_callable("test_small_struct_return")
        result = test_small_struct_return()
        self.assertIsInstance(result, SimStructValue)
        self.assertTrue((result.a == 1).is_true())
        self.assertTrue((result.b == 2).is_true())

    def test_array_ffi(self):
        # NOTE: if this test is failing and you think it is wrong, you might be right :)
        p = load_shellcode(b"\xc3", arch="amd64")
        s = p.factory.blank_state()
        s.regs.rdi = 123
        s.regs.rsi = 456
        s.regs.rdx = 789
        execve = parse_file("int execve(const char *pathname, char *const argv[], char *const envp[]);")[0]["execve"]
        cc = p.factory.cc()
        assert all((x == y).is_true() for x, y in zip(cc.get_args(s, execve), (123, 456, 789)))
        # however, this is definitely right
        assert [list(loc.get_footprint()) for loc in cc.arg_locs(execve)] == [
            [SimRegArg("rdi", 8)],
            [SimRegArg("rsi", 8)],
            [SimRegArg("rdx", 8)],
        ]

    def test_microsoft_amd64(self):
        arch = archinfo.ArchAMD64()
        cc = SimCCMicrosoftAMD64(arch)
        ty1 = parse_file("struct foo { int x; int y; };", arch=arch)[1]["struct foo"]
        loc1 = cc.return_val(ty1, perspective_returned=True)
        assert loc1 is not None
        assert loc1.get_footprint() == {SimRegArg("rax", 8)}
        loc2 = cc.return_val(ty1, perspective_returned=False)
        assert loc2 is not None
        assert loc2.get_footprint() == {SimRegArg("rax", 8)}

        ty3 = parse_file("struct foo { short x; int y; short z; };", arch=arch)[1]["struct foo"]
        loc3 = cc.return_val(ty3, perspective_returned=True)
        assert isinstance(loc3, SimReferenceArgument)
        assert loc3.ptr_loc == SimRegArg("rax", 8)
        assert loc3.main_loc.get_footprint() == {SimStackArg(0, 2), SimStackArg(4, 4), SimStackArg(8, 2)}
        loc4 = cc.return_val(ty3, perspective_returned=False)
        assert isinstance(loc4, SimReferenceArgument)
        assert loc4.ptr_loc == SimRegArg("rcx", 8)
        assert loc4.main_loc.get_footprint() == {SimStackArg(0, 2), SimStackArg(4, 4), SimStackArg(8, 2)}

    def test_riscv64_args_actual_values(self):
        bin_path = os.path.join(test_location, "riscv64", "sim_args_riscv64.so")
        src_location = os.path.join(bin_location, "tests_src")

        proj = Project(bin_path, auto_load_libs=False)

        symbol = proj.loader.find_symbol("complex_func")
        func_addr = symbol.rebased_addr
        cc = SimCCRISCV64(proj.arch)

        c_decl = os.path.join(src_location, "arch", "riscv", "sim_args_riscv64.c")
        with open(c_decl, encoding="utf-8") as f:
            raw_content = f.read()
        defns, _ = types.parse_file(raw_content)
        proto = defns["complex_func"].with_arch(proj.arch)

        args = [100, {"f": 1.0, "i": 2}, 3.0, {"x": 10.0, "y": 20.0, "z": 30.0}, 4, 5, 6, 7, 8, 9.0, 10, 11, 12.0]

        state = proj.factory.call_state(func_addr, *args, cc=cc, prototype=proto)

        assert state.solver.eval(state.regs.a0) == 100

        fa0_val = state.solver.eval(state.regs.fa0[31:0].raw_to_fp())
        a1_val = state.solver.eval(state.regs.a1[31:0])
        assert fa0_val == 1.0
        assert a1_val == 2

        fa1_val = state.solver.eval(state.regs.fa1.raw_to_fp())
        assert fa1_val == 3.0

        s2_ptr = state.solver.eval(state.regs.a2)
        s2_x = state.solver.eval(state.memory.load(s2_ptr, 8, endness="Iend_LE").raw_to_fp())
        assert s2_x == 10.0

        sp_val = state.solver.eval(state.regs.sp)
        r9_on_stack = state.solver.eval(state.memory.load(sp_val, 8, endness="Iend_LE"))
        assert r9_on_stack == 10

        fa3_val = state.solver.eval(state.regs.fa3[31:0].raw_to_fp())
        assert fa3_val == 12.0

    def test_riscv64_args_flatten_actual_values(self):
        bin_path = os.path.join(test_location, "riscv64", "sim_args_flatten_riscv64.so")
        src_location = os.path.join(bin_location, "tests_src")

        proj = Project(bin_path, auto_load_libs=False)

        symbol = proj.loader.find_symbol("complex_func")
        func_addr = symbol.rebased_addr

        cc = SimCCRISCV64(proj.arch)

        c_decl = os.path.join(src_location, "arch", "riscv", "sim_args_flatten_riscv64.c")
        with open(c_decl, encoding="utf-8") as f:
            raw_content = f.read()
        defns, _ = types.parse_file(raw_content)
        proto = defns["complex_func"].with_arch(proj.arch)

        args = [{"f": 1.0, "i": 2}, {"x": 10, "y": 20}, {"a": 101.3, "c": 102.3, "d": 60}]
        state = proj.factory.call_state(func_addr, *args, cc=cc, prototype=proto)

        fa0_val = state.solver.eval(state.regs.fa0[31:0].raw_to_fp())
        a0_val = state.solver.eval(state.regs.a0[31:0])
        assert fa0_val == 1.0
        assert a0_val == 2

        a1_val = state.solver.eval(state.regs.a1)
        assert (a1_val & 0xFFFFFFFF) == 10
        assert (a1_val >> 32) == 20

        a2_bits = state.solver.eval(state.regs.a2)
        a3_val = state.solver.eval(state.regs.a3)

        a2_float = struct.unpack("<d", struct.pack("<Q", a2_bits))[0]
        assert abs(a2_float - 101.3) < 0.00001

        c_bits = a3_val & 0xFFFFFFFF
        c_float = struct.unpack("<f", struct.pack("<I", c_bits))[0]
        assert abs(c_float - 102.3) < 0.00001
        assert (a3_val >> 32) == 60

    def test_simcc_arg_locs_returnty_unresolved_simtyperef(self):
        func_proto = SimTypeFunction([], SimTypeRef("std::wstring_t", SimCppClass))

        for arch in [archinfo.ArchAMD64, archinfo.ArchX86, archinfo.ArchARM]:
            proto = func_proto.with_arch(arch())
            cc = default_cc(arch.name)(arch())

            # It should not raise any exception!
            arg_locs = list(cc.arg_locs(proto))
            assert arg_locs is not None


if __name__ == "__main__":
    main()
