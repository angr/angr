#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
import struct
from unittest import TestCase, main

import archinfo

from angr import Project, load_shellcode, types
from angr.calling_conventions import (
    SimCCMicrosoftAMD64,
    SimCCMicrosoftFastcall,
    SimCCN32,
    SimCCN32LinuxSyscall,
    SimCCN64,
    SimCCN64LinuxSyscall,
    SimCCRISCV64,
    SimCCSystemVAMD64,
    SimReferenceArgument,
    SimRegArg,
    SimStackArg,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeInt,
    default_cc,
)
from angr.sim_type import (
    SimCppClass,
    SimStructValue,
    SimTypeChar,
    SimTypeDouble,
    SimTypeLongLong,
    SimTypeRef,
    parse_file,
)

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

    def test_microsoft_fastcall_large_arg(self):
        # Regression test: a >DWORD argument (e.g. __int64/double) landing on a register position
        # must NOT raise "doesn't know how to store large types". Per the __fastcall ABI such
        # arguments are passed on the stack and do not consume an ECX/EDX slot.
        arch = archinfo.arch_from_id("x86")
        cc = SimCCMicrosoftFastcall(arch)

        def footprints(proto):
            return [list(loc.get_footprint()) for loc in cc.arg_locs(proto.with_arch(arch))]

        # __int64 first arg -> stack (two words); the following int still gets ECX.
        assert footprints(SimTypeFunction([SimTypeLongLong(), SimTypeInt()], SimTypeInt())) == [
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
            [SimRegArg("ecx", 4)],
        ]
        # Two small ints fill ECX/EDX, the __int64 spills to the stack.
        assert footprints(SimTypeFunction([SimTypeInt(), SimTypeInt(), SimTypeLongLong()], SimTypeInt())) == [
            [SimRegArg("ecx", 4)],
            [SimRegArg("edx", 4)],
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
        ]
        # An __int64 between two ints: it skips the registers; the trailing int still gets EDX.
        assert footprints(SimTypeFunction([SimTypeInt(), SimTypeLongLong(), SimTypeInt()], SimTypeInt())) == [
            [SimRegArg("ecx", 4)],
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
            [SimRegArg("edx", 4)],
        ]
        # Doubles are passed on the stack too and do not consume a register.
        assert footprints(SimTypeFunction([SimTypeDouble(), SimTypeInt()], SimTypeInt())) == [
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
            [SimRegArg("ecx", 4)],
        ]
        # A sub-DWORD integer still uses a register, refined to its size.
        char_locs = cc.arg_locs(SimTypeFunction([SimTypeChar(), SimTypeInt()], SimTypeInt()).with_arch(arch))
        assert isinstance(char_locs[0], SimRegArg) and char_locs[0].reg_name == "ecx" and char_locs[0].size == 1
        assert char_locs[1] == SimRegArg("edx", 4)

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

    def _mips_int_arg_locs(self, cc_cls, arch, arg_types):
        proto = SimTypeFunction(arg_types, SimTypeInt()).with_arch(arch)
        locs = []
        for loc in cc_cls(arch).arg_locs(proto):
            if isinstance(loc, SimRegArg):
                locs.append(("reg", loc.reg_name, loc.reg_offset, loc.size))
            elif isinstance(loc, SimStackArg):
                locs.append(("stack", loc.stack_offset, loc.size))
            else:
                locs.append(loc)
        return locs

    def test_mips_n32_agrees_with_n64_on_argument_slots(self):
        # n32 passes arguments in the 64-bit MIPS register file even though its pointers, and so
        # archinfo's ``bits``, are 32. Deriving the slot width from ``bits`` puts a 32-bit argument
        # in the sign-extension half of a0 on big-endian, where the callee never reads it.
        int_args = [SimTypeInt(), SimTypeInt()]
        for endness in (archinfo.Endness.BE, archinfo.Endness.LE):
            n32 = self._mips_int_arg_locs(SimCCN32, archinfo.ArchMIPSN32(endness), int_args)
            n64 = self._mips_int_arg_locs(SimCCN64, archinfo.ArchMIPS64(endness), int_args)
            assert n32 == n64, f"{endness}: n32 {n32} != n64 {n64}"

        # Spelled out, so that a change to both conventions at once cannot make the check above vacuous:
        # big-endian puts the low-order half of a 64-bit register at offset 4.
        assert self._mips_int_arg_locs(SimCCN32, archinfo.ArchMIPSN32(archinfo.Endness.BE), int_args) == [
            ("reg", "a0", 4, 4),
            ("reg", "a1", 4, 4),
        ]
        assert self._mips_int_arg_locs(SimCCN32, archinfo.ArchMIPSN32(archinfo.Endness.LE), int_args) == [
            ("reg", "a0", 0, 4),
            ("reg", "a1", 0, 4),
        ]

    def test_mips_n32_passes_a_64_bit_scalar(self):
        # The whole scalar lives in one 64-bit argument register, exactly as on n64; a four-byte
        # slot cannot hold it and the base SimCC rejects the prototype outright.
        args = [SimTypeLongLong(), SimTypeInt()]
        for endness in (archinfo.Endness.BE, archinfo.Endness.LE):
            n32 = self._mips_int_arg_locs(SimCCN32, archinfo.ArchMIPSN32(endness), args)
            n64 = self._mips_int_arg_locs(SimCCN64, archinfo.ArchMIPS64(endness), args)
            assert n32 == n64, f"{endness}: n32 {n32} != n64 {n64}"
            assert n32[0] == ("reg", "a0", 0, 8)

    def test_mips_n32_spills_to_n64_sized_stack_slots(self):
        # Nine integers exhaust a0-a7; the tenth argument lands on the stack, whose slot is as wide
        # as the register it follows.
        args = [SimTypeInt()] * 10
        for endness in (archinfo.Endness.BE, archinfo.Endness.LE):
            n32 = self._mips_int_arg_locs(SimCCN32, archinfo.ArchMIPSN32(endness), args)
            n64 = self._mips_int_arg_locs(SimCCN64, archinfo.ArchMIPS64(endness), args)
            assert n32 == n64, f"{endness}: n32 {n32} != n64 {n64}"
            assert n32[8][0] == "stack"
            assert n32[9][1] - n32[8][1] == 8

    def test_mips_n32_syscall_cc_agrees_with_n64(self):
        args = [SimTypeInt(), SimTypeLongLong()]
        for endness in (archinfo.Endness.BE, archinfo.Endness.LE):
            n32 = self._mips_int_arg_locs(SimCCN32LinuxSyscall, archinfo.ArchMIPSN32(endness), args)
            n64 = self._mips_int_arg_locs(SimCCN64LinuxSyscall, archinfo.ArchMIPS64(endness), args)
            assert n32 == n64, f"{endness}: n32 {n32} != n64 {n64}"


if __name__ == "__main__":
    main()
