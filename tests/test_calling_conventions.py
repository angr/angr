#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
import struct
from unittest import TestCase, main

import archinfo

from angr import Project, calling_conventions, load_shellcode, types
from angr.calling_conventions import (
    SimArrayArg,
    SimCC,
    SimCCARM,
    SimCCARMHF,
    SimCCARMLinuxSyscall,
    SimCCAArch64,
    SimCCCdecl,
    SimCCMicrosoftAMD64,
    SimCCMicrosoftCdecl,
    SimCCMicrosoftFastcall,
    SimCCN32,
    SimCCN32LinuxSyscall,
    SimCCN64,
    SimCCN64LinuxSyscall,
    SimCCRISCV64,
    SimCCStdcall,
    SimCCSystemVAMD64,
    SimCCX86FreeBSDSyscall,
    SimCCX86LinuxSyscall,
    SimComboArg,
    SimReferenceArgument,
    SimRegArg,
    SimStackArg,
    SimStructArg,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeInt,
    default_cc,
)
from angr.engines.pcode.cc import SimCCPARISC
from angr.errors import AngrTypeError
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimStructValue,
    SimTypeArray,
    SimTypeBottom,
    SimTypeChar,
    SimTypeDouble,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimTypeRef,
    SimUnion,
    TypeRef,
    parse_file,
)

from .common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCallingConvention(TestCase):
    def test_arm_empty_struct_argument_uses_an_integer_slot(self):
        for arch, cc_cls in ((archinfo.ArchARM(), SimCCARM), (archinfo.ArchARMHF(), SimCCARMHF)):
            cc = cc_cls(arch)
            empty = SimStruct({}, name="empty").with_arch(arch)

            assert empty.size == 0

            proto = SimTypeFunction([empty, SimTypeInt()], SimTypeInt()).with_arch(arch)
            empty_loc, int_loc = cc.arg_locs(proto)
            assert isinstance(empty_loc, SimStructArg)
            assert not empty_loc.get_footprint()
            assert int_loc == SimRegArg("r1", 4)

    def test_opaque_cpp_class_returns_are_placed_like_integers(self):
        for arch, cc_cls, return_reg in (
            (archinfo.ArchPcode("pa-risc:BE:32:default"), SimCCPARISC, "r28"),
            (archinfo.ArchMIPSN32(), SimCCN32, "v0"),
        ):
            cc = cc_cls(arch)
            opaque = SimCppClass(unique_name="Opaque", name="Opaque", members={}, size=32)
            opaque_loc = cc.return_val(opaque)
            integer_loc = cc.return_val(SimTypeNum(32, signed=False))
            assert opaque_loc is not None
            assert integer_loc is not None
            assert opaque_loc.get_footprint() == integer_loc.get_footprint()
            assert isinstance(opaque_loc, SimRegArg)
            assert opaque_loc.reg_name == return_reg
            assert opaque_loc.size == 4

            known_layout = SimCppClass(
                unique_name="Pair",
                name="Pair",
                members={"a": SimTypeInt(), "b": SimTypeInt()},
                size=64,
            )
            with self.assertRaises(AngrTypeError):
                cc.return_val(known_layout)

            unsized = SimCppClass(unique_name="Unsized", name="Unsized", members={})
            with self.assertRaises(AngrTypeError):
                cc.return_val(unsized)

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

    def test_arg_locs_union_without_sized_members(self):
        arch = archinfo.ArchX86()
        cc = SimCCMicrosoftCdecl(arch)
        unions = (
            SimUnion({}, name="empty"),
            SimUnion({"member": SimTypeBottom()}, name="bottom"),
            SimUnion({"member": SimTypeRef("opaque", SimStruct)}, name="reference"),
        )

        for union in unions:
            union = union.with_arch(arch)
            assert union.size == arch.bits
            proto = SimTypeFunction([union], SimTypeInt()).with_arch(arch)
            assert len(cc.arg_locs(proto)) == 1

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

    def test_aarch64_aggregate_args(self):
        arch = archinfo.arch_from_id("aarch64")
        cc = SimCCAArch64(arch)

        def locs(*args):
            return cc.arg_locs(SimTypeFunction(list(args), SimTypeInt()).with_arch(arch))

        integer = SimTypeInt()
        small = SimStruct({"a": SimTypeInt(), "b": SimTypeInt()}, name="Small")
        pair = SimStruct({"x": SimTypeLongLong(), "y": SimTypeLongLong()}, name="Pair")
        big = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong(), "c": SimTypeLongLong()}, name="Big")

        # A composite of one double-word takes one register, one of two takes a consecutive pair.
        assert locs(small)[0].get_footprint() == {SimRegArg("x0", 8)}
        assert locs(pair)[0].get_footprint() == {SimRegArg("x0", 8), SimRegArg("x1", 8)}

        # A composite larger than 16 bytes is passed by reference.
        big_loc = locs(big)[0]
        assert isinstance(big_loc, SimReferenceArgument)
        assert big_loc.ptr_loc == SimRegArg("x0", 8)
        assert big_loc.main_loc.get_footprint() == {SimStackArg(0, 8), SimStackArg(8, 8), SimStackArg(0x10, 8)}

        # Seven integers leave one register free, which a two-register composite cannot use: it goes on
        # the stack, and the register it skipped is not given to the argument after it either.
        spilled = locs(*[integer] * 7, pair, integer)
        assert spilled[6] == SimRegArg("x6", 4)
        assert spilled[7].get_footprint() == {SimStackArg(0, 8), SimStackArg(8, 8)}
        assert spilled[8] == SimStackArg(0x10, 4)

        # A stack argument starts at its natural alignment even if an earlier spill left NSAA only 8-byte aligned.
        aligned_spill = locs(*[integer] * 9, SimTypeNum(128))
        assert aligned_spill[8] == SimStackArg(0, 4)
        assert aligned_spill[9].get_footprint() == {SimStackArg(0x10, 8), SimStackArg(0x18, 8)}

        # A 16-byte integral argument takes a register pair, starting on an even-numbered register.
        assert locs(integer, SimTypeNum(128))[1].get_footprint() == {SimRegArg("x2", 8), SimRegArg("x3", 8)}

        # Wider integral types map to arrays of 128-bit units, and therefore follow the large-composite rule.
        wide = locs(SimTypeNum(256))[0]
        assert isinstance(wide, SimReferenceArgument)
        assert wide.ptr_loc == SimRegArg("x0", 8)
        assert wide.main_loc.get_footprint() == {
            SimStackArg(0, 8),
            SimStackArg(8, 8),
            SimStackArg(0x10, 8),
            SimStackArg(0x18, 8),
        }

    def test_aarch64_aggregate_args_reach_the_callsite(self):
        proj = Project(os.path.join(test_location, "aarch64", "struct_by_value_aarch64.so"), auto_load_libs=False)
        cc = SimCCAArch64(proj.arch)
        pair = SimStruct({"x": SimTypeLongLong(), "y": SimTypeLongLong()}, name="Pair")
        big = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong(), "c": SimTypeLongLong()}, name="Big")
        proto = SimTypeFunction([SimTypeInt(), pair, big, SimTypeInt()], SimTypeInt()).with_arch(proj.arch)
        symbol = proj.loader.find_symbol("_Z9call_theml")
        assert symbol is not None
        addr = symbol.rebased_addr

        state = proj.factory.call_state(
            addr, 7, {"x": 11, "y": 22}, {"a": 33, "b": 44, "c": 55}, 9, cc=cc, prototype=proto
        )
        evaluate = state.solver.eval
        assert evaluate(state.regs.x0) == 7
        assert evaluate(state.regs.x1) == 11
        assert evaluate(state.regs.x2) == 22
        referenced = evaluate(state.regs.x3)
        assert [evaluate(state.memory.load(referenced + 8 * i, 8, endness="Iend_LE")) for i in range(3)] == [33, 44, 55]
        assert evaluate(state.regs.x4) == 9

        # A final aggregate spill still contributes to the caller's stack allocation.
        spilled_proto = SimTypeFunction([SimTypeInt()] * 7 + [pair], SimTypeInt()).with_arch(proj.arch)
        spilled_locs = cc.arg_locs(spilled_proto)
        assert cc.stack_space(spilled_locs) == 16
        initial_sp = 0x7FFF_0000
        base_state = proj.factory.blank_state()
        base_state.regs.sp = initial_sp
        spilled_state = proj.factory.call_state(
            addr,
            *range(7),
            {"x": 0x1111, "y": 0x2222},
            base_state=base_state,
            cc=cc,
            prototype=spilled_proto,
        )
        assert evaluate(spilled_state.regs.sp) == initial_sp - 16
        assert evaluate(spilled_state.memory.load(initial_sp - 16, 8, endness="Iend_LE")) == 0x1111
        assert evaluate(spilled_state.memory.load(initial_sp - 8, 8, endness="Iend_LE")) == 0x2222

    def test_aarch64_class_by_value_argument(self):
        proj = Project(os.path.join(test_location, "aarch64", "struct_by_value_aarch64.so"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)
        func = next(f for f in proj.kb.functions.values() if f.name == "_Z8take_big3Big" and not f.is_plt)
        assert func.prototype is not None
        assert isinstance(func.prototype.args[0], SimCppClass)
        assert len(proj.factory.cc().arg_locs(func.prototype.with_arch(proj.arch))) == 1
        assert proj.analyses.Decompiler(func, cfg=cfg.model).codegen is not None

    def test_simcc_arg_locs_returnty_unresolved_simtyperef(self):
        func_proto = SimTypeFunction([], SimTypeRef("std::wstring_t", SimCppClass))

        for arch in [archinfo.ArchAMD64, archinfo.ArchX86, archinfo.ArchARM]:
            proto = func_proto.with_arch(arch())
            cc = default_cc(arch.name)(arch())

            # It should not raise any exception!
            arg_locs = list(cc.arg_locs(proto))
            assert arg_locs is not None

    def test_simcc_arg_locs_returnty_typeref_without_size(self):
        # a TypeRef around an unresolvable SimTypeRef (angr/angr#7135) or an empty class has no usable size
        arch = archinfo.ArchAMD64()
        cc = SimCCMicrosoftAMD64(arch)
        for inner in (SimTypeRef("class Base::Type", SimCppClass), SimCppClass(name="class Base::Type")):
            proto = SimTypeFunction([SimTypeInt()], TypeRef("class Base::Type", inner)).with_arch(arch)
            assert not cc.return_in_implicit_outparam(proto.returnty)
            assert len(cc.arg_locs(proto)) == 1

    def _arg_layout(self, cc, arg_types):
        proto = SimTypeFunction(arg_types, SimTypeInt()).with_arch(cc.arch)
        try:
            return [sorted(loc.get_footprint(), key=repr) for loc in cc.arg_locs(proto)]
        except Exception as e:  # pylint: disable=broad-exception-caught
            return f"{type(e).__name__}: {e}"

    def test_next_arg_lays_a_typeref_out_as_the_type_it_names(self):
        named = [
            ("fpos_t", lambda: SimStruct({}, name="fpos_t")),
            ("int64_t", SimTypeLongLong),
            ("point_t", lambda: SimStruct({"x": SimTypeInt(), "y": SimTypeInt()}, name="point")),
            ("quad_t", lambda: SimTypeFixedSizeArray(SimTypeInt(), 4)),
            ("real_t", SimTypeDouble),
        ]
        conventions = [
            cls
            for cls in vars(calling_conventions).values()
            if isinstance(cls, type) and issubclass(cls, SimCC) and cls.ARCH is not None
        ]
        assert len(conventions) > 20, len(conventions)
        for cls in sorted(conventions, key=lambda c: c.__name__):
            arch_cls = cls.ARCH
            assert arch_cls is not None
            cc = cls(arch_cls())  # type: ignore[reportCallIssue]
            for name, make in named:
                direct = [SimTypePointer(SimTypeChar()), make(), SimTypeInt()]
                aliased = [SimTypePointer(SimTypeChar()), TypeRef(name, make()), SimTypeInt()]
                self.assertEqual(
                    self._arg_layout(cc, aliased),
                    self._arg_layout(cc, direct),
                    f"{cls.__name__} {name}",
                )

        cc = SimCCMicrosoftCdecl(archinfo.ArchX86())
        assert self._arg_layout(
            cc, [SimTypePointer(SimTypeChar()), TypeRef("fpos_t", SimStruct({}, name="fpos_t")), SimTypeInt()]
        ) == [[SimStackArg(0x4, 4)], [], [SimStackArg(0x8, 4)]]
        assert self._arg_layout(
            cc, [SimTypePointer(SimTypeChar()), TypeRef("int64_t", SimTypeLongLong()), SimTypeInt()]
        ) == [[SimStackArg(0x4, 4)], [SimStackArg(0x8, 4), SimStackArg(0xC, 4)], [SimStackArg(0x10, 4)]]

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

    def test_arm_linux_syscall_argument_registers(self):
        for endness in (archinfo.Endness.LE, archinfo.Endness.BE):
            arch = archinfo.ArchARM(endness=endness)
            cc = SimCCARMLinuxSyscall(arch)

            # pread64 has three word-sized arguments followed by a loff_t. The
            # 64-bit value skips odd r3, occupies r4:r5, and leaves r6 usable.
            proto = SimTypeFunction(
                [SimTypeInt(), SimTypePointer(SimTypeChar()), SimTypeInt(), SimTypeLongLong(), SimTypeInt()],
                SimTypeInt(),
            ).with_arch(arch)
            locs = cc.arg_locs(proto)
            assert locs[:3] == [SimRegArg("r0", 4), SimRegArg("r1", 4), SimRegArg("r2", 4)]
            assert isinstance(locs[3], SimComboArg)
            expected_wide = [SimRegArg("r4", 4), SimRegArg("r5", 4)]
            if endness == archinfo.Endness.BE:
                expected_wide.reverse()
            assert locs[3].locations == expected_wide
            assert locs[4] == SimRegArg("r6", 4)

            # There is no stack fallback: the kernel receives at most seven
            # word-sized argument slots in r0-r6.
            with self.assertRaisesRegex(TypeError, "exhausted r0-r6"):
                cc.arg_locs(SimTypeFunction([SimTypeInt()] * 8, SimTypeInt()).with_arch(arch))

    def test_x86_linux_syscall_argument_registers(self):
        arch = archinfo.arch_from_id("x86")
        cc = SimCCX86LinuxSyscall(arch)

        # fadvise64_64 is where the i386 kernel spells the rule out: its entry
        # point takes fd, offset_low, offset_high, len_low, len_high and advice,
        # so the two loff_t arguments fill ecx:edx and esi:edi and advice still
        # reaches ebp. The first wide value starting in ecx also shows there is
        # no even-slot alignment: it takes the next two registers as they come.
        proto = SimTypeFunction(
            [SimTypeInt(), SimTypeLongLong(), SimTypeLongLong(), SimTypeInt()],
            SimTypeInt(),
        ).with_arch(arch)
        locs = cc.arg_locs(proto)
        assert locs[0] == SimRegArg("ebx", 4)
        assert isinstance(locs[1], SimComboArg)
        assert locs[1].locations == [SimRegArg("ecx", 4), SimRegArg("edx", 4)]
        assert isinstance(locs[2], SimComboArg)
        assert locs[2].locations == [SimRegArg("esi", 4), SimRegArg("edi", 4)]
        assert locs[3] == SimRegArg("ebp", 4)

        # There is no stack fallback: the kernel receives at most six word-sized
        # argument slots in ebx-ebp.
        with self.assertRaisesRegex(TypeError, "exhausted ebx-ebp"):
            cc.arg_locs(SimTypeFunction([SimTypeInt()] * 7, SimTypeInt()).with_arch(arch))

    def test_x86_freebsd_syscall_stack_arguments(self):
        arch = archinfo.arch_from_id("x86")
        cc = SimCCX86FreeBSDSyscall(arch)

        # FreeBSD takes its i386 syscall arguments from the stack, not from registers:
        # the kernel reads them from tf_esp + sizeof(uint32_t), past the slot a call to a
        # libc stub would have left the return address in. So the first argument sits one
        # word above the stack pointer and they follow one word apart.
        proto = SimTypeFunction([SimTypeInt(), SimTypeInt(), SimTypeInt()], SimTypeInt()).with_arch(arch)
        assert cc.arg_locs(proto) == [SimStackArg(4, 4), SimStackArg(8, 4), SimStackArg(12, 4)]

        # There is no argument register to run out of, so the stack keeps going.
        wide = SimTypeFunction([SimTypeInt()] * 8, SimTypeInt()).with_arch(arch)
        assert cc.arg_locs(wide)[-1] == SimStackArg(32, 4)

        # The number travels in eax, which is also where the result lands.
        return_val = cc.RETURN_VAL
        assert isinstance(return_val, SimRegArg)
        assert return_val.reg_name == "eax"

    def test_x86_cdecl_array_and_union_return(self):
        arch = archinfo.arch_from_id("x86")
        conventions = (SimCCCdecl(arch), SimCCMicrosoftCdecl(arch), SimCCStdcall(arch))

        exact = SimTypeArray(SimTypeInt(), 2).with_arch(arch)
        large = SimTypeArray(SimTypeInt(), 8).with_arch(arch)
        pair = SimStruct({"a": SimTypeInt(), "b": SimTypeInt()}, name="pair").with_arch(arch)
        big = SimStruct({f"f{i}": SimTypeInt() for i in range(8)}, name="big8").with_arch(arch)
        union = SimUnion({"i": SimTypeInt(), "p": SimTypePointer(SimTypeChar())}, name="u").with_arch(arch)

        # Microsoft cdecl and stdcall return an eight-byte array in EAX:EDX, like an equal-sized struct.
        for cc in conventions[1:]:
            exact_ret = cc.return_val(exact)
            pair_ret = cc.return_val(pair)
            assert isinstance(exact_ret, SimArrayArg)
            assert pair_ret is not None
            assert set(exact_ret.get_footprint()) == set(pair_ret.get_footprint())
            assert cc.return_in_implicit_outparam(exact) is False

        # Every convention uses its existing struct rule for a larger array, including reserving the
        # hidden return pointer before placing the declared arguments.
        for cc in conventions:
            large_ret = cc.return_val(large)
            big_ret = cc.return_val(big)
            assert isinstance(large_ret, SimReferenceArgument)
            assert isinstance(big_ret, SimReferenceArgument)
            assert large_ret.ptr_loc == big_ret.ptr_loc == SimStackArg(0, 4)
            assert cc.return_in_implicit_outparam(large) is True

            array_proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], large).with_arch(arch)
            struct_proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], big).with_arch(arch)
            assert [list(loc.get_footprint()) for loc in cc.arg_locs(array_proto)] == [
                list(loc.get_footprint()) for loc in cc.arg_locs(struct_proto)
            ]

            # A union is placed like its widest member, as the layout helper already does.
            union_ret = cc.return_val(union)
            int_ret = cc.return_val(SimTypeInt().with_arch(arch))
            assert union_ret is not None
            assert int_ret is not None
            assert set(union_ret.get_footprint()) == set(int_ret.get_footprint())

            # Arrays without a concrete layout stay on the named aggregate-refusal path instead of
            # reaching the layout helper with a zero or unknown size.
            incomplete = SimTypeArray(SimTypeChar(), None).with_arch(arch)
            unsized = SimTypeArray(SimTypeBottom(), 2).with_arch(arch)
            for unrepresentable in incomplete, unsized:
                with self.assertRaises(AngrTypeError):
                    cc.return_val(unrepresentable)
                assert cc.return_in_implicit_outparam(unrepresentable) is False

    def test_microsoft_fastcall_aggregate_return(self):
        # Regression test: __fastcall changes how arguments are passed, not how values are returned.
        # Without a return_val override the base class refuses every aggregate return type, and a
        # decompiled function returning a small struct comes out empty. This is the return-side
        # counterpart of test_microsoft_fastcall_large_arg above.
        arch = archinfo.arch_from_id("x86")
        fastcall = SimCCMicrosoftFastcall(arch)
        cdecl = SimCCMicrosoftCdecl(arch)

        small = SimStruct({"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeInt()}, name="fatptr").with_arch(arch)
        large = SimStruct({f"f{i}": SimTypeInt() for i in range(8)}, name="big").with_arch(arch)

        # An eight-byte aggregate comes back in EAX:EDX, the same as __cdecl on Windows x86.
        small_ret = fastcall.return_val(small)
        assert isinstance(small_ret, SimStructArg)
        assert list(small_ret.locs.values()) == [SimRegArg("eax", 4), SimRegArg("edx", 4)]
        cdecl_small = cdecl.return_val(small)
        assert isinstance(cdecl_small, SimStructArg)
        assert set(small_ret.get_footprint()) == set(cdecl_small.get_footprint())
        assert fastcall.return_in_implicit_outparam(small) is False

        # A larger one is written through a hidden pointer. That pointer is the call's first
        # argument, so __fastcall passes it in ECX -- not in the stack slot __cdecl uses. This is
        # why the implementation cannot simply be inherited from the cdecl convention.
        large_ret = fastcall.return_val(large)
        assert isinstance(large_ret, SimReferenceArgument)
        assert large_ret.ptr_loc == SimRegArg("ecx", 4)
        cdecl_large = cdecl.return_val(large)
        assert isinstance(cdecl_large, SimReferenceArgument)
        assert cdecl_large.ptr_loc == SimStackArg(0, 4)
        assert fastcall.return_in_implicit_outparam(large) is True

        # The hidden pointer consumes ECX, so the declared arguments shift along.
        proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], large).with_arch(arch)
        assert [list(loc.get_footprint()) for loc in fastcall.arg_locs(proto)] == [
            [SimRegArg("edx", 4)],
            [SimStackArg(0x4, 4)],
        ]


if __name__ == "__main__":
    main()
