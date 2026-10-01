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
    SimCC,
    SimCCMicrosoftAMD64,
    SimCCMicrosoftCdecl,
    SimCCMicrosoftFastcall,
    SimCCN32,
    SimCCN32LinuxSyscall,
    SimCCN64,
    SimCCN64LinuxSyscall,
    SimCCRISCV64,
    SimCCS390X,
    SimCCSystemVAMD64,
    SimFunctionArgument,
    SimReferenceArgument,
    SimRegArg,
    SimStackArg,
    SimStructArg,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeInt,
    default_cc,
)
from angr.errors import AngrTypeError
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimStructValue,
    SimTypeArray,
    SimTypeBottom,
    SimTypeChar,
    SimTypeDouble,
    SimTypeFloat,
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


def struct_fields(loc: SimFunctionArgument | None) -> dict[str, SimFunctionArgument]:
    """The field locations of an argument the convention laid out as an aggregate."""
    assert isinstance(loc, SimStructArg)
    return loc.locs


def referenced(loc: SimFunctionArgument | None) -> SimReferenceArgument:
    """The argument as a by-reference one, asserting the convention passed it that way."""
    assert isinstance(loc, SimReferenceArgument)
    return loc


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

    def test_s390x_aggregate_args(self):
        # Every location here was read off gcc 15.3.0 output for s390x-unknown-linux-gnu.
        arch = archinfo.arch_from_id("s390x")
        cc = SimCCS390X(arch)

        def locs(*args):
            return cc.arg_locs(SimTypeFunction(list(args), SimTypeInt()).with_arch(arch))

        byte = SimStruct({"a": SimTypeChar()}, name="Byte")
        word = SimStruct({"a": SimTypeInt()}, name="Word")
        chars = SimStruct({"a": SimTypeChar(), "b": SimTypeChar(), "c": SimTypeChar()}, name="Chars")
        doubleword = SimStruct({"a": SimTypeLongLong()}, name="DoubleWord")
        giant = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong()}, name="Giant")
        single = SimStruct({"a": SimTypeFloat()}, name="Single")
        nested = SimStruct({"inner": single}, name="Nested")
        twice = SimStruct({"a": SimTypeDouble()}, name="Twice")
        either = SimUnion({"a": SimTypeInt(), "b": SimTypeFloat()}, name="Either")

        # An aggregate of 1, 2, 4 or 8 bytes is passed in one general register, right-justified in it:
        # gcc loads a one-byte struct with `ic %r2` and a four-byte one with `l %r2`.
        assert struct_fields(locs(byte)[0])["a"] == SimRegArg("r2", 1, 7)
        assert struct_fields(locs(word)[0])["a"] == SimRegArg("r2", 4, 4)
        assert struct_fields(locs(doubleword)[0])["a"] == SimRegArg("r2", 8, 0)

        # A record with one member is passed just as that member would be, so a struct holding one
        # float or double goes in a floating-point register -- and there a short float occupies the
        # leading bytes, not the trailing ones. A union is not unwrapped this way.
        assert struct_fields(locs(single)[0])["a"] == SimRegArg("f0", 4, 0)
        assert struct_fields(struct_fields(locs(nested)[0])["inner"])["a"] == SimRegArg("f0", 4, 0)
        assert struct_fields(locs(twice)[0])["a"] == SimRegArg("f0", 8, 0)
        assert locs(either)[0].get_footprint() == {SimRegArg("r2", 4, 4)}

        # The two register files advance independently: a double takes f0 and leaves r2 for the
        # struct beside it.
        assert [loc.get_footprint() for loc in locs(twice, word)] == [{SimRegArg("f0", 8, 0)}, {SimRegArg("r2", 4, 4)}]

        # An aggregate of any other size is copied by the caller and passed as a pointer.
        three = referenced(locs(chars)[0])
        assert three.ptr_loc == SimRegArg("r2", 8)
        assert three.main_loc.get_footprint() == {SimStackArg(0, 1), SimStackArg(1, 1), SimStackArg(2, 1)}
        sixteen = referenced(locs(giant)[0])
        assert sixteen.ptr_loc == SimRegArg("r2", 8)
        assert sixteen.main_loc.get_footprint() == {SimStackArg(0, 8), SimStackArg(8, 8)}

        # So is any scalar too wide for a register.
        assert referenced(locs(SimTypeNum(128))[0]).ptr_loc == SimRegArg("r2", 8)

        # An opaque aggregate -- a C++ class the header parser gave a size and no members -- is
        # placed by its size, right-justified like any other.
        assert locs(SimCppClass(name="Opaque8", members={}, size=64))[0] == SimRegArg("r2", 8, 0)
        assert locs(SimCppClass(name="Opaque4", members={}, size=32))[0] == SimRegArg("r2", 4, 4)
        assert locs(SimCppClass(name="Opaque1", members={}, size=8))[0] == SimRegArg("r2", 1, 7)
        opaque_twelve = referenced(locs(SimCppClass(name="Opaque12", members={}, size=96))[0])
        assert opaque_twelve.ptr_loc == SimRegArg("r2", 8)
        assert opaque_twelve.main_loc == SimStackArg(0, 12)

        # Out of registers, the value keeps its place in the eight-byte slot: gcc stores a four-byte
        # struct at 164(%r15) and a struct holding a double at 160(%r15), and spills the pointer of a
        # by-reference argument to 160(%r15).
        longs = [SimTypeLongLong()] * 5
        assert struct_fields(locs(*longs, word)[5])["a"] == SimStackArg(0xA4, 4)
        assert referenced(locs(*longs, chars)[5]).ptr_loc == SimStackArg(0xA0, 8)
        assert struct_fields(locs(*([SimTypeDouble()] * 4), twice)[4])["a"] == SimStackArg(0xA0, 8)

    def test_s390x_flexible_array_member_is_still_refused(self):
        # refine_locs_with_struct_type cannot place an array with no length. Variable recovery, the
        # calling-convention fact collector and FCP catch TypeError and ValueError around arg_locs,
        # so this convention refuses such a type the way the base class does rather than asserting.
        arch = archinfo.arch_from_id("s390x")
        cc = SimCCS390X(arch)
        flexible = SimStruct({"n": SimTypeInt(), "d": SimTypeArray(SimTypeInt())}, name="Flexible")
        proto = SimTypeFunction([flexible], SimTypeInt()).with_arch(arch)
        with self.assertRaises(TypeError):
            cc.arg_locs(proto)
        with self.assertRaises(AngrTypeError):
            cc.return_val(flexible.with_arch(arch))

    def test_s390x_aggregate_returns(self):
        arch = archinfo.arch_from_id("s390x")
        cc = SimCCS390X(arch)
        word = SimStruct({"a": SimTypeInt()}, name="Word")

        # An aggregate of any size comes back in memory, so there is no size below which this is
        # false: gcc forwards the hidden pointer even for a one-word struct.
        assert cc.return_in_implicit_outparam(word) is True
        assert cc.return_in_implicit_outparam(SimTypeNum(128).with_arch(arch)) is True
        assert cc.return_in_implicit_outparam(SimTypeInt().with_arch(arch)) is False

        # The caller passes the address of the return area as an implicit first argument in r2 and
        # the function hands that same address back in r2.
        returned = referenced(cc.return_val(word))
        assert returned.ptr_loc == SimRegArg("r2", 8)
        assert struct_fields(returned.main_loc)["a"] == SimStackArg(0, 4)
        assert referenced(cc.return_val(word, perspective_returned=True)).ptr_loc == SimRegArg("r2", 8)

        # A scalar too wide for r2 goes back the same way.
        assert referenced(cc.return_val(SimTypeNum(128).with_arch(arch))).ptr_loc == SimRegArg("r2", 8)

        # The hidden pointer is an argument, so the declared ones shift along one register.
        proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], word).with_arch(arch)
        assert cc.arg_locs(proto) == [SimRegArg("r3", 4, 4), SimRegArg("r4", 4, 4)]

        # An array is the same aggregate rule, and SimTypeFixedSizeArray is an alias of
        # SimTypeArray, so both spellings arrive here.
        sized = SimTypeArray(SimTypeInt(), 4).with_arch(arch)
        assert cc.return_in_implicit_outparam(sized) is True
        sized_returned = referenced(cc.return_val(sized))
        assert sized_returned.ptr_loc == SimRegArg("r2", 8)
        assert sized_returned.main_loc.get_footprint() == {SimStackArg(off, 4) for off in (0, 4, 8, 12)}

        # Returning something that fits is unchanged.
        assert cc.return_val(SimTypeInt().with_arch(arch)) == SimRegArg("r2", 4, 4)

    def test_s390x_aggregate_args_reach_the_callsite(self):
        proj = Project(os.path.join(test_location, "s390x", "fauxware"), auto_load_libs=False)
        cc = SimCCS390X(proj.arch)
        word = SimStruct({"a": SimTypeInt()}, name="Word")
        giant = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong()}, name="Giant")
        proto = SimTypeFunction([word, giant, SimTypeInt()], SimTypeInt()).with_arch(proj.arch)
        entry = proj.loader.find_symbol("main")
        assert entry is not None

        state = proj.factory.call_state(
            entry.rebased_addr, {"a": 0x11223344}, {"a": 33, "b": 44}, 9, cc=cc, prototype=proto
        )
        evaluate = state.solver.eval
        # A four-byte aggregate occupies the low word of its register and leaves the rest alone.
        assert evaluate(state.regs.r2[31:0]) == 0x11223344
        pointer = evaluate(state.regs.r3)
        assert [evaluate(state.memory.load(pointer + 8 * i, 8, endness="Iend_BE")) for i in range(2)] == [33, 44]
        assert evaluate(state.regs.r4[31:0]) == 9

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
