#!/usr/bin/env python3
# pylint:disable=no-self-use
"""Tests for Go's ABIInternal calling convention (SimCCGoAMD64) and its automatic selection."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo
import cle

import angr
from angr.calling_conventions import (
    GO_ABI0_CC,
    SimCCGoAArch64,
    SimCCGoAArch64ABI0,
    SimCCGoAMD64,
    SimCCGoAMD64ABI0,
    SimCCGoARM,
    SimCCGoX86,
    SimCCSystemVAMD64,
    SimRegArg,
    SimStackArg,
    default_cc,
    default_cc_for_project,
    go_cc_class,
)
from angr.go import GO_FLAVOR
from angr.sim_type import (
    SimStruct,
    SimTypeBottom,
    SimTypeChar,
    SimTypeDouble,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
)
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")
GO_BINARY = os.path.join(test_location, "x86_64", "langdetect_go")

ARCH = archinfo.ArchAMD64()


def _go_string():
    return SimStruct({"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeLong()}, name="string").with_arch(ARCH)


def _go_slice():
    return SimStruct(
        {"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeLong(), "cap": SimTypeLong()}, name="slice"
    ).with_arch(ARCH)


def _reg_names(loc):
    """The register names touched by an argument location, or None if any part of it lives on the stack."""
    footprint = list(loc.get_footprint())
    if any(isinstance(f, SimStackArg) for f in footprint):
        return None
    return {f.reg_name for f in footprint if isinstance(f, SimRegArg)}


def _stack_offsets(loc):
    """The stack offsets of an argument location that must live entirely on the stack."""
    assert loc is not None
    footprint = list(loc.get_footprint())
    assert all(isinstance(f, SimStackArg) for f in footprint), footprint
    return {f.stack_offset for f in footprint if isinstance(f, SimStackArg)}


class TestGoCallingConventionSelection(unittest.TestCase):
    """Selecting the Go ABI for Go binaries without perturbing anything else."""

    def test_default_cc_by_language(self):
        assert default_cc("AMD64", "Linux", language="go") is SimCCGoAMD64
        assert default_cc("AMD64", "Win32", language="go") is SimCCGoAMD64
        # other languages and the language-less lookup are untouched
        assert default_cc("AMD64", "Linux") is SimCCSystemVAMD64
        assert default_cc("AMD64", "Linux", language="rust") is SimCCSystemVAMD64
        assert default_cc("AMD64", "Linux", language="c") is SimCCSystemVAMD64
        assert default_cc("AARCH64", "Linux", language="go") is SimCCGoAArch64
        # architectures without a Go ABI fall back to the platform default
        assert default_cc("MIPS32", "Linux", language="go") is default_cc("MIPS32", "Linux")
        # syscalls never use the Go ABI
        assert default_cc("AMD64", "Linux", language="go", syscall=True) is default_cc("AMD64", "Linux", syscall=True)

    def test_go_binary_gets_go_cc(self):
        proj = angr.Project(GO_BINARY, auto_load_libs=False)
        assert proj.languages() == ["go"]
        assert proj.is_go_binary
        assert not proj.is_rust_binary
        assert isinstance(proj.factory.cc(), SimCCGoAMD64)

    def test_non_go_binary_unaffected(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        assert not proj.is_go_binary
        assert isinstance(proj.factory.cc(), SimCCSystemVAMD64)
        assert not isinstance(proj.factory.cc(), SimCCGoAMD64)

    def test_low_confidence_detection_does_not_switch_abi(self):
        # LanguageDetector calls this C object file Go on the strength of a single "main.end" symbol,
        # which is nowhere near enough to reinterpret every argument and return value in it
        proj = angr.Project(
            os.path.join(test_location, "x86_64", "decompiler", "call_expr_folding_load_order.o"),
            auto_load_libs=False,
        )
        assert proj.languages() == ["go"]
        assert proj.language_confidence != "high"
        assert not proj.language_is_certain
        assert not proj.is_go_binary
        assert isinstance(proj.factory.cc(), SimCCSystemVAMD64)


class TestGoArgumentLayout(unittest.TestCase):
    """Go's register assignment algorithm."""

    def setUp(self):
        self.cc = SimCCGoAMD64(ARCH)

    def test_integer_register_sequence(self):
        proto = SimTypeFunction([SimTypeLong()] * 9, SimTypeBottom()).with_arch(ARCH)
        locs = self.cc.arg_locs(proto)
        assert [loc.reg_name for loc in locs] == ["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"]

    def test_tenth_integer_spills_to_stack(self):
        proto = SimTypeFunction([SimTypeLong()] * 10, SimTypeBottom()).with_arch(ARCH)
        locs = self.cc.arg_locs(proto)
        assert isinstance(locs[9], SimStackArg)
        # the return address sits at offset 0, so the first stack argument is at offset 8
        assert locs[9].stack_offset == 8

    def test_float_register_sequence(self):
        proto = SimTypeFunction([SimTypeDouble()] * 15, SimTypeBottom()).with_arch(ARCH)
        locs = self.cc.arg_locs(proto)
        assert [loc.reg_name for loc in locs] == [f"xmm{i}" for i in range(15)]

    def test_int_and_float_use_independent_sequences(self):
        proto = SimTypeFunction([SimTypeLong(), SimTypeDouble(), SimTypeLong(), SimTypeFloat()], SimTypeBottom())
        locs = self.cc.arg_locs(proto.with_arch(ARCH))
        assert [loc.reg_name for loc in locs] == ["rax", "xmm0", "rbx", "xmm1"]

    def test_r14_and_x15_are_never_arguments(self):
        # r14 pins the current goroutine and x15 is a zero register
        assert "r14" not in self.cc.ARG_REGS
        assert "xmm15" not in self.cc.FP_ARG_REGS
        # rdx carries the closure context pointer, not an argument
        assert "rdx" not in self.cc.ARG_REGS
        offsets = SimCCGoAMD64.arg_reg_offsets(ARCH)
        for reg in ("r14", "xmm15", "rdx", "r12", "r13"):
            base, _ = ARCH.registers[reg]
            assert base not in offsets, f"{reg} must not be an argument register"

    def test_struct_is_decomposed_per_field_not_per_eightbyte(self):
        # this is the key difference from System V: two int32 fields share one eightbyte but Go still
        # gives each its own register
        two_i32 = SimStruct({"a": SimTypeInt(), "b": SimTypeInt()}, name="two_i32").with_arch(ARCH)
        (loc,) = self.cc.arg_locs(SimTypeFunction([two_i32], SimTypeBottom()).with_arch(ARCH))
        assert _reg_names(loc) == {"rax", "rbx"}

    def test_string_takes_two_registers(self):
        proto = SimTypeFunction([_go_string(), _go_string()], SimTypeChar()).with_arch(ARCH)
        locs = self.cc.arg_locs(proto)
        assert _reg_names(locs[0]) == {"rax", "rbx"}
        assert _reg_names(locs[1]) == {"rcx", "rdi"}

    def test_oversized_aggregate_rolls_back_to_stack(self):
        # three slices use all nine integer registers; the fourth cannot fit, so the whole value goes
        # on the stack rather than being split across registers and memory
        proto = SimTypeFunction([_go_slice()] * 4, SimTypeBottom()).with_arch(ARCH)
        locs = self.cc.arg_locs(proto)
        assert _reg_names(locs[0]) == {"rax", "rbx", "rcx"}
        assert _reg_names(locs[2]) == {"r9", "r10", "r11"}
        assert _reg_names(locs[3]) is None
        assert {f.stack_offset for f in locs[3].get_footprint()} == {8, 16, 24}

    def test_caller_reserves_spill_space_for_register_arguments(self):
        proto = SimTypeFunction([SimTypeLong()] * 3, SimTypeBottom()).with_arch(ARCH)
        locs = self.cc.arg_locs(proto)
        # no stack arguments, but the caller still reserves one word of spill space per register argument
        assert self.cc.stack_space(locs) >= 3 * 8


class TestGoReturnValues(unittest.TestCase):
    """Results are assigned from the same register sequences as arguments."""

    def setUp(self):
        self.cc = SimCCGoAMD64(ARCH)

    def test_scalar_results(self):
        assert self.cc.return_val(SimTypeLong().with_arch(ARCH)).reg_name == "rax"
        assert self.cc.return_val(SimTypeDouble().with_arch(ARCH)).reg_name == "xmm0"
        assert self.cc.return_val(SimTypeBottom().with_arch(ARCH)) is None

    def test_results_restart_at_the_first_register(self):
        # unlike System V, a result does not continue where the arguments left off
        assert SimRegArg("rax", 8) == self.cc.RETURN_VAL
        assert SimRegArg("rbx", 8) == self.cc.OVERFLOW_RETURN_VAL

    def test_multi_value_return_uses_consecutive_registers(self):
        # func() string  ->  (ptr, len) in rax, rbx
        assert _reg_names(self.cc.return_val(_go_string())) == {"rax", "rbx"}
        # func() (int, error)  ->  int in rax, the interface's two words in rbx, rcx
        iface = SimStruct(
            {"tab": SimTypePointer(SimTypeChar()), "data": SimTypePointer(SimTypeChar())}, name="iface"
        ).with_arch(ARCH)
        ret = SimStruct({"r0": SimTypeLong(), "r1": iface}, name="ret").with_arch(ARCH)
        assert _reg_names(self.cc.return_val(ret)) == {"rax", "rbx", "rcx"}


class TestGoABI0(unittest.TestCase):
    """Go's legacy all-stack ABI0."""

    def test_everything_goes_on_the_stack(self):
        cc = SimCCGoAMD64ABI0(ARCH)
        proto = SimTypeFunction([SimTypeLong(), _go_string()], SimTypeBottom()).with_arch(ARCH)
        locs = cc.arg_locs(proto)
        assert all(_reg_names(loc) is None for loc in locs)
        assert locs[0].stack_offset == 8
        assert {f.stack_offset for f in locs[1].get_footprint()} == {16, 24}
        assert _reg_names(cc.return_val(SimTypeLong().with_arch(ARCH))) is None


class TestGoCallingConventionRecovery(unittest.TestCase):
    """End-to-end recovery against a real Go binary."""

    def _scoped_project(self, start, end):
        proj = angr.Project(GO_BINARY, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(regions=[(start, end)], normalize=True)
        return proj, cfg

    def test_fibonacci_takes_one_integer_argument_in_rax(self):
        # main.fibonacci is `func fibonacci(n int) int`: one argument in rax, one result in rax
        start, end = 0x483540, 0x4835A4
        proj, cfg = self._scoped_project(start, end)
        func = proj.kb.functions[start]
        assert func.name == "main.fibonacci"
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, analyze_callsites=True, workers=0)

        assert isinstance(func.calling_convention, SimCCGoAMD64)
        assert func.prototype is not None
        assert len(func.prototype.args) == 1
        (arg_loc,) = func.calling_convention.arg_locs(func.prototype)
        assert isinstance(arg_loc, SimRegArg)
        assert arg_loc.reg_name == "rax"
        assert func.calling_convention.return_val(func.prototype.returnty).reg_name == "rax"

    def test_r14_is_not_recovered_as_an_argument(self):
        start, end = 0x483540, 0x4835A4
        proj, cfg = self._scoped_project(start, end)
        func = proj.kb.functions[start]
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, analyze_callsites=True, workers=0)
        # the function reads r14 (the goroutine pointer) in its stack-growth check; it must not become
        # an argument
        reg_names = {
            loc.reg_name
            for loc in func.calling_convention.arg_locs(func.prototype)
            for loc in loc.get_footprint()
            if isinstance(loc, SimRegArg)
        }
        assert "r14" not in reg_names

    def test_abi0_function_uses_the_stack_convention(self):
        # internal/cpu.cpuid.abi0 reads its arguments from 8(rsp) and 12(rsp)
        start, end = 0x4028A0, 0x4028BB
        proj, cfg = self._scoped_project(start, end)
        func = proj.kb.functions[start]
        assert func.name == "internal/cpu.cpuid.abi0"
        proj.analyses.CompleteCallingConventions(cfg=cfg.model, analyze_callsites=True, workers=0)

        assert isinstance(func.calling_convention, SimCCGoAMD64ABI0)
        assert func.prototype is not None
        locs = func.calling_convention.arg_locs(func.prototype)
        assert locs, "expected at least one stack argument"
        assert all(_reg_names(loc) is None for loc in locs)


class TestGoX86AndAArch64(unittest.TestCase):
    """Go ABI0 on 386 and the register ABI on AArch64."""

    def test_x86_abi0(self):
        # 386 only has the all-stack ABI0: arguments from 4(SP), results after them at the next word boundary
        assert default_cc("X86", "Linux", language="go") is SimCCGoX86
        assert GO_ABI0_CC["X86"] is SimCCGoX86
        arch = archinfo.ArchX86()
        string = SimStruct({"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeInt()}, name="string")
        error = SimStruct({"tab": SimTypePointer(SimTypeChar()), "data": SimTypePointer(SimTypeChar())}, name="error")
        proto = SimTypeFunction([SimTypeInt(), string], SimStruct({"s": string, "err": error}, name="ret")).with_arch(
            arch
        )
        assert isinstance(proto, SimTypeFunction)
        cc = SimCCGoX86.for_prototype(arch, proto)
        locs = cc.arg_locs(proto)
        assert all(_reg_names(loc) is None for loc in locs)
        assert isinstance(locs[0], SimStackArg) and locs[0].stack_offset == 4
        assert _stack_offsets(locs[1]) == {8, 12}
        assert cc.args_size == 12
        assert _stack_offsets(cc.return_val(proto.returnty)) == {16, 20, 24, 28}
        # without the prototype the results are assumed to start right above the return address
        assert _stack_offsets(SimCCGoX86(arch).return_val(string.with_arch(arch))) == {4, 8}

    def test_aarch64(self):
        # Go's register ABI on arm64: R0-R15 / F0-F15, results restarting at R0, g in R28
        proj = angr.Project(os.path.join(test_location, "aarch64", "go", "go1.22.5", "basics"), auto_load_libs=False)
        assert proj.is_go_binary
        assert isinstance(proj.factory.cc(), SimCCGoAArch64)

        arch = archinfo.ArchAArch64()
        cc = SimCCGoAArch64(arch)
        string = SimStruct({"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeLong()}, name="string").with_arch(arch)
        locs = cc.arg_locs(SimTypeFunction([SimTypeLong(), string, SimTypeDouble()], SimTypeLong()).with_arch(arch))
        assert _reg_names(locs[0]) == {"x0"}
        assert _reg_names(locs[1]) == {"x1", "x2"}
        assert _reg_names(locs[2]) == {"d0"}
        ret = SimStruct({"a": SimTypeLong(), "b": SimTypeLong()}, name="pair").with_arch(arch)
        assert _reg_names(cc.return_val(ret)) == {"x0", "x1"}
        assert "x28" not in cc.ARG_REGS and "x26" not in cc.ARG_REGS and "x27" not in cc.ARG_REGS
        assert isinstance(cc.RETURN_ADDR, SimRegArg) and cc.RETURN_ADDR.reg_name == "lr"
        proto = SimTypeFunction([SimTypeLong(), SimTypeLong()], SimTypeLong()).with_arch(arch)
        assert all(_reg_names(loc) is None for loc in SimCCGoAArch64ABI0(arch).arg_locs(proto))


class TestGoARMABI0(unittest.TestCase):
    """32-bit arm only has the all-stack ABI0: arguments from 4(R13), above the saved-LR slot, results after them."""

    def test_selected_for_go_on_arm(self):
        for arch in ("ARMEL", "ARMHF"):
            assert default_cc(arch, "Linux", language="go") is SimCCGoARM
            assert GO_ABI0_CC[arch] is SimCCGoARM
        # C binaries keep AAPCS
        assert default_cc("ARMEL", "Linux") is not SimCCGoARM

    def test_args_then_results_on_the_stack(self):
        arch = archinfo.ArchARMEL()
        string = SimStruct({"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeInt()}, name="string")
        error = SimStruct({"tab": SimTypePointer(SimTypeChar()), "data": SimTypePointer(SimTypeChar())}, name="error")
        proto = SimTypeFunction([string], SimStruct({"n": SimTypeInt(), "err": error}, name="ret")).with_arch(arch)
        cc = SimCCGoARM.for_prototype(arch, proto)
        (loc,) = cc.arg_locs(proto)
        assert {f.stack_offset for f in loc.get_footprint()} == {4, 8}
        assert cc.args_size == 8
        assert {f.stack_offset for f in cc.return_val(proto.returnty).get_footprint()} == {12, 16, 20}
        assert cc.return_addr == SimRegArg("lr", 4)
        # BL pushes nothing: stack arguments from 4(R13) still match
        assert SimCCGoARM._match(arch, [SimStackArg(4, 4), SimStackArg(8, 4)], 0)


def _exact(version):
    """A Go release range pinned to one release."""
    return version, version


class TestGoCallingConventionByVersion(unittest.TestCase):
    """The register ABI arrived in go1.17 on amd64 and go1.18 on arm64; older binaries use ABI0 throughout."""

    def test_version_boundaries(self):
        assert go_cc_class("AMD64", _exact((1, 16))) is SimCCGoAMD64ABI0
        assert go_cc_class("AMD64", _exact((1, 17))) is SimCCGoAMD64
        assert go_cc_class("AMD64", _exact((1, 17)), goos="linux") is SimCCGoAMD64
        # go1.17 left the BSDs on ABI0; go1.18 switched every GOOS
        assert go_cc_class("AMD64", _exact((1, 17)), goos="freebsd") is SimCCGoAMD64ABI0
        assert go_cc_class("AMD64", _exact((1, 18)), goos="freebsd") is SimCCGoAMD64
        assert go_cc_class("AARCH64", _exact((1, 17))) is SimCCGoAArch64ABI0
        assert go_cc_class("AARCH64", _exact((1, 18))) is SimCCGoAArch64
        # unknown release: the register ABI
        assert go_cc_class("AMD64") is SimCCGoAMD64
        assert go_cc_class("AARCH64") is SimCCGoAArch64
        # 386 and arm never got the register ABI
        for arch, cc in (("X86", SimCCGoX86), ("ARMEL", SimCCGoARM), ("ARMHF", SimCCGoARM)):
            assert go_cc_class(arch) is cc
            assert go_cc_class(arch, _exact((1, 27))) is cc
        # ".abi0" symbols are ABI0 whatever the release
        assert go_cc_class("AMD64", _exact((1, 22)), abi0=True) is SimCCGoAMD64ABI0
        assert go_cc_class("MIPS32") is None

    def test_pclntab_layout_ranges(self):
        # layouts before go1.16: ABI0 on both
        assert go_cc_class("AMD64", ((1, 12), (1, 15))) is SimCCGoAMD64ABI0
        assert go_cc_class("AARCH64", ((1, 2), (1, 9))) is SimCCGoAArch64ABI0
        # the go1.16 layout (1.16-1.17) predates arm64's register ABI but straddles amd64's: keep the default there
        assert go_cc_class("AARCH64", ((1, 16), (1, 17))) is SimCCGoAArch64ABI0
        assert go_cc_class("AMD64", ((1, 16), (1, 17))) is SimCCGoAMD64
        assert go_cc_class("AARCH64", ((1, 18), (1, 19))) is SimCCGoAArch64
        assert go_cc_class("AMD64", ((1, 20), None)) is SimCCGoAMD64

    def test_fixtures(self):
        cases = [
            (("x86_64", "langdetect_go_go1.10.8"), (1, 10), SimCCGoAMD64ABI0),
            (("x86_64", "langdetect_go_go1.15.15"), (1, 15), SimCCGoAMD64ABI0),
            (("x86_64", "langdetect_go_go1.15.15.macho"), (1, 15), SimCCGoAMD64ABI0),
            (("x86_64", "langdetect_go_go1.16.15"), (1, 16), SimCCGoAMD64ABI0),
            (("x86_64", "langdetect_go"), (1, 22), SimCCGoAMD64),
            (("x86_64", "go", "go1.4.3", "basics"), (1, 4), SimCCGoAMD64ABI0),
            (("x86_64", "go", "go1.9.7", "basics"), (1, 9), SimCCGoAMD64ABI0),
            (("x86_64", "go", "go1.10.8", "basics"), (1, 10), SimCCGoAMD64ABI0),
            (("x86_64", "go", "go1.15.15", "basics"), (1, 15), SimCCGoAMD64ABI0),
            (("x86_64", "go", "go1.16.15", "basics"), (1, 16), SimCCGoAMD64ABI0),
            (("x86_64", "go", "go1.22.5", "basics"), (1, 22), SimCCGoAMD64),
            (("aarch64", "langdetect_go_go1.17.13"), (1, 17), SimCCGoAArch64ABI0),
            (("aarch64", "windows", "langdetect_go_go1.17.13.exe"), (1, 17), SimCCGoAArch64ABI0),
            (("aarch64", "langdetect_go_go1.18.10"), (1, 18), SimCCGoAArch64),
            (("i386", "langdetect_go_go1.17.13"), (1, 17), SimCCGoX86),
            (("armel", "langdetect_go_go1.17.13"), (1, 17), SimCCGoARM),
        ]
        for path, version, cc in cases:
            with self.subTest(binary=os.path.join(*path)):
                proj = angr.Project(os.path.join(test_location, *path), auto_load_libs=False)
                assert proj.is_go_binary
                assert proj.go_version_range == (version, version)
                assert default_cc_for_project(proj) is cc
                assert type(proj.factory.cc()) is cc

    def test_printfloat_takes_one_float_from_the_stack_on_arm64_go117(self):
        path = os.path.join(test_location, "aarch64", "langdetect_go_go1.17.13")
        addr = cle.Loader(path, auto_load_libs=False).find_symbol("runtime.printfloat").rebased_addr
        proj, cfg = load_project_with_scoped_cfg(path, addr, call_tree_depth=1, window=0x400)
        func = proj.kb.functions[addr]
        assert isinstance(func.calling_convention, SimCCGoAArch64ABI0)
        # the register ABI read 16 integer registers and d0 as arguments
        assert func.prototype is not None and len(func.prototype.args) == 1
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, flavor="go", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text
        proto = func.get_prototype(GO_FLAVOR)
        assert proto is not None and len(proto.args) == 1
        assert isinstance(proto.args[0], SimTypeFloat) and proto.args[0].size == 64
        assert "func runtime.printfloat(v float64) {" in dec.codegen.text

    def test_results_follow_arguments_on_amd64_go116(self):
        path = os.path.join(test_location, "x86_64", "go", "go1.16.15", "basics")
        addr = cle.Loader(path, auto_load_libs=False).find_symbol("main.add").rebased_addr
        proj, cfg = load_project_with_scoped_cfg(path, addr, call_tree_depth=1, window=0x100)
        func = proj.kb.functions[addr]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, flavor="go", fail_fast=True)
        assert dec.codegen is not None
        assert isinstance(func.calling_convention, SimCCGoAMD64ABI0)
        # func add(a, b int) int: a at 8(SP), b at 16(SP), the result at 24(SP)
        proto = func.get_prototype(GO_FLAVOR)
        args = func.calling_convention.arg_locs(proto)
        assert [loc.stack_offset for loc in args] == [8, 16]
        assert func.calling_convention.return_val(proto.returnty).stack_offset == 24
        text = dec.codegen.text
        assert "func main.add(a int, b int) int {" in text
        assert "return b + a" in text or "return a + b" in text


if __name__ == "__main__":
    unittest.main()
