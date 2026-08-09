#!/usr/bin/env python3
# pylint:disable=no-self-use
"""Tests for Go's ABIInternal calling convention (SimCCGoAMD64) and its automatic selection."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.calling_conventions import (
    SimCCGoAMD64,
    SimCCGoAMD64ABI0,
    SimCCSystemVAMD64,
    SimRegArg,
    SimStackArg,
    default_cc,
)
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
from tests.common import bin_location

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


class TestGoCallingConventionSelection(unittest.TestCase):
    """Selecting the Go ABI for Go binaries without perturbing anything else."""

    def test_default_cc_by_language(self):
        assert default_cc("AMD64", "Linux", language="go") is SimCCGoAMD64
        assert default_cc("AMD64", "Win32", language="go") is SimCCGoAMD64
        # other languages and the language-less lookup are untouched
        assert default_cc("AMD64", "Linux") is SimCCSystemVAMD64
        assert default_cc("AMD64", "Linux", language="rust") is SimCCSystemVAMD64
        assert default_cc("AMD64", "Linux", language="c") is SimCCSystemVAMD64
        # architectures without a Go ABI fall back to the platform default
        assert default_cc("ARMEL", "Linux", language="go") is default_cc("ARMEL", "Linux")
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


if __name__ == "__main__":
    unittest.main()
