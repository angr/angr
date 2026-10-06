#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.utils.go_runtime import (
    find_go_noreturn_functions,
    find_go_runtime_functions,
    has_go_hint,
    is_go_noreturn_name,
    is_go_resuming_name,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# runtime.morestack_noctxt, the function it jumps to, and runtime.morestackc. main.main is a normal Go function
# whose body sits behind the goroutine stack-growth check.
MORESTACK_NOCTXT = 0x460600
MORESTACK = 0x460580
MORESTACKC = 0x45F4C0
MAIN_MAIN = 0x4835C0
MAIN_MAIN_RESUME = 0x483690


def go_project(*path):
    return angr.Project(os.path.join(test_location, "x86_64", *(path or ("langdetect_go",))), auto_load_libs=False)


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestGoRuntimeNoReturn(unittest.TestCase):
    def test_name_table(self):
        assert is_go_noreturn_name("runtime.morestackc")
        assert is_go_noreturn_name("runtime.gopanic")
        assert is_go_noreturn_name("runtime.goPanicSliceB")
        assert is_go_noreturn_name("runtime.panicIndex")

        # these all fall through to their caller despite the suggestive names
        assert not is_go_noreturn_name("runtime.systemstack")
        assert not is_go_noreturn_name("runtime.panicCheck1")
        assert not is_go_noreturn_name("runtime.badsystemstack")
        assert not is_go_noreturn_name("runtime.mexit")
        assert not is_go_noreturn_name("runtime.throw.func1")

        # these never execute a ret, but resume their caller at the return address
        for name in ("runtime.morestack", "runtime.morestack_noctxt.abi0", "runtime.mcall"):
            assert is_go_resuming_name(name)
            assert not is_go_noreturn_name(name)

    def test_identification_by_symbol(self):
        proj = go_project()
        assert has_go_hint(proj)
        found = find_go_runtime_functions(proj)
        verdicts = found.noreturn
        assert find_go_noreturn_functions(proj) == verdicts

        def addr(name):
            sym = proj.loader.find_symbol(name)
            assert sym is not None, name
            return sym.rebased_addr

        for name in [
            "runtime.morestackc",
            "runtime.gopanic",
            "runtime.throw",
            "runtime.fatalpanic",
            "runtime.panicIndex",
            "runtime.goPanicIndex",
            "runtime.gogo.abi0",
            "runtime.exit.abi0",
        ]:
            assert addr(name) in verdicts, f"{name} was not identified"

        for name in [
            "runtime.systemstack.abi0",
            "runtime.panicCheck1",
            "runtime.badsystemstack",
            "runtime.mexit",
            "runtime.gcWriteBarrier1",
            "runtime.gcWriteBarrier2",
            "runtime.morestack.abi0",
            "runtime.morestack_noctxt.abi0",
            "runtime.mcall",
            "main.main",
        ]:
            assert addr(name) not in verdicts, f"{name} was falsely identified as non-returning"

        assert set(found.resuming) == {
            addr(n) for n in ("runtime.morestack.abi0", "runtime.morestack_noctxt.abi0", "runtime.mcall")
        }
        assert set(found.stack_growth) == {
            addr(n)
            for n in (
                "runtime.morestack.abi0",
                "runtime.morestack_noctxt.abi0",
                "runtime.morestackc.abi0",
                "runtime.morestackc",
            )
        }

    def test_identification_by_shape(self):
        # The shape-based path is the one that has to carry stripped binaries, so exercise it on its
        # own and check it against the symbols of this (unstripped) binary.
        proj = go_project()
        found = find_go_runtime_functions(proj, use_names=False)
        verdicts = found.noreturn

        # morestack is the callee of the stackguard0 preambles, morestackc of the stackguard1 ones
        assert set(found.resuming) == {MORESTACK_NOCTXT, MORESTACK}
        morestackc = proj.loader.find_symbol("runtime.morestackc.abi0").rebased_addr
        assert set(found.stack_growth) == {MORESTACK_NOCTXT, MORESTACK, morestackc, MORESTACKC}
        assert {morestackc, MORESTACKC} <= set(verdicts)
        assert MORESTACK_NOCTXT not in verdicts
        assert MORESTACK not in verdicts
        assert proj.loader.find_symbol("runtime.systemstack.abi0").rebased_addr not in verdicts
        assert proj.loader.find_symbol("runtime.gcWriteBarrier1").rebased_addr not in verdicts
        assert MAIN_MAIN not in verdicts

    def test_cfgfast_morestack_resumes_caller(self):
        proj = go_project()
        cfg = proj.analyses.CFGFast(
            regions=[(MAIN_MAIN, MAIN_MAIN + 0x240), (MORESTACK, MORESTACK + 0xA0)],
            normalize=True,
            function_prologues=False,
        )
        funcs = cfg.kb.functions

        for stub in (MORESTACK, MORESTACK_NOCTXT):
            assert funcs[stub].returning is True
            assert funcs[stub].info.get("is_go_resuming") is True
            assert funcs[stub].info.get("is_go_stack_growth") is True
            assert "is_go_noreturn" not in funcs[stub].info

        # the argument reload after the morestack call belongs to main.main, and loops back to its entry
        main = funcs[MAIN_MAIN]
        assert MAIN_MAIN_RESUME in main.block_addrs_set
        assert MAIN_MAIN_RESUME not in funcs
        resume = main.get_node(MAIN_MAIN_RESUME)
        assert [succ.addr for succ in main.graph.successors(resume)] == [MAIN_MAIN]

    def test_cfgfast_mcall_resumes_caller(self):
        # runtime.goschedIfBusy: mcall(gosched_m), then the epilogue
        proj = go_project("go", "go1.27.1", "basics_stripped")
        func_addr, mcall = 0x44EDE0, 0x485240
        cfg = proj.analyses.CFGFast(
            regions=[(func_addr, func_addr + 0x3C), (mcall, mcall + 0x5C)], normalize=True, function_prologues=False
        )
        funcs = cfg.kb.functions
        assert funcs[mcall].name == "runtime.mcall"
        assert funcs[mcall].returning is True
        func = funcs[func_addr]
        assert 0x44EE10 in func.block_addrs_set
        assert func.returning is True

    def test_morestackc_by_shape_go110(self):
        # go1.10 morestackc is systemstack(func() { throw(...) }): a call and a ret, non-returning only through the
        # closure. The stackguard1 preambles of //go:systemstack functions are what identify it.
        proj = go_project("go", "go1.10.8", "basics_stripped")
        morestackc, morestack_noctxt, morestack = 0x43E930, 0x44D2C0, 0x44D220
        found = find_go_runtime_functions(proj, use_names=False)
        assert set(found.stack_growth) == {morestackc, morestack_noctxt, morestack}
        assert set(found.resuming) == {morestack_noctxt, morestack}
        assert set(found.noreturn) == {morestackc}

        # runtime.gcmarkwb_m is //go:systemstack: its trampoline calls morestackc, and the jump back is dead
        gcmarkwb_m = 0x40DFD0
        cfg = proj.analyses.CFGFast(
            regions=[(gcmarkwb_m, gcmarkwb_m + 0x8B), (morestackc, morestackc + 0x28)],
            normalize=True,
            function_prologues=False,
        )
        funcs = cfg.kb.functions
        assert funcs[morestackc].returning is False
        assert funcs[morestackc].info.get("is_go_stack_growth") is True
        assert 0x40E051 in funcs[gcmarkwb_m].block_addrs_set
        assert 0x40E056 not in funcs[gcmarkwb_m].block_addrs_set

    def test_non_go_binary_is_untouched(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        assert not has_go_hint(proj)
        cfg = proj.analyses.CFGFast()
        assert cfg._go_noreturn_funcs == {}
        assert not cfg.kb.functions.get_key_func_addrs("go_noreturn")


if __name__ == "__main__":
    unittest.main()
