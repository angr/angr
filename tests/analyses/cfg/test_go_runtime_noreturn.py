#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.utils.go_runtime import find_go_noreturn_functions, has_go_hint, is_go_noreturn_name
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# runtime.morestack_noctxt and the function that jumps to it. main.main is a normal Go function whose
# body sits behind the goroutine stack-growth check.
MORESTACK_NOCTXT = 0x460600
MORESTACK = 0x460580
MAIN_MAIN = 0x4835C0
MAIN_MAIN_RESUME = 0x483690


def go_project():
    return angr.Project(os.path.join(test_location, "x86_64", "langdetect_go"), auto_load_libs=False)


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestGoRuntimeNoReturn(unittest.TestCase):
    def test_name_table(self):
        assert is_go_noreturn_name("runtime.morestack")
        assert is_go_noreturn_name("runtime.morestack_noctxt.abi0")
        assert is_go_noreturn_name("runtime.gopanic")
        assert is_go_noreturn_name("runtime.goPanicSliceB")
        assert is_go_noreturn_name("runtime.panicIndex")

        # these all fall through to their caller despite the suggestive names
        assert not is_go_noreturn_name("runtime.systemstack")
        assert not is_go_noreturn_name("runtime.panicCheck1")
        assert not is_go_noreturn_name("runtime.badsystemstack")
        assert not is_go_noreturn_name("runtime.mexit")
        assert not is_go_noreturn_name("runtime.throw.func1")

    def test_identification_by_symbol(self):
        proj = go_project()
        assert has_go_hint(proj)
        verdicts = find_go_noreturn_functions(proj)

        def addr(name):
            sym = proj.loader.find_symbol(name)
            assert sym is not None, name
            return sym.rebased_addr

        for name in [
            "runtime.morestack.abi0",
            "runtime.morestack_noctxt.abi0",
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
            "main.main",
        ]:
            assert addr(name) not in verdicts, f"{name} was falsely identified as non-returning"

    def test_identification_by_shape(self):
        # The shape-based path is the one that has to carry stripped binaries, so exercise it on its
        # own and check it against the symbols of this (unstripped) binary.
        proj = go_project()
        verdicts = find_go_noreturn_functions(proj, use_names=False)

        assert MORESTACK_NOCTXT in verdicts
        assert MORESTACK in verdicts
        assert proj.loader.find_symbol("runtime.systemstack.abi0").rebased_addr not in verdicts
        assert proj.loader.find_symbol("runtime.gcWriteBarrier1").rebased_addr not in verdicts
        assert MAIN_MAIN not in verdicts

    def test_cfgfast_marks_go_runtime_noreturn(self):
        proj = go_project()
        cfg = proj.analyses.CFGFast(
            regions=[(MAIN_MAIN, MAIN_MAIN + 0x240), (MORESTACK, MORESTACK + 0xA0)],
            normalize=True,
            function_prologues=False,
        )
        funcs = cfg.kb.functions

        for stub in (MORESTACK, MORESTACK_NOCTXT):
            assert funcs[stub].returning is False
            assert funcs[stub].info.get("is_go_noreturn") is True

        # the stack-growth stub resumes main.main at its entry point, which angr otherwise records as
        # a tail call from main.main to itself
        main = funcs[MAIN_MAIN]
        assert not any(dst.addr == MAIN_MAIN for _, dst in main.transition_graph.edges())
        assert MAIN_MAIN_RESUME not in main.block_addrs_set

    def test_non_go_binary_is_untouched(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        assert not has_go_hint(proj)
        cfg = proj.analyses.CFGFast()
        assert cfg._go_noreturn_funcs == {}
        assert not cfg.kb.functions.get_key_func_addrs("go_noreturn")


if __name__ == "__main__":
    unittest.main()
