# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import time
import unittest

import angr
from angr.analyses.decompiler.decompilation_options import (
    DEFAULT_MAX_AIL_STATEMENTS,
    DEFAULT_MAX_FUNCTION_BLOCKS,
    PARAM_TO_OPTION,
)
from angr.errors import AngrDecompilationComplexityError

FUNC_ADDR = 0x400000


def oversized_project(n_blocks: int):
    """
    Build a function of ``n_blocks + 1`` blocks out of ``xchg ecx, eax`` filler. pyvex caps an IRSB at 99
    instructions, so linear disassembly of a long run of decodable filler yields one block every 99
    instructions -- the shape of the packer filler in GitHub issue #6968.
    """
    proj = angr.load_shellcode(b"\x91" * (99 * n_blocks) + b"\xc3", arch="x86", load_address=FUNC_ADDR)
    # repeating_byte_run_threshold=0: CFGFast refuses to decode this filler by default (the CFG-side fix for the same
    # issue). These tests target the decompiler's guard, so the oversized function has to be built anyway.
    proj.analyses.CFGFast(
        normalize=True, cross_references=False, function_starts=[FUNC_ADDR], repeating_byte_run_threshold=0
    )
    return proj


def decompile(proj, func, **kwargs):
    """Decompile with resilience on; ``fail_fast`` defaults to True while running under pytest."""
    return proj.analyses[angr.analyses.Decompiler].prep(fail_fast=False)(func, **kwargs)


class TestDecompilerComplexityGuard(unittest.TestCase):
    def test_block_limit_trips_fast_with_a_structured_error(self):
        proj = oversized_project(200)
        func = proj.kb.functions[FUNC_ADDR]
        assert len(func.block_addrs_set) == 201

        t0 = time.time()
        dec = decompile(proj, func, options=[("max_function_blocks", 4)])
        elapsed = time.time() - t0

        # the whole point of the guard: give up before any of the expensive work happens. Decompiling this
        # function for real takes well over a minute.
        assert elapsed < 1.0
        assert dec.codegen is None

        err = dec.complexity_error
        assert err is not None
        assert err.limit_name == "max_function_blocks"
        assert err.limit == 4
        assert err.actual == 201
        assert "max_function_blocks" in str(err)
        assert "201" in str(err)

        # the failure is also where callers of a cached decompilation look for it
        cached_errors = proj.kb.decompilations[(FUNC_ADDR, "pseudocode")].errors
        assert any("max_function_blocks" in e for e in cached_errors)

    def test_block_limit_raises_under_fail_fast(self):
        proj = oversized_project(200)
        func = proj.kb.functions[FUNC_ADDR]

        with self.assertRaises(AngrDecompilationComplexityError) as cm:
            proj.analyses[angr.analyses.Decompiler].prep(fail_fast=True)(func, options=[("max_function_blocks", 4)])
        assert cm.exception.limit_name == "max_function_blocks"
        assert cm.exception.actual == 201

    def test_block_limit_disabled_decompiles_the_same_function(self):
        proj = oversized_project(12)
        func = proj.kb.functions[FUNC_ADDR]
        assert len(func.block_addrs_set) == 13

        assert decompile(proj, func, options=[("max_function_blocks", 4)]).complexity_error is not None

        dec = decompile(proj, func, options=[("max_function_blocks", 0)])
        assert dec.complexity_error is None
        assert dec.codegen is not None
        assert dec.codegen.text

    def test_ail_statement_limit_trips_independently(self):
        proj = oversized_project(12)
        func = proj.kb.functions[FUNC_ADDR]

        # the block limit is enabled but far out of reach; only the statement limit can fire here
        dec = decompile(proj, func, options=[("max_function_blocks", 100_000), ("max_ail_statements", 100)])
        assert dec.codegen is None

        err = dec.complexity_error
        assert err is not None
        assert err.limit_name == "max_ail_statements"
        assert err.limit == 100
        assert err.actual > 100
        assert "max_ail_statements" in str(err)
        assert str(err.actual) in str(err)

    def test_options_round_trip(self):
        blocks_opt = PARAM_TO_OPTION["max_function_blocks"]
        stmts_opt = PARAM_TO_OPTION["max_ail_statements"]
        assert (blocks_opt.cls, blocks_opt.value_type, blocks_opt.default_value) == (
            "decompiler",
            int,
            DEFAULT_MAX_FUNCTION_BLOCKS,
        )
        assert (stmts_opt.cls, stmts_opt.value_type, stmts_opt.default_value) == (
            "clinic",
            int,
            DEFAULT_MAX_AIL_STATEMENTS,
        )
        # a size limit decides whether a result exists at all, so a change must invalidate cached output
        assert blocks_opt.clears_cache and stmts_opt.clears_cache
        assert blocks_opt.value_range is not None and stmts_opt.value_range is not None

        proj = oversized_project(3)
        func = proj.kb.functions[FUNC_ADDR]

        # passing the DecompilationOption objects themselves works just like passing param names
        dec = decompile(proj, func, options=[(blocks_opt, 0), (stmts_opt, 987_654)])
        assert dec.codegen is not None
        # the clinic-class option reached Clinic
        assert dec.clinic._max_ail_statements == 987_654

        dec = decompile(proj, func, options=[(blocks_opt, 1)])
        assert dec.complexity_error is not None
        assert dec.complexity_error.limit == 1

    def test_defaults_do_not_trip_on_a_normal_function(self):
        proj = oversized_project(3)
        func = proj.kb.functions[FUNC_ADDR]

        dec = decompile(proj, func)
        assert dec.complexity_error is None
        assert dec.codegen is not None


if __name__ == "__main__":
    unittest.main()
