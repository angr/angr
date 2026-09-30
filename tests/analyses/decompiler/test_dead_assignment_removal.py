#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import time
import unittest
from unittest import mock

import archinfo

import angr
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Call, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel, populate_model
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

BLOCK_ADDR = 0x400000
BLOCK_KEY = (BLOCK_ADDR, None)


def _vvar(varid: int) -> VirtualVariable:
    return VirtualVariable(varid, varid, 32, VirtualVariableCategory.REGISTER, oident=16)


def _find_dead_vvars(statements):
    """
    Run AILSimplifier._find_dead_vvars over a single block made of ``statements``.
    """
    blocks = {BLOCK_KEY: Block(BLOCK_ADDR, 1, statements=statements, idx=None)}
    model = SRDAModel(None, None, archinfo.ArchAMD64())
    populate_model(model, blocks, None)

    simplifier = AILSimplifier.__new__(AILSimplifier)
    simplifier._removed_vvar_ids = set()
    simplifier._propagator_dead_vvar_ids = set()
    simplifier._remove_dead_memdefs = False
    simplifier._stackarg_offset_manager = None

    to_remove, to_keep, dead_vvar_ids = simplifier._find_dead_vvars(model, blocks, set())
    return to_remove[BLOCK_KEY], to_keep[BLOCK_KEY], dead_vvar_ids


class TestDeadAssignmentRemoval(unittest.TestCase):
    def test_dead_copy_chain_is_removed_in_linear_time(self):
        # issue #6968: deadness propagates backwards along use-def edges, so the old re-scan fixed point retired only
        # one link of a copy chain per scan. 20,000 links took minutes; the worklist takes a fraction of a second.
        chain_length = 20000
        statements = [Assignment(i, _vvar(i + 1), _vvar(i), ins_addr=BLOCK_ADDR + i) for i in range(chain_length)]
        statements.append(Return(chain_length, [], ins_addr=BLOCK_ADDR + chain_length))

        start = time.time()
        to_remove, to_keep, _ = _find_dead_vvars(statements)
        elapsed = time.time() - start

        assert to_remove == set(range(chain_length))
        assert not to_keep
        assert elapsed < 5.0, f"the dead copy chain took {elapsed:.1f}s to retire"

    def test_copy_chain_with_a_live_tail_is_kept(self):
        statements = [
            Assignment(0, _vvar(1), _vvar(0), ins_addr=BLOCK_ADDR),
            Assignment(1, _vvar(2), _vvar(1), ins_addr=BLOCK_ADDR + 1),
            Return(2, [_vvar(2)], ins_addr=BLOCK_ADDR + 2),
        ]
        to_remove, to_keep, dead_vvar_ids = _find_dead_vvars(statements)
        assert not to_remove
        assert to_keep == {0, 1}
        assert not dead_vvar_ids

    def test_uses_inside_a_call_statement_still_count(self):
        # the return value of the call is unused, so the call statement is retired, but the call itself survives, which
        # means its arguments keep the definitions they read alive
        statements = [
            Assignment(0, _vvar(1), _vvar(0), ins_addr=BLOCK_ADDR),
            Assignment(
                1,
                _vvar(2),
                Call(100, Const(101, 0x400500, 64), args=[_vvar(1)], bits=32, ins_addr=BLOCK_ADDR + 1),
                ins_addr=BLOCK_ADDR + 1,
            ),
            Return(2, [], ins_addr=BLOCK_ADDR + 2),
        ]
        to_remove, to_keep, dead_vvar_ids = _find_dead_vvars(statements)
        assert to_remove == {1}
        assert to_keep == {0}
        assert dead_vvar_ids == {2}


class TestPackerFillerDecompilation(unittest.TestCase):
    @staticmethod
    def _decompile_xchg_filler(block_count: int):
        """
        Decompile ``block_count`` blocks of 0x91 (xchg ecx, eax) filler. Returns the CPU seconds it cost and the
        decompiler.

        CPU time rather than wall clock: CI runs this suite several tests at a time on a shared runner, so wall
        clock here measures the neighbours as much as it measures the decompiler.
        """
        code = b"\x91" * (99 * block_count) + b"\xc3"

        start = time.process_time()
        proj = angr.load_shellcode(code, arch="x86", load_address=0x400000)
        # repeating_byte_run_threshold=0: CFGFast refuses to decode this filler by default (the CFG-side fix for the
        # same issue). This test targets the decompiler, so the chain has to be built anyway.
        cfg = proj.analyses.CFGFast(
            normalize=True, cross_references=False, function_starts=[0x400000], repeating_byte_run_threshold=0
        )
        dec = proj.analyses.Decompiler(proj.kb.functions[0x400000], cfg=cfg.model, preset="malware")
        elapsed = time.process_time() - start

        assert dec.clinic is not None
        assert dec.codegen is not None and dec.codegen.text is not None
        return elapsed, dec

    def test_xchg_filler_decompiles_quickly(self):
        # issue #6968: 0x91 (xchg ecx, eax) filler decodes cleanly, so CFGFast happily builds one long chain of
        # 99-instruction blocks out of it. Every instruction turns into a pair of dead virtual variables, and retiring
        # that chain used to be quadratic.
        block_count = 39
        elapsed, dec = self._decompile_xchg_filler(block_count)
        print_decompilation_result(dec)

        assert dec.clinic is not None
        assert dec.clinic._cross_insn_opt_for_large_blocks is False
        assert elapsed < 20.0, f"decompiling {block_count} blocks of filler took {elapsed:.1f}s"

    def test_xchg_filler_decompiles_in_linear_time_cross_insn_opt(self):
        # both sizes are past the 40 large blocks that turn cross-insn-opt on, so both take that path.
        #
        # issue #7054: this used to time one 5,000-block run and require it to finish inside 60 seconds. A constant
        # cannot say what the test is for. The same run costs about twice as much under the coverage job as it does
        # without instrumentation, and a run that shares a machine with its neighbours spreads about 1.5x either way,
        # so the bound was one slow shard away from firing and fired four times. What #6968 was about is the shape of
        # the cost, not its size: the fixed point that retired dead virtual variables re-scanned every definition once
        # per retired use-def link. Five times the blocks costs the worklist about five times the work and costs that
        # scan loop roughly nine to sixteen times, and a ratio of two runs on the same machine says which of the two
        # this is without having to know how fast the machine is.
        #
        # The baseline is the smaller of two 1,000-block runs. A busy machine can only ever make a run slower, and a
        # baseline that came out slow is what would let a real regression through: it divides the large run by too
        # much. Taking the smaller of two is what keeps the marginal case caught.
        first, dec_small = self._decompile_xchg_filler(1000)
        second, _ = self._decompile_xchg_filler(1000)
        small = min(first, second)
        large, dec_large = self._decompile_xchg_filler(5000)
        print_decompilation_result(dec_large)

        assert dec_small.clinic is not None
        assert dec_large.clinic is not None
        assert dec_small.clinic._cross_insn_opt_for_large_blocks is True
        assert dec_large.clinic._cross_insn_opt_for_large_blocks is True
        assert large < small * 8.0, (
            f"five times the filler cost {large / small:.1f} times the work "
            f"({small:.1f}s for 1,000 blocks, {large:.1f}s for 5,000)"
        )
        # a ratio cancels a slowdown that hits both sizes alike, so bound the large run as well. This is a backstop,
        # not the guard: it is roughly twice the worst wall clock this run has ever recorded on CI.
        assert large < 120.0, f"decompiling 5,000 blocks of filler took {large:.1f}s of CPU"


def _nested(manager, depth):
    x = VirtualVariable(manager.next_atom(), 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    expr = x
    for i in range(depth):
        expr = BinaryOp(manager.next_atom(), "Add", [expr, Const(manager.next_atom(), i, 64)], False)
    return expr


class TestBinOpCap(unittest.TestCase):
    def test_counts_the_whole_block(self):
        manager = Manager()
        y = VirtualVariable(manager.next_atom(), 2, 64, VirtualVariableCategory.REGISTER, oident=24)
        block = Block(
            0x1000,
            1,
            statements=[
                Assignment(manager.next_atom(), y, _nested(manager, 2)),
                Assignment(manager.next_atom(), y, _nested(manager, 5)),
                Assignment(manager.next_atom(), y, _nested(manager, 1)),
            ],
        )
        assert Clinic.binop_count(block) == 8

    def test_defaults(self):
        assert Clinic.CROSS_INSN_OPT_MIN_LARGE_BLOCK_COUNT == 400
        assert Clinic.CROSS_INSN_OPT_MAX_BINOP_COUNT == 3
        assert Clinic.CROSS_INSN_OPT_MIN_BLOCK_SIZE == 99
        assert Clinic.CROSS_INSN_OPT_MIN_STRIDE_REPEATS == 30


class TestRepeatingStrides(unittest.TestCase):
    def test_a_one_byte_filler(self):
        assert Clinic.repeating_stride_run(b"\x91" * 40, 16) == 40

    def test_a_three_byte_stride(self):
        data = b"\x48\x87\xc0" * 35 + b"\xc3"
        assert Clinic.repeating_stride_run(data, 16) == 35

    def test_real_code_repeats_little(self):
        data = bytes(range(7, 200)) + bytes(range(3, 90))
        assert Clinic.repeating_stride_run(data, 16) <= 2

    def test_empty_and_short(self):
        assert Clinic.repeating_stride_run(b"", 16) == 0
        assert Clinic.repeating_stride_run(b"\x90", 16) == 1


class TestLiftingBookkeeping(unittest.TestCase):
    def setUp(self):
        self._saved = (
            Clinic.CROSS_INSN_OPT_MIN_LARGE_BLOCK_COUNT,
            Clinic.CROSS_INSN_OPT_MIN_BLOCK_SIZE,
            Clinic.CROSS_INSN_OPT_MAX_BINOP_COUNT,
            Clinic.CROSS_INSN_OPT_MIN_STRIDE_REPEATS,
        )
        Clinic.CROSS_INSN_OPT_MIN_LARGE_BLOCK_COUNT = 1
        Clinic.CROSS_INSN_OPT_MIN_BLOCK_SIZE = 1
        Clinic.CROSS_INSN_OPT_MAX_BINOP_COUNT = 1000
        Clinic.CROSS_INSN_OPT_MIN_STRIDE_REPEATS = 1

    def tearDown(self):
        (
            Clinic.CROSS_INSN_OPT_MIN_LARGE_BLOCK_COUNT,
            Clinic.CROSS_INSN_OPT_MIN_BLOCK_SIZE,
            Clinic.CROSS_INSN_OPT_MAX_BINOP_COUNT,
            Clinic.CROSS_INSN_OPT_MIN_STRIDE_REPEATS,
        ) = self._saved

    def test_every_block_is_recorded_and_the_cap_is_honoured(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "cat_gcc17.0.0_O2"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions[0x4023C0]  # main
        victim = max((n for n in func.graph.nodes() if n.size > 0), key=lambda n: n.size)
        real_count = Clinic.binop_count

        def count(block):
            return 10_000 if block.addr == victim.addr else real_count(block)

        with mock.patch.object(Clinic, "binop_count", staticmethod(count)):
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.clinic is not None
        clinic = dec.clinic
        assert clinic._cross_insn_opt_for_large_blocks is True

        folded = clinic._block_cross_insn_opt
        sizes = {(n.addr, n.size) for n in func.graph.nodes() if n.size > 0}
        assert (victim.addr, victim.size) not in folded, "the block over the cap was lifted plain"
        assert folded == sizes - {(victim.addr, victim.size)}, "every other block stayed folded"
        for addr, size in sizes:
            assert clinic.block_lifted_with_cross_insn_opt(addr, size) == ((addr, size) in folded)
        assert clinic.block_lifted_with_cross_insn_opt(0xDEAD, 16) is False, "an unknown block is lifted plain"

    def test_real_code_is_never_folded_under_the_stride_gate(self):
        Clinic.CROSS_INSN_OPT_MIN_STRIDE_REPEATS = 30
        proj = angr.Project(os.path.join(test_location, "x86_64", "cat_gcc17.0.0_O2"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions[0x4023C0]  # main
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.clinic is not None
        assert dec.clinic._cross_insn_opt_for_large_blocks is True, "the function-level heuristic did engage"
        assert not dec.clinic._block_cross_insn_opt, "but no block of real code repeats a stride"


if __name__ == "__main__":
    unittest.main()
