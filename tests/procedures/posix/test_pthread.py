#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.posix"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# Two -O2 blocks of the committed `cat` fixture. The first uses aligned SSE
# loads, which VEX guards with an explicit alignment check that exits with
# Ijk_SigSEGV -- with an unconstrained pointer those guards are satisfiable, so
# the block's fault successors sort *before* its real one. Feeding the first of
# them back into the engine (to execute the next block) reaches the failure
# engine, which refuses to execute Ijk_Sig* and raised AngrExitError all the way
# out of CFGFast.
CAT_SSE_BLOCK = 0x404870
CAT_NEXT_BLOCK = 0x4049E0


class TestPthreadCreateStaticExits(unittest.TestCase):
    """pthread_create.static_exits speculatively executes the blocks CFGFast
    lifted ahead of the callsite. That execution is best-effort -- the blocks
    need not even lie on a path to the call -- so its failures must not escape
    into CFGFast and abort recovery of the whole binary."""

    @staticmethod
    def _procedure(proj):
        cc_cls = angr.default_cc(proj.arch.name, platform="Linux")
        assert cc_cls is not None
        proc = angr.SIM_PROCEDURES["posix"]["pthread_create"](
            project=proj,
            cc=cc_cls(proj.arch),
            prototype="int pthread_create(void *thread, void *attr, void *start, void *arg)",
        )
        proc.arch = proj.arch
        proc.prototype = proc.prototype.with_arch(proj.arch)
        return proc

    def test_faulting_block_ahead_does_not_abort(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "cat"), auto_load_libs=False)
        blocks = [proj.factory.block(CAT_SSE_BLOCK).vex, proj.factory.block(CAT_NEXT_BLOCK).vex]

        # the premise: the first block really does produce Ijk_SigSEGV successors first
        state = angr.SimState(project=proj, mode="fastpath", cle_memory_backer=proj.loader.memory)
        succs = proj.factory.default_engine.process(state, blocks[0], force_addr=CAT_SSE_BLOCK).successors
        assert succs[0].history.jumpkind == "Ijk_SigSEGV"

        # must not raise AngrExitError("Cannot execute following jumpkind Ijk_SigSEGV")
        exits = self._procedure(proj).static_exits(blocks)
        assert [e["jumpkind"] for e in exits] == ["Ijk_Call", "Ijk_Ret"]

    def test_fault_successors_are_not_followed(self):
        # the exits must be read off the block's real successor, not off a state
        # that trapped: a faulted state's argument registers are meaningless
        proj = angr.Project(os.path.join(test_location, "x86_64", "cat"), auto_load_libs=False)
        blocks = [proj.factory.block(CAT_SSE_BLOCK).vex]

        state = angr.SimState(project=proj, mode="fastpath", cle_memory_backer=proj.loader.memory)
        succs = proj.factory.default_engine.process(state, blocks[0], force_addr=CAT_SSE_BLOCK).successors
        proc = self._procedure(proj)

        def sources(bv):
            # the unconstrained registers the value came from, without the
            # per-state serial numbers ("reg_rsi_5_64" -> "reg_rsi")
            return {v.rsplit("_", 2)[0] for v in bv.variables}

        real = next(s for s in succs if not s.history.jumpkind.startswith("Ijk_Sig"))
        faulted = next(s for s in succs if s.history.jumpkind.startswith("Ijk_Sig"))
        expected = sources(proc.cc.get_args(real, proc.prototype)[2])
        assert expected != sources(proc.cc.get_args(faulted, proc.prototype)[2])

        (call_exit, _) = proc.static_exits(blocks)
        assert sources(call_exit["address"]) == expected


if __name__ == "__main__":
    unittest.main()
