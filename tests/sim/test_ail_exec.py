from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use

import os
import unittest
from functools import cache

import claripy

import angr
from angr import ailment
from angr.engines.ail.callstack import AILCallStack
from angr.engines.ail.engine_light import SimEngineAILSimState
from angr.engines.successors import SimSuccessors
from angr.procedures.libc.snprintf import snprintf as snprintf_proc

from angr.analyses.decompiler.clinic import Clinic
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestAILExec(unittest.TestCase):
    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)

        @cache
        def lift_function(addr):
            func = p.kb.functions[addr]
            passes = angr.analyses.decompiler.DECOMPILATION_PRESETS["full"].get_optimization_passes(
                p.arch, p.simos.name
            )
            return p.analyses[Clinic].prep(kb=p.kb)(func, optimization_passes=passes)

        def lifter(addr):
            node = cfg.model.get_any_node(addr, anyaddr=True)
            assert node is not None
            return lift_function(node.function_address)

        argc = claripy.BVS("argc", 64)
        state = angr.engines.ail.ail_call_state(
            p,
            "main",
            [argc, claripy.BVV(0, 64)],
            lifter,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.RUN_HOOKS_AT_PLT,
                angr.options.CALLLESS,
            },
        )
        simgr = p.factory.simgr(state)
        simgr.run(n=20)
        # there should be 4 deadended states, and all of them should have argc in the constraints
        assert len(simgr.active) == 0
        assert len(simgr.errored) == 0
        assert len(simgr.deadended) == 4
        assert all(
            any(argc.variables & constraint.variables for constraint in state.solver.constraints)
            for state in simgr.deadended
        )
