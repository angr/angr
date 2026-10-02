#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.posix"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from tests.common import bin_location

CTF_NUCLEAR = os.path.join(bin_location, "tests", "i386", "ctf_nuclear")
CAT = os.path.join(bin_location, "tests", "x86_64", "cat")
KNOWN_VALUES = os.path.join(bin_location, "tests", "x86_64", "known_values_x64")
SIMPLE_OVERFLOW_NOPIE = os.path.join(bin_location, "tests", "x86_64", "simple_overflow_nopie")
CAT_SSE_BLOCK = 0x404870
KNOWN_VALUES_RDX_BLOCK = 0x40118C
KNOWN_VALUES_RDX_BLOCK_SIZE = 10
KNOWN_VALUES_RDX = 0x7644B4B3B2BD76AD


class TestPthreadCreateStaticExits(unittest.TestCase):
    """
    CFGFast calls pthread_create.static_exits() to recover the entry point of the spawned thread.
    """

    def test_static_exits_executes_the_supplied_vex_block(self):
        source = angr.Project(KNOWN_VALUES, auto_load_libs=False)
        target = angr.Project(SIMPLE_OVERFLOW_NOPIE, auto_load_libs=False)
        assert source.loader.memory.load(
            KNOWN_VALUES_RDX_BLOCK, KNOWN_VALUES_RDX_BLOCK_SIZE
        ) != target.loader.memory.load(KNOWN_VALUES_RDX_BLOCK, KNOWN_VALUES_RDX_BLOCK_SIZE)
        block = source.factory.block(KNOWN_VALUES_RDX_BLOCK, size=KNOWN_VALUES_RDX_BLOCK_SIZE).vex
        procedure = angr.SIM_PROCEDURES["posix"]["pthread_create"](
            project=target,
            cc=angr.calling_conventions.SimCCSystemVAMD64(target.arch),
        )

        exits = procedure.static_exits([block])

        thread_exit = next(exit_ for exit_ in exits if exit_["jumpkind"] == "Ijk_Call")
        assert not thread_exit["address"].symbolic
        assert thread_exit["address"].concrete_value == KNOWN_VALUES_RDX

    def test_static_exits_falls_back_to_the_default_calling_convention(self):
        proj = angr.Project(CAT, auto_load_libs=False)
        procedure = angr.SIM_PROCEDURES["posix"]["pthread_create"](project=proj)
        assert procedure.cc is None
        exits = procedure.static_exits([proj.factory.block(CAT_SSE_BLOCK).vex])

        assert procedure.cc is not None
        assert [exit_["jumpkind"] for exit_ in exits] == ["Ijk_Call", "Ijk_Ret"]

    def test_pcode_cfg_recovers_static_exits(self):
        proj = angr.Project(CTF_NUCLEAR, auto_load_libs=False, engine=angr.engines.UberEnginePcode)
        pthread_create = proj.loader.find_symbol("pthread_create")
        assert pthread_create is not None
        hook_addr = pthread_create.rebased_addr
        procedure = proj.hooked_by(hook_addr)
        assert procedure is not None
        assert procedure.display_name == "pthread_create"

        observed_exits = []
        procedure_class = type(procedure)
        original_static_exits = procedure_class.static_exits

        def observe_static_exits(proc, blocks, **kwargs):
            exits = original_static_exits(proc, blocks, **kwargs)
            observed_exits.append(exits)
            return exits

        with mock.patch.object(procedure_class, "static_exits", observe_static_exits):
            proj.analyses.CFGFast()

        assert len(observed_exits) == 1
        assert [exit_["jumpkind"] for exit_ in observed_exits[0]] == ["Ijk_Call", "Ijk_Ret"]


if __name__ == "__main__":
    unittest.main()
