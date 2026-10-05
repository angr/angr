#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,unused-argument
from __future__ import annotations

import os
import unittest
from unittest import mock

import angr
from angr import claripy
from angr.engines.vex.claripy import ccall
from angr.engines.vex.heavy import dirty
from angr.errors import SimOperationError
from tests.common import bin_location

STATIC = os.path.join(bin_location, "tests", "x86_64", "static")

# `fnstcw word ptr [rsp - 2]` in __setfpucw, whose IR calls amd64g_create_fpucw.
FPUCW_INSN = 0x44EE30
# `cpuid` in init_cacheinfo, whose IR calls amd64g_dirtyhelper_CPUID_avx512_SKX.
CPUID_INSN = 0x400681


def narrow_extract(*args, **kwargs):
    """Slice 32 bits out of an 8-bit value, as a helper does on a short load."""
    return claripy.BVS("narrow", 8)[31:0]


def called_names(irsb):
    items = list(irsb.statements) + list(irsb.expressions)
    return {getattr(getattr(item, "cee", None), "name", None) for item in items}


class TestVEXHelperResilience(unittest.TestCase):
    """A claripy error out of a ccall or a dirty helper must arrive as a SimError.

    Everything that contains an engine failure is written against SimError:
    VEXResilienceMixin's wrappers, CFGFast's jump-table resolver and
    SyscallResolver's statement-skipping retry. A claripy exception is none of
    those, so one used to escape the engine and take the whole analysis with it.

    The error is injected by replacing one helper, because the producers that
    emit a bad width into a helper are separate defects with their own fixes;
    what is under test here is the boundary, not any one producer.
    """

    def _project_at(self, addr, helper):
        project = angr.Project(STATIC, auto_load_libs=False)
        assert helper in called_names(project.factory.block(addr, num_inst=1).vex)
        return project

    def test_ccall_claripy_error_becomes_sim_operation_error(self):
        project = self._project_at(FPUCW_INSN, "amd64g_create_fpucw")
        with mock.patch.object(ccall, "amd64g_create_fpucw", narrow_extract):
            state = project.factory.blank_state(addr=FPUCW_INSN)
            with self.assertRaises(SimOperationError):
                project.factory.successors(state, num_inst=1)

    def test_errored_ccall_can_be_bypassed(self):
        project = self._project_at(FPUCW_INSN, "amd64g_create_fpucw")
        with mock.patch.object(ccall, "amd64g_create_fpucw", narrow_extract):
            state = project.factory.blank_state(addr=FPUCW_INSN, add_options={angr.options.BYPASS_ERRORED_IRCCALL})
            assert len(project.factory.successors(state, num_inst=1).successors) == 1

    def test_dirty_claripy_error_becomes_sim_operation_error(self):
        project = self._project_at(CPUID_INSN, "amd64g_dirtyhelper_CPUID_avx512_SKX")
        with mock.patch.object(dirty, "amd64g_dirtyhelper_CPUID_avx512_SKX", narrow_extract):
            state = project.factory.blank_state(addr=CPUID_INSN)
            with self.assertRaises(SimOperationError):
                project.factory.successors(state, num_inst=1)

    def test_errored_dirty_statement_can_be_bypassed(self):
        project = self._project_at(CPUID_INSN, "amd64g_dirtyhelper_CPUID_avx512_SKX")
        with mock.patch.object(dirty, "amd64g_dirtyhelper_CPUID_avx512_SKX", narrow_extract):
            state = project.factory.blank_state(addr=CPUID_INSN, add_options={angr.options.BYPASS_ERRORED_IRSTMT})
            assert len(project.factory.successors(state, num_inst=1).successors) == 1


if __name__ == "__main__":
    unittest.main()
