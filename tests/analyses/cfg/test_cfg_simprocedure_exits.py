#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo
import pyvex

import angr
from tests.common import bin_location

# A libgomp relocatable. gomp_team_start reads through %gs at many points, so the block before
# several of its call sites ends in a failure exit guarded on the selector translation failing,
# and CFGFast hands that block to the procedure hooked at the call site.
BINARY = os.path.join(bin_location, "tests", "i386", "cfg_mapfail_static_member.o")
ARCH = archinfo.arch_from_id("x86")

# Offsets into gomp_team_start. The pthread_create call site and the block before it, which ends
# in Ijk_Call:
BEFORE_CALL = 0x32D
CALL_SITE = 0x394
# A call site whose predecessor ends in Ijk_Boring instead. error.dynamic_returns prefers an
# Ijk_FakeRet successor when the predecessor ends in Ijk_Call, so only this shape reaches it:
BEFORE_BORING = 0x68
BORING_CALL_SITE = 0x153


def _libc(name):
    return angr.SIM_LIBRARIES["libc.so.6"][0].get(name, ARCH)


def _symbol(proj, name):
    symbol = proj.loader.find_symbol(name)
    assert symbol is not None, f"the fixture has no symbol {name}"
    return symbol.rebased_addr


def _blocks(proj, *offsets):
    """
    Lift the blocks CFGFast would hand a procedure at these offsets into gomp_team_start, with
    the lifter options CFGFast._lift uses.
    """

    team_start = _symbol(proj, "gomp_team_start")
    return [proj.factory.block(team_start + offset, opt_level=1, cross_insn_opt=False).vex for offset in offsets]


def _hooked(proj, name):
    """
    A procedure set up the way CFGFast sets one up before asking it for exits.
    """

    procedure = _libc(name)
    procedure.project = proj
    procedure.arch = proj.arch
    return procedure


class TestSimProcedureFailureExits(unittest.TestCase):
    """
    CFGFast asks a hooked SimProcedure to pre-execute the blocks leading up to a call site. Those
    blocks can produce failure successors, and a procedure that continues from one hits
    SimEngineFailure on the next block, which raises AngrExitError: out of the procedure, and for
    dynamic_returns out of the whole analysis.
    """

    def test_the_predecessor_blocks_really_end_in_a_failure_exit(self):
        # the premise the rest of the file rests on, so none of it can pass vacuously
        proj = angr.Project(BINARY, auto_load_libs=False)
        for block in _blocks(proj, BEFORE_CALL, BEFORE_BORING):
            exits = [stmt.jumpkind for stmt in block.statements if isinstance(stmt, pyvex.IRStmt.Exit)]
            assert "Ijk_MapFail" in exits, f"{block.addr:#x} has no failure exit: {exits}"

    def test_pthread_create_static_exits_over_a_failure_exit(self):
        # Coverage rather than a regression. Both exits come back whether or not the failure
        # successor is skipped, because this object's arguments are register- and stack-sourced
        # and stay symbolic either way. What the skip changes is the state they are read from.
        proj = angr.Project(BINARY, auto_load_libs=False)
        exits = _hooked(proj, "pthread_create").static_exits(_blocks(proj, BEFORE_CALL, CALL_SITE))
        assert [(exit_["jumpkind"], exit_["namehint"]) for exit_ in exits] == [
            ("Ijk_Call", "thread_entry"),
            ("Ijk_Ret", None),
        ]

    def test_libc_start_main_static_exits_over_a_failure_exit(self):
        proj = angr.Project(BINARY, auto_load_libs=False)
        exits = _hooked(proj, "__libc_start_main").static_exits(_blocks(proj, BEFORE_CALL, CALL_SITE))
        assert ("Ijk_Call", "main") in [(exit_["jumpkind"], exit_["namehint"]) for exit_ in exits]

    def test_error_dynamic_returns_over_a_failure_exit(self):
        proj = angr.Project(BINARY, auto_load_libs=False)
        # The status argument is stack-sourced on this object, so the answer is "cannot tell".
        # The assertion is that the procedure answers at all rather than raising.
        assert _hooked(proj, "error").dynamic_returns(_blocks(proj, BEFORE_BORING, BORING_CALL_SITE)) is None

    def test_error_dynamic_returns_does_not_abort_the_scan(self):
        # CFGFast reaches dynamic_returns through _is_call_returning, which does not catch for it,
        # so an AngrExitError raised there ends the whole scan. This object does not import
        # error, so the test hooks it in place of __libc_thr_self, and defuses pthread_create so
        # that only error can reach a failure successor.
        proj = angr.Project(BINARY, auto_load_libs=False)
        for import_name, procedure in (
            ("pthread_create", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]()),
            ("__libc_thr_self", _libc("error")),
        ):
            proj.hook(_symbol(proj, import_name), procedure, replace=True)
        cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)

        # the scan ran to completion: every symbol-seeded function start survives in the CFG, and
        # gomp_team_start covers the blocks whose pre-execution error was handed
        defined = {symbol.rebased_addr for symbol in proj.loader.main_object.symbols if symbol.is_function}
        assert defined, "the fixture has no defined function symbols"
        assert defined <= set(cfg.functions)
        team_start = _symbol(proj, "gomp_team_start")
        blocks = {block.addr for block in cfg.functions[team_start].blocks}
        assert {team_start + BEFORE_BORING, team_start + BORING_CALL_SITE} <= blocks


if __name__ == "__main__":
    unittest.main()
