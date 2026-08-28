#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from tests.common import bin_location

# A libgomp relocatable. gomp_team_start reads through %gs at many points, so the block preceding
# several of its call sites ends in a failure exit guarded on the selector translation failing, and
# the procedure at the call site is handed that block.
BINARY = os.path.join(bin_location, "tests", "i386", "cfg_mapfail_static_member.o")
ARCH = archinfo.arch_from_id("x86")

# Offsets into gomp_team_start. The pthread_create call site and the block before it, which ends in
# Ijk_Call:
BEFORE_CALL = 0x32D
CALL_SITE = 0x394
# A call site whose predecessor ends in Ijk_Boring instead. error.dynamic_returns prefers an
# Ijk_FakeRet successor when the predecessor ends in Ijk_Call, so only this shape reaches it:
BEFORE_BORING = 0x68
BORING_CALL_SITE = 0x153


def _cfg(hooks):
    """
    Recover a CFG of the fixture, with each named import stub replaced by another procedure.
    """

    proj = angr.Project(BINARY, auto_load_libs=False)
    for import_name, procedure in hooks.items():
        symbol = proj.loader.find_symbol(import_name)
        assert symbol is not None, import_name
        proj.hook(symbol.rebased_addr, procedure, replace=True)
    return proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)


def _libc(name):
    return angr.SIM_LIBRARIES["libc.so.6"][0].get(name, ARCH)


def _assert_scanned(cfg, offsets):
    """
    The scan ran to completion: every symbol-seeded function start survives in the CFG, and
    gomp_team_start covers the blocks whose pre-execution the procedure was handed.
    """

    loader = cfg.project.loader
    defined = {symbol.rebased_addr for symbol in loader.main_object.symbols if symbol.is_function}
    assert defined, "the fixture has no defined function symbols"
    assert defined <= set(cfg.functions)

    gomp_team_start = loader.find_symbol("gomp_team_start")
    assert gomp_team_start is not None, "the fixture does not define gomp_team_start"
    team_start = gomp_team_start.rebased_addr
    blocks = {block.addr for block in cfg.functions[team_start].blocks}
    assert {team_start + offset for offset in offsets} <= blocks


class TestCfgSimProcedureExits(unittest.TestCase):
    """
    CFGFast asks a hooked SimProcedure to pre-execute the blocks leading up to a call site. Those
    blocks can produce failure successors, and stepping one raises AngrExitError out of the whole
    analysis unless the procedure keeps to successors that execution can continue from.
    """

    def test_pthread_create_static_exits_over_segment_override(self):
        cfg = _cfg({})
        # this case rests on angr's own default hook rather than on one the test installs
        symbol = cfg.project.loader.find_symbol("pthread_create")
        assert symbol is not None, "the fixture does not import pthread_create"
        stub = symbol.rebased_addr
        assert type(cfg.project.hooked_by(stub)).__name__ == "pthread_create"
        _assert_scanned(cfg, (BEFORE_CALL, CALL_SITE))

    def test_libc_start_main_static_exits_over_segment_override(self):
        cfg = _cfg({"pthread_create": _libc("__libc_start_main")})
        _assert_scanned(cfg, (BEFORE_CALL, CALL_SITE))

    def test_error_dynamic_returns_over_segment_override(self):
        # defuse pthread_create so the only procedure that can reach a failure successor is error
        cfg = _cfg(
            {
                "pthread_create": angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),
                "__libc_thr_self": _libc("error"),
            }
        )
        _assert_scanned(cfg, (BEFORE_BORING, BORING_CALL_SITE))


if __name__ == "__main__":
    unittest.main()
