#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import pyvex

import angr
from angr.analyses.cfg.indirect_jump_resolvers.arm_elf_fast import ArmElfFastResolver
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

FAUXWARE = os.path.join(test_location, "armel", "fauxware")
REGISTER_ADD = os.path.join(test_location, "armel", "cfg_arm_elf_fast_resolve_put")

# strcmp's PLT stub, the sequence _resolve_put is written for:
#
#   8430  add ip, pc, #0
#   8434  add ip, ip, #0x8000
#   8438  ldr pc, [ip, #0xbd4]!
STRCMP_STUB = 0x8430


class TestArmElfFastResolver(unittest.TestCase):
    def test_plt_stub_is_resolved(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        strcmp = proj.loader.find_symbol("strcmp")
        assert strcmp is not None
        stub = cfg.model.get_any_node(STRCMP_STUB)
        assert stub is not None
        assert sorted(successor.addr for successor in cfg.model.get_successors(stub)) == [strcmp.rebased_addr]

    def test_block_with_a_register_add_is_declined(self):
        proj = angr.Project(REGISTER_ADD, auto_load_libs=False)
        original = ArmElfFastResolver._resolve_put
        register_add_results = []

        class StopAfterRegisterAdd:
            def __init__(self, block):
                self._block = block
                self.statements = self._statements()

            def __getattr__(self, name):
                return getattr(self._block, name)

            def _statements(self):
                for block_stmt in self._block.statements:
                    yield block_stmt
                    if (
                        isinstance(block_stmt, pyvex.IRStmt.WrTmp)
                        and isinstance(block_stmt.data, pyvex.IRExpr.Binop)
                        and "Add" in block_stmt.data.op
                        and not block_stmt.constants
                    ):
                        raise AssertionError("resolver continued after a register-register add")

        def record_register_add(resolver, stmt, block, source, cfg, blade):
            has_register_add = any(
                isinstance(block_stmt, pyvex.IRStmt.WrTmp)
                and isinstance(block_stmt.data, pyvex.IRExpr.Binop)
                and "Add" in block_stmt.data.op
                and not block_stmt.constants
                for block_stmt in block.statements
            )
            observed_block = StopAfterRegisterAdd(block) if has_register_add else block
            result = original(resolver, stmt, observed_block, source, cfg, blade)
            if has_register_add:
                register_add_results.append(result)
            return result

        with mock.patch.object(ArmElfFastResolver, "_resolve_put", record_register_add):
            proj.analyses.CFGFast()

        assert register_add_results
        assert all(result == (False, []) for result in register_add_results)


if __name__ == "__main__":
    unittest.main()
