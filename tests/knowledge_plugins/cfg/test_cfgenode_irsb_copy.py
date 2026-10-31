#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import copy
import unittest

import archinfo
import pyvex

from angr.engines.vex.data_sensitive import DataSensitiveRdTmp, DataSensitiveU64
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode, clone_irsb

# mov rax, 1; add rax, rbx; ret
STRAIGHT = b"\x48\xc7\xc0\x01\x00\x00\x00\x48\x01\xd8\xc3"
# mov rax, 1; add rax, rbx; cmp rax, 2; je +2
BRANCH = b"\x48\xc7\xc0\x01\x00\x00\x00\x48\x01\xd8\x48\x83\xf8\x02\x74\x02"


def _lift(code):
    return pyvex.lift(code, 0x401000, archinfo.ArchAMD64(), opt_level=0)


def _put_index(irsb, data_type, value=None):
    return next(
        i
        for i, s in enumerate(irsb.statements)
        if isinstance(s, pyvex.stmt.Put)
        and isinstance(s.data, data_type)
        and (value is None or s.data.con.value == value)
    )


class TestCFGENodeIRSBCopy(unittest.TestCase):
    def test_node_owns_a_copy_that_shares_the_arch(self):
        irsb = _lift(STRAIGHT)
        node = CFGENode(0x401000, irsb.size, None, irsb=irsb, instruction_addrs=list(irsb.instruction_addresses))

        assert node.irsb is not irsb
        assert node.irsb.arch is irsb.arch
        assert str(node.irsb) == str(irsb)
        assert all(a is not b for a, b in zip(node.irsb.statements, irsb.statements))

        # rewriting the node must not touch the source
        node.irsb.statements = node.irsb.statements[:1]
        node.irsb.jumpkind = "Ijk_Boring"
        assert len(irsb.statements) > 1
        assert irsb.jumpkind == "Ijk_Ret"

    def test_clone_matches_deepcopy(self):
        irsb = _lift(BRANCH)
        assert irsb.exit_statements  # populate the lazy cache so the clone has to remap it
        bid = BlockID(0x401000, None, "normal", 0x1234)
        const_idx = _put_index(irsb, pyvex.expr.Const, value=1)  # mov rax, 1
        tmp_idx = _put_index(irsb, pyvex.expr.RdTmp)
        irsb.statements[tmp_idx].data = DataSensitiveRdTmp(irsb.statements[tmp_idx].data.tmp, bid)
        irsb.next = pyvex.expr.Const(DataSensitiveU64(0x401010, bid))

        clone = clone_irsb(irsb)
        ref = copy.deepcopy(irsb)
        assert str(clone) == str(ref)
        assert clone.tyenv is not irsb.tyenv and clone.tyenv.types == irsb.tyenv.types
        assert clone.instruction_addresses == irsb.instruction_addresses

        # exit_statements refer to the clone's own statements, as deepcopy's memo guarantees
        assert clone.exit_statements
        for _, idx, stmt in clone.exit_statements:
            assert stmt is clone.statements[idx]

        # data-sensitive extras survive and are independent objects
        assert isinstance(clone.statements[tmp_idx].data, DataSensitiveRdTmp)
        assert clone.statements[tmp_idx].data.block_id == bid
        assert clone.statements[tmp_idx].data is not irsb.statements[tmp_idx].data
        assert isinstance(clone.next.con, DataSensitiveU64)
        assert clone.next.con.block_id == bid
        assert clone.next.con is not irsb.next.con

        # in-place statement rewrites stay local to the clone
        clone.statements[const_idx].data = pyvex.expr.Const(pyvex.const.U64(7))
        assert irsb.statements[const_idx].data.con.value == 1


if __name__ == "__main__":
    unittest.main()
