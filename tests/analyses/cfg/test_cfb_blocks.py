#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""The Blocks CFGFast hands to a CFBlanket: same state as the Python lifting path, built with fewer allocations."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.block import _NO_INS_ADDRS, Block
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _state(block: Block) -> dict:
    return block.__getstate__()


class TestCFBBlocks(unittest.TestCase):
    def test_cfb_block_matches_lift(self):
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            for node in list(cfg.model.graph.nodes())[:50]:
                if not node.size:
                    continue
                got = cfg._cfb_block(node.addr, node.size)
                expected = cfg._lift(
                    node.addr,
                    size=node.size,
                    collect_data_refs=True,
                    strict_block_end=True,
                    load_from_ro_regions=True,
                    const_prop=cfg._fold_ro_const_loads,
                )
                assert _state(got) == _state(expected), (binary, hex(node.addr))
                assert got._project is proj
                # lifted lazily, to the same thing
                assert got._vex is None and got.instruction_addrs == expected.instruction_addrs

    def test_block_factory_args(self):
        # every factory.block argument reaches the same Block parameter as a keyword call
        proj = angr.Project(os.path.join(test_location, "armel", "fauxware"), auto_load_libs=False)
        addr = proj.entry & ~1
        kwargs = {
            "size": 4,
            "max_size": 100,
            "byte_string": b"\x00\xbf\x00\xbf",
            "thumb": True,
            "backup_state": None,
            "extra_stop_points": {addr + 2},
            "opt_level": 2,
            "num_inst": 3,
            "traceflags": 0x10,
            "strict_block_end": True,
            "collect_data_refs": True,
            "cross_insn_opt": False,
            "load_from_ro_regions": True,
            "const_prop": True,
            "initial_regs": [(8, 4, 0x1000)],
        }
        assert _state(proj.factory.block(addr, **kwargs)) == _state(Block(addr, project=proj, **kwargs))
        # backup_state and skip_stmts only matter when the bytes are loaded or the block is lifted
        state = proj.factory.blank_state()
        for skip_stmts in (False, True):
            got = proj.factory.block(addr, backup_state=state, skip_stmts=skip_stmts)
            expected = Block(addr, project=proj, backup_state=state, skip_stmts=skip_stmts)
            assert (got._vex is None) is skip_stmts and (got._vex_nostmt is None) is not skip_stmts
            assert got._backup_state is state
            assert got.size == expected.size and got.bytes == expected.bytes
            assert got.instruction_addrs == expected.instruction_addrs

    def test_unlifted_ins_addrs_are_never_handed_out(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        block = proj.factory.block(proj.entry, size=8)
        assert block._instruction_addrs is _NO_INS_ADDRS
        addrs = block.instruction_addrs
        assert addrs is not _NO_INS_ADDRS and len(addrs) > 0
        assert len(_NO_INS_ADDRS) == 0


if __name__ == "__main__":
    unittest.main()
