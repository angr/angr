#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPhoenixBackEdgeNodes(unittest.TestCase):
    """
    Acyclic schemas must match nodes that have an edge to the region head, but must not absorb the region head.
    """

    def test_mirai_killer_kill_by_port(self):
        # after cyclic refinement, a node of the /proc/net/tcp loop either continues or runs
        # `util_strcpy(...); break;`. that node has an edge to the region head.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "decbench_mirai_O2_noinline")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="killer_kill_by_port")
        assert func is not None

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not dec.structuring_failures

        text = dec.codegen.text
        # code after the /proc/net/tcp loop is present
        assert "Found inode" in text
        assert "Failed to find inode" in text
        assert "[killer] Found pid" in text
        # both exits of the loop to close(fd) at 0x4070bc are breaks
        assert "LABEL_4070bc" not in text

    def test_switch_case_targeting_the_region_head(self):
        # plot() is `for (;;) switch (*p++)`. the switch's bounds check heads an inner loop, and the jump table sends
        # ' ' and ',' straight back to it, so one case of the switch is the region head.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "loop_head_switch")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="plot")
        assert func is not None

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not dec.structuring_failures

        text = dec.codegen.text
        assert "switch" in text
        # the case that jumps back to the region head is a continue
        assert "continue;" in text
        assert "goto" not in text

    def test_jump_table_entry_that_is_the_region_head(self):
        # in sub_40ed70, the loop head at 0x410c0e is also an entry of the two-entry jump table at 0x410c00
        # (`sete al; jmp [0x4419c8 + eax*4]`), whose other entry leaves the loop. the function is built by hand so the
        # test does not depend on how CFGFast recovers the 936-block function around the loop.
        bin_path = os.path.join(
            test_location, "i386", "windows", "50e5f670700243535f8ff558831dbbc314b215092f523355aa7a1c26205ece37"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True, regions=[(0x410C00, 0x410C23)], function_starts=[0x410C0E], resolve_indirect_jumps=False
        )

        func_addr, dispatch_addr = 0x410C0E, 0x410C00
        fm = proj.kb.functions
        for addr in list(fm):
            del fm[addr]
        fm.function(addr=func_addr, create=True)
        head = proj.factory.snippet(func_addr, size=0xA)
        call = proj.factory.snippet(0x410C18, size=0x6)
        after_call = proj.factory.snippet(0x410C1E, size=0x5)
        dispatch = proj.factory.snippet(dispatch_addr, size=0xE)
        fm._add_node(func_addr, head)
        fm._add_transition_to(func_addr, head, dispatch, ins_addr=0x410C16, stmt_idx=-2)
        fm._add_transition_to(func_addr, head, call, ins_addr=0x410C16, stmt_idx=-2)
        fm._add_call_to(func_addr, call, 0x408A60, retn_node=after_call, stmt_idx=-2, ins_addr=0x410C19)
        fm._add_fakeret_to(func_addr, call, after_call, confirmed=True)
        fm._add_transition_to(func_addr, after_call, dispatch, ins_addr=0x410C21, stmt_idx=-2)
        fm._add_transition_to(func_addr, dispatch, head, ins_addr=0x410C07, stmt_idx=-2)
        fm._add_outside_transition_to(
            func_addr, dispatch, 0x410BE0, to_function_addr=0x410BE0, ins_addr=0x410C07, stmt_idx=-2
        )
        targets = [func_addr, 0x410BE0]
        cfg.model.jump_tables[dispatch_addr] = IndirectJump(
            dispatch_addr,
            0x410C07,
            func_addr,
            "Ijk_Boring",
            -2,
            resolved_targets=targets,
            jumptable=True,
            jumptable_addr=0x4419C8,
            jumptable_size=8,
            jumptable_entry_size=4,
            jumptable_entries=targets,
            type_=IndirectJumpType.Jumptable_AddressLoadedFromMemory,
        )
        func = fm[func_addr]
        func.normalize()

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "sub_408a60(" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
