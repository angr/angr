#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.analyses import Decompiler
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import ContinueNode, LoopNode
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def _while_loop_continue_targets(root) -> list[tuple[int, int]]:
    """
    (loop head, continue target) for every continue whose innermost enclosing loop is a while loop.
    """
    pairs = []

    def _walk_loop(loop: LoopNode):
        def _handle_Continue(node: ContinueNode, **kwargs):  # pylint:disable=unused-argument
            if loop.sort == "while":
                pairs.append((loop.addr, node.target))

        def _handle_Loop(node: LoopNode, **kwargs):  # pylint:disable=unused-argument
            _walk_loop(node)

        SequenceWalker(handlers={ContinueNode: _handle_Continue, LoopNode: _handle_Loop}).walk(loop.sequence_node)

    def _handle_Loop(node: LoopNode, **kwargs):  # pylint:disable=unused-argument
        _walk_loop(node)

    SequenceWalker(handlers={LoopNode: _handle_Loop}).walk(root)
    return pairs


class TestWhileLoopContinues(unittest.TestCase):
    def test_continue_to_block_in_while_loop(self):
        """
        delete_archive_members() in GNU tar's src/delete.c (0x417069 here) reads headers in a loop until it finds a
        member to delete or the end of the archive. Five jmp instructions in that loop go to 0x417299, which saves the
        status just read and tests whether to leave the loop, before the loop goes back to 0x4170c1 to read the next
        header. Cyclic refinement turns those jumps into continues, but the loop is structured as a while loop headed by
        0x4170c1, where a continue would skip 0x417299.
        """
        bin_path = os.path.join(test_location, "x86_64", "decbench_tar_O0_stripped")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x417069, include_plt=True, expand_call_tree=False)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(proj.kb.functions[0x417069], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        pairs = _while_loop_continue_targets(dec.seq_node)
        assert (0x4170C1, 0x417299) not in pairs, pairs
        # the five jmp instructions, plus the path that master already prints as a goto to 0x417299
        assert dec.codegen.text.count("goto LABEL_417299;") == 6


if __name__ == "__main__":
    unittest.main()
