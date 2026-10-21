#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPhoenixSwitchSuccessorEdges(unittest.TestCase):
    """
    Switch-case constructs built from lowered switch heads must keep the region connected: a cascade whose copied
    comparison node leaves the switch must stay an if-chain, and a cascade must not swallow a branch that compares
    a different variable.
    """

    def test_gnutls_cli_test_ciphersuite_kx_switch_successor_kept(self):
        # the gnutls_handshake() retry loop: a lowered switch on the client's return value sits inside a loop region
        # whose only exits are case-node successors. the rewritten switch used to orphan the loop's exit, and the
        # enclosing region could not be structured.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "decbench_gnutls_cli_O2_noinline")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x413160, include_plt=True, project_kwargs={"auto_load_libs": False}
        )
        func = proj.kb.functions[0x413160]

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not dec.structuring_failures

        text = dec.codegen.text
        # the code after the handshake loop is present
        assert "Handshake failed" in text
        assert "gnutls_deinit" in text

    def test_bash_execute_connection_cascade_with_foreign_gt_branch(self):
        # execute_connection(): `if (connector < 0x120) { switch-like if-tree on connector } else if (other) ...`.
        # the gt node heads the cascade, and its gt-side subtree compares a different variable. that subtree must
        # not be swallowed by the cascade, or the fake switch head keeps an edge no case refers to and the function
        # can no longer be structured.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "decbench_bash_O0")
        # one call-tree round: the full callee closure of bash's executor covers most of the binary
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x4511E3, include_plt=True, call_tree_depth=1, project_kwargs={"auto_load_libs": False}
        )
        func = proj.kb.functions[0x4511E3]

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not dec.structuring_failures

        text = dec.codegen.text
        # both sides of the >= 0x120 test survive
        assert "288" in text
        assert "124" in text


if __name__ == "__main__":
    unittest.main()
