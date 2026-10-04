#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

from angr.analyses.decompiler.ssailification import ssailification as ssailification_mod
from angr.analyses.decompiler.ssailification.rewriting import RewritingAnalysis
from angr.analyses.decompiler.ssailification.traversal import TraversalAnalysis
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestSsailificationStartStates(unittest.TestCase):
    def _decompile(self, start_state_blocks_override: set | bool | None):
        traversals = []
        phis = []

        class RecordingTraversal(TraversalAnalysis):
            def __init__(self, *args, **kwargs):
                if start_state_blocks_override is not False:
                    kwargs["start_state_blocks"] = start_state_blocks_override
                super().__init__(*args, **kwargs)
                traversals.append((self, args[2]))

        class RecordingRewriting(RewritingAnalysis):
            def __init__(self, project, func, ail_graph, phiid_to_udef, block_to_phiids, *args, **kwargs):
                phis.append(
                    sorted(
                        (b.addr, b.idx or 0, phiid_to_udef[phi_id])
                        for b, phi_ids in block_to_phiids.items()
                        for phi_id in phi_ids
                    )
                )
                super().__init__(project, func, ail_graph, phiid_to_udef, block_to_phiids, *args, **kwargs)

        bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x40B9F4)
        func = cfg.functions[0x40B9F4]
        with (
            mock.patch.object(ssailification_mod, "TraversalAnalysis", RecordingTraversal),
            mock.patch.object(ssailification_mod, "RewritingAnalysis", RecordingRewriting),
        ):
            dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text, traversals, phis

    def test_start_states_only_kept_for_join_blocks(self):
        text, traversals, phis = self._decompile(False)
        assert traversals
        for traversal, graph in traversals:
            assert traversal.start_states
            # only blocks that can be in a dominance frontier (join points) keep their start states
            assert all(graph.in_degree[block] >= 2 for block in traversal.start_states)
            assert len(traversal.start_states) < len(graph)

        # phi placement must match retaining every start state
        full_text, full_traversals, full_phis = self._decompile(None)
        assert all(len(t.start_states) == len(g) for t, g in full_traversals)
        assert phis == full_phis
        assert text == full_text

        # sanity: phi placement does depend on start states
        _, _, no_state_phis = self._decompile(set())
        assert no_state_phis != full_phis


if __name__ == "__main__":
    unittest.main()
