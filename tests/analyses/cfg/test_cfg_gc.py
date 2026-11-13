#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""Python objects CFGFast leaves behind."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import gc
import os
import pickle
import unittest

import angr
from angr.analyses.cfg.indirect_jump_resolvers.constant_value_manager import ConstantValueManager
from angr.codenode import FuncNode, HookNode
from angr.knowledge_plugins.functions.recovery import RecoveryFunction, RecoveryFunctionManager
from angr.procedures.stubs.UnresolvableJumpTarget import UnresolvableJumpTarget
from angr.rustylib.function_graph import FunctionGraph, NodeKind
from angr.rustylib.recovery_functions import RecoveryFunctions
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCFGFastGC(unittest.TestCase):
    def test_scan_time_functions_are_freed(self):
        # the jump-table resolver steps a state whose reg_read BP references a ConstantValueManager
        # exact types: isinstance() raises on dead weakproxies left by other tests
        scan_types = {RecoveryFunction, RecoveryFunctionManager, RecoveryFunctions, ConstantValueManager}
        before = {id(o) for o in gc.get_objects() if type(o) in scan_types}
        path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        assert cfg.kb.functions
        gc.collect()
        leaked = [o for o in gc.get_objects() if type(o) in scan_types and id(o) not in before]
        assert not leaked, f"{len(leaked)} scan-time objects alive, e.g. {type(leaked[0]).__name__}"

    def test_function_graphs_are_untracked(self):
        g = FunctionGraph(0x1000)
        g.add_node(NodeKind.BLOCK, 0x1000, 4, False)
        for obj in (g, g.copy(), FunctionGraph.from_bytes(g.to_bytes()), pickle.loads(pickle.dumps(g))):
            assert not gc.is_tracked(obj)
            assert obj.number_of_nodes() == 1
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        assert not any(gc.is_tracked(f._graph) for f in proj.kb.functions.values())

    def test_graph_reads_match_code_nodes(self):
        # the index-based reads of post-analysis and FCP against the CodeNode-based ones
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        funcs = list(cfg.kb.functions.values())
        for func in funcs:
            func._node_objs = None
            assert func.has_endpoints() == (len(func.endpoints) > 0)
            by_index = list(cfg._goout_site_successors(func))
            by_object = [
                (
                    is_retout,
                    [
                        (
                            isinstance(n, FuncNode),
                            isinstance(n, HookNode) and isinstance(n.sim_procedure, UnresolvableJumpTarget),
                            n.addr,
                        )
                        for n in site.successors()
                    ],
                )
                for is_retout, sites in ((False, func.jumpout_sites), (True, func.retout_sites))
                for site in sites
            ]
            assert by_index == by_object, func

        main = cfg.kb.functions["main"]
        main._node_objs = None
        everything = proj.analyses.FastConstantPropagation(main)
        assert main._node_objs is None  # FCP reads node IDs
        addrs = set(main.block_addrs_set)
        by_addrs = proj.analyses.FastConstantPropagation(main, block_addrs=addrs)
        by_blocks = proj.analyses.FastConstantPropagation(main, blocks=set(main.graph))
        assert by_addrs.replacements == by_blocks.replacements == everything.replacements
        assert everything.replacements

    def test_view_cache_shares_one_callback(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        nodes = list(cfg.model.graph.nodes())
        cache = cfg.model.graph._keys._cache
        assert len(cache) >= len(nodes) > 1
        assert len({id(ref.__callback__) for ref in cache.values()}) == 1


if __name__ == "__main__":
    unittest.main()
