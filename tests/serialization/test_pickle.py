#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import gc
import os
import pickle
import shutil
import unittest
from contextlib import suppress

from claripy import BVS

import angr
from angr.knowledge_plugins.cfg.spilling_cfg import USE_SPILLING_CFGNODE_DICT, SpillingCFG
from angr.knowledge_plugins.cfg.spilling_digraph import SpillingDiGraph
from angr.knowledge_plugins.functions.function_manager import USE_SPILLING_FUNCTION_DICT, SpillingFunctionDict
from angr.storage import SimFile
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPickle(unittest.TestCase):
    @classmethod
    def tearDown(self):
        shutil.rmtree("pickletest", ignore_errors=True)
        shutil.rmtree("pickletest2", ignore_errors=True)
        with suppress(FileNotFoundError):
            os.remove("pickletest_good")
        with suppress(FileNotFoundError):
            os.remove("pickletest_bad")

    def _load_pickles(self):
        # This is the working case
        with open("pickletest_good", "rb"):
            pass

        # This will not work
        with open("pickletest_bad", "rb"):
            pass

    def _make_pickles(self):
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"))

        fs = {
            "/dev/stdin": SimFile("/dev/stdin"),
            "/dev/stdout": SimFile("/dev/stdout"),
            "/dev/stderr": SimFile("/dev/stderr"),
        }

        MEM_SIZE = 1024
        mem_bvv = {}
        for f in fs:
            mem = BVS(f, MEM_SIZE * 8)
            mem_bvv[f] = mem

        with open("pickletest_good", "wb") as f:
            pickle.dump(mem_bvv, f, -1)

        # If you do not have a state you cannot write
        _ = p.factory.entry_state(fs=fs)
        for f in fs:
            mem = mem_bvv[f]
            fs[f].write(0, mem, MEM_SIZE)

        with open("pickletest_bad", "wb") as f:
            pickle.dump(mem_bvv, f, -1)

    def test_pickling(self):
        self._make_pickles()
        self._load_pickles()
        gc.collect()
        self._load_pickles()

    def test_project_pickling(self):
        # AnalysesHub should not be pickled together with the project itself
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"))

        # make a copy of the active_preset so that we do not touch the global preset object. this is only for writing
        # this test case.
        p.analyses._active_preset = pickle.loads(pickle.dumps(p.analyses._active_preset, -1))
        assert len(p.analyses._active_preset._default_plugins) > 0
        p.analyses._active_preset = p.analyses._active_preset
        p.analyses._active_preset._default_plugins = {}
        assert len(p.analyses._active_preset._default_plugins) == 0

        s = pickle.dumps(p, -1)

        p1 = pickle.loads(s)
        assert len(p1.analyses._active_preset._default_plugins) > 0

    @unittest.skipUnless(
        USE_SPILLING_FUNCTION_DICT and USE_SPILLING_CFGNODE_DICT,
        "Requires LMDB-backed spilling dicts to be enabled (USE_SPILLING_FUNCTION_DICT / USE_SPILLING_CFGNODE_DICT)",
    )
    def test_cfg_pickling_with_rtdb(self):
        # Regression test for angr/angr#6408: pickling a Project after CFGFast must
        # succeed even when the RuntimeDb LMDB environment has been initialized by
        # SpillingFunctionDict / SpillingCFGNodeDict. The fauxware binary is too small
        # to trigger automatic spilling, so we force small cache limits.
        p = angr.Project(
            os.path.join(test_location, "x86_64", "fauxware"),
            auto_load_libs=False,
            cache_limits={"functions": 10, "cfg_nodes": 10, "cfg_edges": 10},
        )
        # Force the LMDB environment to actually be opened so the unpicklable handle
        # would be present in RuntimeDb at pickle time.
        p.kb.rtdb._init_lmdb()
        assert p.kb.rtdb._lmdb_env is not None

        cfg = p.analyses.CFGFast()

        # Confirm the spilling LMDB-backed containers are actually in use; without them
        # this test wouldn't exercise the original bug.
        assert isinstance(p.kb.functions._function_map, SpillingFunctionDict)
        assert isinstance(cfg.model.graph, SpillingCFG)
        assert isinstance(cfg.model.graph._graph, SpillingDiGraph)
        original_func_count = len(p.kb.functions)
        original_main_addr = p.kb.functions["main"].addr
        original_node_count = len(list(cfg.model.nodes()))

        data = pickle.dumps(p, -1)
        p2 = pickle.loads(data)

        # RuntimeDb on the unpickled side should start with a fresh (uninitialized) LMDB.
        assert p2.kb.rtdb._lmdb_env is None
        assert p2.kb.rtdb._lmdb_path is None

        # Functions survive the round-trip.
        assert len(p2.kb.functions) == original_func_count
        assert p2.kb.functions["main"].addr == original_main_addr
        # SpillingFunctionDict.rtdb is re-wired by FunctionManager.set_kb during unpickle.
        assert p2.kb.functions._function_map.rtdb is p2.kb.rtdb

        # CFG nodes survive the round-trip.
        cfg2_model = next(iter(p2.kb.cfgs.cfgs.values()))
        assert len(list(cfg2_model.nodes())) == original_node_count

        # Lazy re-initialization of LMDB on the unpickled side must work for future use.
        p2.kb.rtdb._init_lmdb()
        assert p2.kb.rtdb._lmdb_env is not None

    def test_multi_kb_serialization(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFG()

        func_main = cfg.kb.functions["main"]
        other_kb = p.get_kb("other")
        p.analyses.CFG(kb=other_kb)
        other_kb.functions["main"].name = "asdf"
        assert other_kb.functions["asdf"].addr == func_main.addr

        p1 = pickle.loads(pickle.dumps(p, -1))
        assert p1.get_kb("other").functions["asdf"].addr == func_main.addr


if __name__ == "__main__":
    unittest.main()
