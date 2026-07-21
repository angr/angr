#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest
from unittest import mock

import angr
from angr.knowledge_plugins.variables import variable_manager as variable_manager_mod
from angr.knowledge_plugins.variables.spilling import SpillingVariableInternalDict
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestVariableManager(unittest.TestCase):
    def test_variable_manager_internal_pickle(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        vm = p.kb.variables

        # Create a VariableManagerInternal and generate some variable idents
        vmi = vm.get_function_manager(0x400000)
        ident0 = vmi.next_variable_ident("stack")
        ident1 = vmi.next_variable_ident("stack")
        ident2 = vmi.next_variable_ident("register")
        assert ident0 == "is_0"
        assert ident1 == "is_1"
        assert ident2 == "ir_0"

        # Pickle round-trip
        data = pickle.dumps(vmi)
        vmi2 = pickle.loads(data)

        # The counters should continue from where they left off
        ident3 = vmi2.next_variable_ident("stack")
        ident4 = vmi2.next_variable_ident("register")
        assert ident3 == "is_2"
        assert ident4 == "ir_1"

    def test_dec_variables_spill_evict_and_reload(self):
        # kb.dec_variables holds its per-function managers in a SpillingVariableInternalDict. Forcing a tiny cache
        # limit spills the least-recently-used entries to the RuntimeDb LMDB store, and they reload with identical
        # content on access.
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        for name in ("main", "authenticate"):
            p.analyses.Decompiler(name, cfg=cfg.model)

        dvm = p.kb.dec_variables
        fm = dvm.function_managers
        assert isinstance(fm, SpillingVariableInternalDict)
        assert len(fm) >= 2

        def content(internal):
            return sorted(v.ident for v in internal._variables)

        pre = {addr: content(fm[addr]) for addr in list(fm)}
        assert all(pre.values()), "each decompiled function should have variables"

        # force every entry out of the in-memory cache
        fm._cache_limit = 0
        fm._evict_lru()
        assert not fm._cache and len(fm._spilled) == len(pre)

        # accessing a spilled entry reloads it losslessly (with the manager reattached)
        for addr, expected in pre.items():
            reloaded = fm[addr]
            assert reloaded.manager is dvm
            assert content(reloaded) == expected

    def test_dec_variables_spilling_pickle_roundtrip(self):
        # A knowledge base whose dec_variables have been spilled pickles self-containedly (the non-durable RuntimeDb
        # reference is dropped) and the per-function variables survive the round-trip.
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        p.analyses.Decompiler("main", cfg=cfg.model)

        dvm = p.kb.dec_variables
        addr = next(iter(dvm.function_managers))
        pre = sorted(v.ident for v in dvm.function_managers[addr]._variables)
        # spill everything before pickling
        dvm.function_managers._cache_limit = 0
        dvm.function_managers._evict_lru()

        kb2 = pickle.loads(pickle.dumps(p.kb))
        dvm2 = kb2.dec_variables
        assert isinstance(dvm2.function_managers, SpillingVariableInternalDict)
        assert list(dvm2.function_managers) == [addr]
        post = sorted(v.ident for v in dvm2.function_managers[addr]._variables)
        assert post == pre

    def test_dec_variables_decompile_under_tiny_spill_limit(self):
        # Decompilation output is byte-identical whether dec_variables spill aggressively (cache limit 1, so every
        # function's manager is evicted as soon as the next function is decompiled) or spilling is disabled.
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        func_names = ("main", "authenticate", "accepted", "rejected")

        p = angr.Project(binpath, auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        fm = p.kb.dec_variables.function_managers
        assert isinstance(fm, SpillingVariableInternalDict)
        fm._cache_limit = 1

        texts = {}
        for name in func_names:
            dec = p.analyses.Decompiler(name, cfg=cfg.model)
            assert dec.codegen is not None and dec.codegen.text is not None
            texts[name] = dec.codegen.text
        assert fm._spilled, "decompiling multiple functions under cache limit 1 must have spilled entries"

        with mock.patch.object(variable_manager_mod, "USE_SPILLING_DVARS", False):
            p2 = angr.Project(binpath, auto_load_libs=False)
            cfg2 = p2.analyses.CFGFast(normalize=True)
            assert type(p2.kb.dec_variables.function_managers) is dict
            for name in func_names:
                dec2 = p2.analyses.Decompiler(name, cfg=cfg2.model)
                assert dec2.codegen is not None and dec2.codegen.text == texts[name]


if __name__ == "__main__":
    unittest.main()
