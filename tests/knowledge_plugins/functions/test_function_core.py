#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""FunctionCore (the Rust core of Function), bulk function construction, and the FunctionManager address index."""

from __future__ import annotations

import os
import pickle
import random
import unittest

import angr
from angr.knowledge_plugins.functions import Function, FunctionManager, FunctionRecord
from angr.knowledge_plugins.functions.function_index import FunctionIndex, PyFunctionIndex
from angr.knowledge_plugins.functions.function_manager import FunctionDict
from angr.knowledge_plugins.functions.recovery import RecoveryFunctionManager
from angr.rustylib.function_core import FunctionCore
from angr.rustylib.function_graph import NodeKind
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


def _core_fields(func: Function) -> dict:
    return {
        "addr": func.addr,
        "name": func.name,
        "is_default_name": func.is_default_name,
        "previous_names": list(func.previous_names),
        "binary_name": func.binary_name,
        "is_syscall": func.is_syscall,
        "is_simprocedure": func.is_simprocedure,
        "is_plt": func.is_plt,
        "is_alignment": func.is_alignment,
        "returning": func.returning,
        "prototype": func.prototype,
        "calling_convention": type(func.calling_convention),
        "prototype_libname": func.prototype_libname,
        "info": dict(func.info),
        "blocks": sorted(func.block_addrs_set),
    }


class TestFunctionCore(unittest.TestCase):
    def test_core_fields_and_dirty_tracking(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        func = Function(proj.kb.functions, 0x400580, syscall=False)
        assert isinstance(func, FunctionCore)
        func._dirty = False
        func.is_plt = func.is_plt
        assert not func.dirty
        func.is_plt = not func.is_plt
        assert func.dirty
        func._dirty = False
        func.name = "renamed"
        assert func.dirty
        assert func.previous_names == ["_start"]
        func.previous_names.append("other")  # the list is the function's own
        assert func.previous_names == ["_start", "other"]
        func.returning = False
        assert proj.kb.functions.is_func_nonreturning(0x400580)

    def test_pickle_and_legacy_state(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.kb.functions["main"]
        func.name = "main2"
        func.tags = ("x",)
        state = func.__getstate__()
        loaded = pickle.loads(pickle.dumps(func))
        assert _core_fields(loaded) | {"calling_convention": None} == _core_fields(func) | {"calling_convention": None}
        assert loaded.tags == ("x",)
        assert loaded._graph is not func._graph
        # a state pickled before the core moved to Rust (flags may be None there)
        state["_is_alignment"] = None
        old = Function.__new__(Function)
        old.__setstate__(state)
        assert old.is_alignment is False
        assert old.name == "main2" and old.previous_names == ["main"]

    def test_bulk_add_matches_function_creation(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        proj.analyses.CFGFast()
        addrs = sorted(proj.kb.functions)
        one_by_one = FunctionManager(proj.kb)
        for addr in addrs:
            one_by_one.function(addr, create=True)
        bulk = FunctionManager(proj.kb)
        funcs = bulk.bulk_add_functions([FunctionRecord(addr) for addr in addrs])
        assert [f.addr for f in funcs] == addrs
        for addr in addrs:
            assert _core_fields(bulk[addr]) == _core_fields(one_by_one[addr])
        for addr in addrs:
            assert bulk.is_func_returning_unknown(addr) == one_by_one.is_func_returning_unknown(addr)
            assert bulk.get_func_name(addr) == one_by_one.get_func_name(addr)
        # given fields win, and the graph is used as is
        graph = proj.kb.functions[addrs[0]]._graph.copy()
        fm = FunctionManager(proj.kb)
        (f,) = fm.bulk_add_functions(
            [FunctionRecord(addrs[0], graph=graph, name="x", returning=False, is_plt=True, info={"is_foo": True})]
        )
        assert (f.name, f.is_default_name, f.returning, f.is_plt) == ("x", False, False, True)
        assert f._graph is graph and f.block_addrs_set == proj.kb.functions[addrs[0]].block_addrs_set
        assert fm.get_key_func_addrs("foo") == {addrs[0]}
        assert fm.is_func_nonreturning(addrs[0])
        with self.assertRaises(ValueError):
            fm.bulk_add_functions([FunctionRecord(addrs[0])])

    def test_bulk_import_store(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        rec = RecoveryFunctionManager(proj.kb)
        rec._add_node(0x400580, (NodeKind.BLOCK, 0x400580, 4, False))
        rec._add_node(0x400600, (NodeKind.BLOCK, 0x400600, 8, False))
        rec[0x400600].name = "named"
        rec[0x400600].info["is_alloca_probe"] = True
        rec[0x400580].returning = False
        fm = FunctionManager(proj.kb)
        funcs = fm.bulk_import_store(rec.store)
        assert [f.addr for f in funcs] == [0x400580, 0x400600]
        for f in funcs:
            view = rec[f.addr]
            assert f._graph is view._graph
            assert (f.name, f.previous_names, f.returning, dict(f.info)) == (
                view.name,
                view.previous_names,
                view.returning,
                dict(view.info),
            )
        assert fm.get_key_func_addrs("alloca_probe") == {0x400600}
        assert fm.is_func_nonreturning(0x400580)
        assert fm.get_addrs_by_name("named") == {0x400600}


class TestFunctionIndex(unittest.TestCase):
    def test_rust_index_matches_python_index(self):
        rng = random.Random(7)
        rust, py = FunctionIndex(), PyFunctionIndex()
        names = ["a", "b", "c"]
        for _ in range(3000):
            addr = rng.randrange(0, 64) * 16
            op = rng.randrange(8)
            returning = rng.choice([True, False, None])
            for idx in (rust, py):
                if op == 0:
                    idx.add(addr)
                elif op == 1:
                    idx.discard(addr)
                elif op == 2:
                    idx.set_returning(addr, returning)
                elif op == 3:
                    idx.set_block_count(addr, addr % 3)
                elif op == 4:
                    idx.name_changed(addr, idx.name(addr), names[addr % 3])
                elif op == 5:
                    idx.set_from_signature(addr, "flirt" if addr % 32 else None)
                elif op == 6:
                    idx.add_key_func("k", addr)
                else:
                    idx.function_removed(addr, [names[(addr + 1) % 3]])
            q = rng.randrange(0, 64) * 16 + 3
            assert rust.addrs() == py.addrs()
            assert rust.floor(q) == py.floor(q) and rust.ceiling(q) == py.ceiling(q)
            assert rust.next_addr(q) == py.next_addr(q)
            assert rust.irange(q, q + 200, (True, False), True) == py.irange(q, q + 200, (True, False), True)
            assert rust.is_nonreturning(addr) == py.is_nonreturning(addr)
            assert rust.is_returning_unknown(addr) == py.is_returning_unknown(addr)
            assert rust.block_counts() == py.block_counts()
            assert list(rust.addrs_with_block_count(1)) == list(py.addrs_with_block_count(1))
            assert list(rust.addrs_from_signature("flirt")) == list(py.addrs_from_signature("flirt"))
            for n in names:
                assert rust.addrs_by_name(n, True) == py.addrs_by_name(n, True)
                assert list(rust.addrs_by_name_set(n, True)) == list(py.addrs_by_name_set(n, True))
            assert rust.key_funcs() == py.key_funcs()

    def test_iteration_sees_later_insertions(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        fm = FunctionManager(proj.kb)
        for addr in (0x400580, 0x400600):
            fm.function(addr, create=True)
        seen = []
        for addr in fm:
            seen.append(addr)
            if addr == 0x400580:
                fm.function(0x4005F0, create=True)  # after the cursor: visited
                fm.function(0x400500, create=True)  # before the cursor: not visited
                del fm[0x400600]
        assert seen == [0x400580, 0x4005F0]
        assert fm.floor_addr(0x4005EF) == 0x400580
        assert fm.ceiling_addr(0x400581) == 0x4005F0
        assert list(fm._function_map.irange(maximum=0x400580)) == [0x400500, 0x400580]
        assert 0x400500 in fm.function_addrs_set and len(fm.function_addrs_set) == 3

    def test_legacy_function_dict_pickle(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        func = Function(proj.kb.functions, 0x400580, syscall=False)
        # pickles of the former SortedDict-based FunctionDict call FunctionDict(<key func>, {addr: func})
        d = FunctionDict(None, {0x400580: func})
        assert list(d) == [0x400580] and d[0x400580] is func
        d2 = pickle.loads(pickle.dumps(d))
        assert list(d2) == [0x400580] and d2[0x400580].name == func.name


if __name__ == "__main__":
    unittest.main()
