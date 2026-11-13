#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""CFGFast post-analysis steps that avoid lifting blocks and loading spilled functions."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
from collections import Counter
from unittest import mock

import angr
from angr.analyses.cfg import cfg_fast
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.functions.function_manager import SpillingFunctionDict
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
GO_BIN = os.path.join(test_location, "aarch64", "langdetect_go")
THREEWARE = os.path.join(test_location, "x86_64", "windows", "3ware.sys")


def _propagate_reference(self: CFGFast) -> None:
    """_propagate_key_func_info_to_jump_thunks lifting every single-block function in every round."""
    functions = self.kb.functions
    key_func_addrs: set[int] = set()
    for addrs in functions.get_key_func_type_and_addrs().values():
        key_func_addrs |= addrs
    single_block_addrs = functions.get_func_addr_with_block_count(1)
    if not key_func_addrs or not single_block_addrs:
        return
    changed = True
    rounds = 0
    while changed and rounds < 8:
        changed = False
        rounds += 1
        for func_addr in single_block_addrs:
            if func_addr in key_func_addrs:
                continue
            target = self._trivial_jump_target(func_addr)
            if target is None or target not in key_func_addrs:
                continue
            src_info = functions.get_by_addr(target, meta_only=True).info
            func = functions.get_by_addr(func_addr)
            for key, value in src_info.items():
                if key not in func.info:
                    func.info[key] = value
            key_func_addrs.add(func_addr)
            changed = True


def _infos(proj) -> tuple[dict, dict]:
    fm = proj.kb.functions
    infos = {addr: dict(fm.get_by_addr(addr).info) for addr in fm}
    return infos, {k: sorted(v) for k, v in fm.get_key_func_type_and_addrs().items()}


class _LoadCounter:
    """Counts full SpillingFunctionDict loads per CFGFast phase."""

    def __init__(self, phases: tuple[str, ...]):
        self.loads: Counter[str] = Counter()
        self._phase = ["other"]
        self._patches = []
        orig_load = SpillingFunctionDict._load_from_lmdb

        def load(sfd, addr, meta_only=False):
            if not meta_only:
                self.loads[self._phase[0]] += 1
            return orig_load(sfd, addr, meta_only=meta_only)

        self._patches.append(mock.patch.object(SpillingFunctionDict, "_load_from_lmdb", load))
        for name in phases:
            orig = next(cls.__dict__[name] for cls in CFGFast.__mro__ if name in cls.__dict__)

            def wrapped(cfg, *args, _orig=orig, _name=name, **kwargs):
                prev = self._phase[0]
                self._phase[0] = _name
                try:
                    return _orig(cfg, *args, **kwargs)
                finally:
                    self._phase[0] = prev

            self._patches.append(mock.patch.object(CFGFast, name, wrapped))

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()


class TestJumpThunkPropagation(unittest.TestCase):
    def test_lifts_only_single_instruction_nodes_once(self):
        ref = angr.Project(GO_BIN, auto_load_libs=False)
        with mock.patch.object(CFGFast, "_propagate_key_func_info_to_jump_thunks", _propagate_reference):
            ref.analyses.CFGFast(normalize=True)
        ref_infos, ref_keys = _infos(ref)

        lifted: Counter[int] = Counter()
        orig = CFGFast._trivial_jump_target

        def trivial_jump_target(cfg, addr):
            lifted[addr] += 1
            return orig(cfg, addr)

        proj = angr.Project(GO_BIN, auto_load_libs=False)
        with mock.patch.object(CFGFast, "_trivial_jump_target", trivial_jump_target):
            cfg = proj.analyses.CFGFast(normalize=True)
        assert _infos(proj) == (ref_infos, ref_keys)
        assert lifted and max(lifted.values()) == 1
        for addr in lifted:
            node = cfg.model.get_any_node(addr)
            assert node is None or len(node.instruction_addrs) < 2, hex(addr)
        assert len(lifted) < len(proj.kb.functions.get_func_addr_with_block_count(1))


class TestMakeFunctionsInfo(unittest.TestCase):
    def test_infos_without_reloading_spilled_functions(self):
        ref = angr.Project(GO_BIN, auto_load_libs=False, cache_limits={"functions": None})
        ref.analyses.CFGFast(normalize=True)
        ref_infos, ref_keys = _infos(ref)
        assert any(ref_infos.values())

        proj = angr.Project(GO_BIN, auto_load_libs=False, cache_limits={"functions": 200})
        with _LoadCounter(("_make_functions_in_rust",)) as counter:
            proj.analyses.CFGFast(normalize=True)
        assert counter.loads["_make_functions_in_rust"] == 0
        assert proj.kb.functions._function_map.spilled_count > 0
        assert _infos(proj) == (ref_infos, ref_keys)


class TestSecurityCookieRename(unittest.TestCase):
    def _run(self, normalize: bool) -> Counter[str]:
        calls: Counter[str] = Counter()
        patches = []
        for name in (
            "is_function_security_check_cookie",
            "is_function_security_init_cookie",
            "is_function_security_init_cookie_win8",
        ):
            orig = getattr(cfg_fast, name)

            def counted(*args, _orig=orig, _name=name, **kwargs):
                calls[_name] += 1
                return _orig(*args, **kwargs)

            patches.append(mock.patch.object(cfg_fast, name, counted))
        proj = angr.Project(THREEWARE, auto_load_libs=False)
        for p in patches:
            p.start()
        try:
            proj.analyses.CFGFast(normalize=normalize)
        finally:
            for p in reversed(patches):
                p.stop()
        assert proj.kb.functions[0x1C001A018].name == "_security_init_cookie"
        assert proj.kb.functions[0x1C0010100].name == "_security_check_cookie"
        return calls

    def test_normalized(self):
        calls = self._run(True)
        # no cookie store ends a block of a function other than _security_init_cookie (matched by the win8 check)
        assert calls["is_function_security_init_cookie"] == 0
        assert calls["is_function_security_check_cookie"] == 1
        assert calls["is_function_security_init_cookie_win8"] == 1

    def test_not_normalized(self):
        calls = self._run(False)
        # without a normalized CFG the generic _security_init_cookie check runs on every function
        assert calls["is_function_security_init_cookie"] > 1


if __name__ == "__main__":
    unittest.main()
