#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""CFGFast(normalize=True) creates functions without blocks sharing an end address already normalized."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.knowledge_plugins.functions.function import Function
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _graph(func: Function) -> tuple[list, list]:
    g = func.graph
    return sorted((n.addr, n.size) for n in g.nodes()), sorted((s.addr, s.size, d.addr, d.size) for s, d in g.edges())


class TestPrenormalizedFunctions(unittest.TestCase):
    def _check(self, binary: str):
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        with mock.patch.object(Function, "normalize", autospec=True, side_effect=Function.normalize) as normalize:
            cfg = proj.analyses.CFGFast(normalize=True)
        prenormalized = cfg._prenormalized_func_addrs
        assert prenormalized
        assert not {call.args[0].addr for call in normalize.call_args_list} & prenormalized
        for addr in proj.kb.functions:
            func = proj.kb.functions[addr]
            if proj.is_hooked(addr) or func.startpoint is None:
                continue
            assert func.normalized
            before = _graph(func)
            func.normalize()
            assert _graph(func) == before

    def test_x86_64(self):
        self._check(os.path.join("x86_64", "fauxware"))

    def test_i386_pe_with_nodecode_blocks(self):
        self._check(os.path.join("i386", "windows", "0245fc3455f66354cef5b73de12318f881e89a7f2af19b5592349ce1d7de2017"))

    def test_not_normalized(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=False)
        assert not cfg._prenormalized_func_addrs
        assert not any(proj.kb.functions[a].normalized for a in proj.kb.functions)


if __name__ == "__main__":
    unittest.main()
