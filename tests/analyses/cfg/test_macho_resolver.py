#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestMachOResolver(unittest.TestCase):
    def test_MachO(self):
        p = angr.Project(os.path.join(test_location, "aarch64", "dyld_ios15.macho"), auto_load_libs=False)
        cfg = p.analyses.CFGFast()

        _objc_opt_self_plt = p.kb.functions["_objc_opt_self"]
        assert _objc_opt_self_plt.is_plt

        _objc_opt_self_plt_node = cfg.model.get_any_node(_objc_opt_self_plt.addr)
        assert len(_objc_opt_self_plt_node.successors) == 1

        _objc_opt_self_successor = _objc_opt_self_plt_node.successors[0]
        assert _objc_opt_self_successor.addr == 0x100100108
        assert _objc_opt_self_successor.is_simprocedure
        assert _objc_opt_self_successor.simprocedure_name == "_objc_opt_self"


if __name__ == "__main__":
    unittest.main()
