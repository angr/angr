#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestGoStackCheckPreamble(unittest.TestCase):
    def test_main_main_body_survives(self):
        bin_path = os.path.join(test_location, "x86_64", "go", "go1.22.5", "basics")
        func_addr = 0x470720  # main.main
        proj, cfg = load_project_with_scoped_cfg(bin_path, func_addr, window=0x2000, expand_call_tree=False)
        func = proj.kb.functions[func_addr]

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, update_cache=False)
        assert dec.codegen is not None
        assert dec.structuring_failures == []

        text = dec.codegen.text
        # the stack-growth preamble is a loop back to the entry, not a recursive call
        assert "while (" in text
        assert "runtime.morestack_noctxt" in text
        assert "main.main(" not in text.split("\n{", 1)[1]
        # the body after the preamble is present
        for callee in ("main.parse(", "main.fib(", "main.manhattan(", "runtime.printunlock("):
            assert callee in text, f"{callee} missing from decompilation output"


if __name__ == "__main__":
    unittest.main()
