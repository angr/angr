#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
Memory barriers, which libVEX lifts to one architecture-independent fence statement.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from angr.analyses import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


def _decompile(bin_path: str, addr: int, window: int) -> str:
    proj, cfg = load_project_with_scoped_cfg(
        bin_path, addr, window=window, expand_call_tree=False, project_kwargs={"auto_load_libs": False}
    )
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[addr], cfg=cfg.model)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


class TestMemoryFence(unittest.TestCase):
    def test_aarch64_dmb(self):
        # on_exit: dmb ish orders the stores into the new exit_function entry before the store of its flavor
        text = _decompile(os.path.join(test_location, "aarch64", "libc.so.6"), 0x4362E4, 0x68)
        assert "unsupported instruction" not in text, text
        assert re.search(r"__sync_synchronize\(\);\n\s*\*v\d+ = 2;", text), text

    def test_amd64_mfence(self):
        text = _decompile(os.path.join(test_location, "x86_64", "igt_stats"), 0x40B6B0, 0x14)
        assert "unsupported instruction" not in text, text
        assert re.search(r"\*v\d+ = 0x5000000;\n\s*_mm_mfence\(\);", text), text


if __name__ == "__main__":
    unittest.main()
