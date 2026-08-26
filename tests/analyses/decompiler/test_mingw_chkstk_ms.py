# pylint:disable=missing-class-docstring,missing-function-docstring
"""Regression tests for stripped i686 MinGW ``___chkstk_ms`` stack probes."""

from __future__ import annotations

import os
import re
import unittest

import angr
from angr.analyses import Decompiler
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from tests.common import bin_location

SOURCE_BACKED_BIN_PATH = os.path.join(bin_location, "tests", "i386", "windows", "known_patterns_wdk_ksud.exe")
DECOMPILER_BIN_PATH = os.path.join(bin_location, "tests", "x86", "windows", "simple_crackme_x86.exe")
SOURCE_BACKED_CHKSTK_MS = 0x4028E0
CHKSTK_MS = 0x40DCB0
CONSTANT_SIZE_CALLER = 0x422B10


class TestMinGWChkstkMs(unittest.TestCase):
    def test_cfgfast_recognizes_source_backed_chkstk_ms(self):
        proj = angr.Project(SOURCE_BACKED_BIN_PATH, auto_load_libs=False)
        del proj.kb.labels[SOURCE_BACKED_CHKSTK_MS]
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(SOURCE_BACKED_CHKSTK_MS, 0x40290A)],
            start_at_entry=False,
            function_starts=[SOURCE_BACKED_CHKSTK_MS],
            symbols=False,
            force_smart_scan=False,
        )

        helper = cfg.functions.function(SOURCE_BACKED_CHKSTK_MS)
        assert helper is not None
        self.assertEqual(helper.name, "sub_4028e0")
        self.assertIs(helper.info.get("is_alloca_probe"), True)
        block_bytes = {block.bytes for block in helper.blocks}
        self.assertNotIn(None, block_bytes)
        self.assertSetEqual(
            {data.hex() for data in block_bytes if data is not None},
            {
                "51503d001000008d4c240c7215",
                "81e9001000008309002d001000003d0010000077eb",
                "29c18309005859c3",
            },
        )

    def test_cfgfast_recognizes_chkstk_ms_and_recovers_caller_stack(self):
        proj = angr.Project(DECOMPILER_BIN_PATH, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(CHKSTK_MS, 0x40DCD9), (CONSTANT_SIZE_CALLER, 0x422B85)],
            start_at_entry=False,
            function_starts=[CHKSTK_MS, CONSTANT_SIZE_CALLER],
            symbols=True,
            force_smart_scan=False,
        )

        helper = cfg.functions.function(CHKSTK_MS)
        assert helper is not None
        assert helper.info.get("is_alloca_probe") is True

        # Do not let the fixture's COFF symbol satisfy any name-based fallback: stripped MinGW binaries are the
        # motivating case, and CFGFast's semantic marker must carry the downstream stack-probe behavior by itself.
        helper.name = "sub_40dcb0"
        proj.analyses.CompleteCallingConventions(
            prioritize_func_addrs=[CHKSTK_MS, CONSTANT_SIZE_CALLER],
            skip_other_funcs=True,
        )

        caller = cfg.functions.function(CONSTANT_SIZE_CALLER)
        assert caller is not None
        structurer_option = get_structurer_option()
        for structurer in ("Phoenix", "SAILR"):
            with self.subTest(structurer=structurer):
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(
                    caller,
                    cfg=cfg.model,
                    options=[(structurer_option, structurer)],
                )
                assert dec.codegen is not None and dec.codegen.text is not None
                text = dec.codegen.text

                assert "sub_40dcb0(" not in text
                assert "unsupported instruction" not in text
                assert re.search(r"\w+;  // \[bp-0x5c\]", text) is not None

                memcpy = re.search(r"_memcpy\(([^;]+)\);", text)
                assert memcpy is not None
                assert memcpy.group(1).startswith("a0, ")
                assert memcpy.group(1).count(",") >= 2


if __name__ == "__main__":
    unittest.main()
