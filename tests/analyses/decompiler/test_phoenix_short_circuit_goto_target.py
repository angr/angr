#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from angr.analyses import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestPhoenixShortCircuitGotoTarget(unittest.TestCase):
    def test_goto_target_is_not_folded_into_a_short_circuit_condition(self):
        # 0x1000267c0 dispatches on a Mach-O magic number. Block 0x100026841 is reached through
        # `cmp eax, 0xbfbafeca; je 0x100026841` at 0x1000267ee and by falling through the 0xcafebabf test at
        # 0x10002683a. The first edge becomes a goto, which leaves 0x100026841 with one predecessor. The
        # short-circuit matcher must not then fold it into the 0xcafebabf test's condition: that drops the label the
        # goto jumps to, and the goto and the 0xbfbafeca test go with it.
        bin_path = os.path.join(test_location, "x86_64", "rust", "short_circuit_goto_target.macho")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x1000267C0, window=0x400, expand_call_tree=False)

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x1000267C0], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "3216703178" in text or "0xbfbafeca" in text
        gotos = set(re.findall(r"goto (LABEL_\w+);", text))
        labels = set(re.findall(r"^\s*(LABEL_\w+):", text, re.MULTILINE))
        assert "LABEL_100026841" in gotos
        assert gotos <= labels, gotos - labels


if __name__ == "__main__":
    unittest.main()
