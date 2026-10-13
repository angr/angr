#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestThumbITState(unittest.TestCase):
    def test_no_stale_itstate_at_thumb_function_entry(self):
        # timeMemEffect() directly follows isTimeMemDone.isra.0(), which ends inside an IT block. LibVEX used to carry
        # that IT state into timeMemEffect()'s entry block, which made the decompiler emit a condition check and a
        # branch over the first instruction.
        bin_path = os.path.join(test_location, "armel", "decompiler", "cf2.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x800BB11, window=0x400)

        func = cfg.functions[0x800BB11]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "armg_calculate_condition" not in text
        assert "itstate" not in text
        assert "LABEL_0x800bb15" not in text

        # the real function body is still there
        assert "timeMemEffect(" in text
        assert len(text.splitlines()) >= 200

    def test_itstate_clears_do_not_hide_jump_only_blocks(self):
        # sensfusion6UpdateQImpl() starts with `if (!(ax == 0.0f && ay == 0.0f && az == 0.0f))`. Each `b` that joins
        # the chain is lifted as `itstate = 0; itstate = 0; goto`, so Clinic used to keep these trampolines, Phoenix
        # could not match the short-circuit condition, and the quaternion update after the if was duplicated.
        bin_path = os.path.join(test_location, "armel", "decompiler", "cf2.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x802A3C1, window=0x400, expand_call_tree=False)

        func = cfg.functions[0x802A3C1]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None and dec.clinic is not None
        print_decompilation_result(dec)

        assert 0x802A565 not in {node.addr for node in dec.clinic.graph.nodes}

        text = dec.codegen.text
        assert "||" in text
        assert "goto" not in text
        # accelerometer normalisation and quaternion normalisation; the latter is not duplicated
        assert text.count("invSqrt(") == 2
        assert text.count("return") == 1

    def test_virtualized_edge_from_one_armed_condition_keeps_its_goto(self):
        # owRead(): the final owSyslinkTransfer() failure edge is virtualized after the ITE matcher has folded the
        # cbz into a one-armed ConditionNode. _virtualize_edge() used to see the jump inside that arm, assume it
        # already went to the target, and emit nothing, silently dropping the `return false` path.
        bin_path = os.path.join(test_location, "armel", "decompiler", "cf2.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x8016E45, window=0x400, expand_call_tree=False)

        func = cfg.functions[0x8016E45]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert text.count("owSyslinkTransfer(") == 2
        # five ways out of the body: nothing to read, bulk-transfer failure, bulk-transfer completion,
        # final-transfer failure, final-transfer completion
        exits = sum(len(re.findall(rf"\b{kw}\b", text)) for kw in ("break", "return", "goto"))
        assert exits >= 5, text


if __name__ == "__main__":
    unittest.main()
