#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestReturnDuplicatorJumpTablePred(unittest.TestCase):
    def test_return_is_duplicated_for_direct_preds_next_to_a_jump_table_dispatch(self):
        # genericLocHandle() ends in one shared return block reached from the switch cases, the entry check, and the
        # jump-table dispatch itself. The dispatch cannot be retargeted to a copy, but that must not stop the direct
        # predecessors from getting their own return.
        bin_path = os.path.join(test_location, "armel", "decompiler", "cf2.elf")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x8024BC5, window=0x100, expand_call_tree=False, run_ccc=False
        )

        func = cfg.functions[0x8024BC5]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "LABEL_8024be7" not in text
        assert "isEmergencyStopRequested = 1;\n        return;" in text
        assert "xTaskGetTickCount();\n        return;" in text
        assert "switch (" in text


if __name__ == "__main__":
    unittest.main()
