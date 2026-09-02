#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
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


if __name__ == "__main__":
    unittest.main()
