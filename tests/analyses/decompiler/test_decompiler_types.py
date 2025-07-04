# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestDecompilerTypes(unittest.TestCase):
    def test_mapping_int64_to_basic_type(self):
        proj = angr.Project(
            os.path.join(
                test_location, "x86_64", "windows", "7995a0325b446c462bdb6ae10b692eee2ecadd8e888e9d7729befe4412007afb"
            ),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFG(
            normalize=True,
            show_progressbar=True,
            regions=[(0x14004C100, 0x14004C100 + 0x1000)],
            start_at_entry=False,
        )

        func = proj.kb.functions[0x14004C100]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None

        # these prototypes are created when decompiling the function above (their caller)
        assert proj.kb.functions[0x1402004F8].prototype.args
        assert proj.kb.functions[0x1402004F8].prototype.args[0].size > 0
        assert proj.kb.functions[0x140200518].prototype.args
        assert proj.kb.functions[0x140200518].prototype.args[-1].size > 0


if __name__ == "__main__":
    unittest.main()
