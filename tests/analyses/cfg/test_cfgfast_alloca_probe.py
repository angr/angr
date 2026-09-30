# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

import angr
from angr.calling_conventions import is_stack_probe
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

# notepad.exe whose _alloca_probe touches each page with `test byte ptr [r11], r11b` instead of `mov byte ptr [r11], 0`
NOTEPAD_PATH = os.path.join(
    test_location, "x86_64", "windows", "534530cf9e140bf637950070e3f9b73220a3ac2cc394cb8f9ba5003096e33583"
)
ALLOCA_PROBE = 0x140014A30


class TestCFGFastAllocaProbe(unittest.TestCase):
    def test_alloca_probe_touching_pages_with_test(self):
        _, cfg = load_project_with_scoped_cfg(
            NOTEPAD_PATH, ALLOCA_PROBE, window=0x100, expand_call_tree=False, run_ccc=False
        )

        func = cfg.functions.function(ALLOCA_PROBE)
        assert func is not None
        assert func.info.get("is_alloca_probe") is True
        assert ALLOCA_PROBE in cfg.functions.get_key_func_addrs("alloca_probe")

    def test_stack_probe_by_pdb_name(self):
        # without the CFGFast marker, the name from the PDB alone identifies the probe
        proj = angr.Project(NOTEPAD_PATH, auto_load_libs=False)
        func = proj.kb.functions.function(addr=ALLOCA_PROBE, create=True)
        func.name = "_alloca_probe"
        assert is_stack_probe(func)


if __name__ == "__main__":
    unittest.main()
