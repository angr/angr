#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestUnmappedRegisterRendering(unittest.TestCase):
    """Rendering of a register that variable recovery did not turn into a variable."""

    def test_stack_pointer_in_a_variable_length_frame_is_named(self):
        # sub_401690 adjusts esp by a value it computes at run time, so the stack pointer
        # survives to the C backend and variable recovery has no variable for it.
        proj = angr.Project(os.path.join(test_location, "i386", "simple_windows.exe"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        decompilation = proj.analyses.Decompiler(proj.kb.functions[0x401690], cfg=cfg.model)

        assert decompilation.codegen is not None and decompilation.codegen.text is not None
        text = decompilation.codegen.text
        assert "/* unsupported instruction */" not in text
        assert "esp = " in text


if __name__ == "__main__":
    unittest.main()
