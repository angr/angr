# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestUnnamedSectionSymbolExtern(unittest.TestCase):
    """
    A relocatable object reaches its own rodata through STT_SECTION symbols, and those carry no name. The global
    variable Clinic makes for one of them used to keep the symbol's empty name, which left the extern declaration
    with nothing to print and lost the whole function.
    """

    def test_a_global_from_an_unnamed_symbol_still_has_a_name(self):
        binary = os.path.join(test_location, "i386", "rtl8723be.ko")
        project = angr.Project(binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        project.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)

        symbol = project.loader.find_symbol(0x40F300)
        assert symbol is not None and symbol.name == ""

        decompilation = project.analyses.Decompiler(cfg.functions[0x400434], cfg=cfg.model)
        codegen = decompilation.codegen
        assert codegen is not None
        print_decompilation_result(decompilation)
        text = codegen.text
        assert text is not None and text.strip()
        assert "extern char g_40f300;" in text


if __name__ == "__main__":
    unittest.main()
