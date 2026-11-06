# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def declared_global_names(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        if not line.startswith("extern ") or not line.endswith(";"):
            continue
        declarator = line.removeprefix("extern ").removesuffix(";").split("[")[0]
        names.append(declarator.split()[-1].lstrip("*"))
    return names


class TestSymbolVariableNames(unittest.TestCase):
    def test_versioned_symbol_names_a_global(self):
        # ld writes the version a reference resolved against into the symbol table entry, so the
        # copy-relocated stderr is named stderr@GLIBC_2.2.5 here.
        bin_path = os.path.join(test_location, "x86_64", "type_inference_2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=not WORKER)
        proj.analyses.CompleteCallingConventions(recover_variables=True)
        dec = proj.analyses.Decompiler(cfg.functions["evaluate"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        assert "stderr" in declared_global_names(text)
        assert "GLIBC" not in text
        for name in declared_global_names(text):
            assert name.isidentifier(), f"{name!r} is not a C identifier:\n{text}"


if __name__ == "__main__":
    unittest.main()
