# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
import unittest
import os

import angr
from angr.analyses.decompiler import Decompiler
from tests.common import print_decompilation_result, bin_location

test_location = os.path.join(bin_location, "tests")


class TestDecompilerInlining(unittest.TestCase):
    def test_inlining_shallow(self):
        # https://github.com/angr/angr/issues/4573
        bin_path = os.path.join(test_location, "x86_64", "inline_gym.so")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep(fail_fast=True)(
            f,
            cfg=cfg.model,
            inline_functions={proj.kb.functions["mylloc"], proj.kb.functions["five"]},
            options=[(angr.analyses.decompiler.decompilation_options.options[0], True)],
        )
        print_decompilation_result(d)

        assert "five" not in d.codegen.text
        assert "mylloc" not in d.codegen.text
        assert "malloc" in d.codegen.text
        assert "bar(15)" in d.codegen.text
        assert "malloc(15)" in d.codegen.text
        assert "v1" not in d.codegen.text

    def test_inlining_mylloc_only(self):
        bin_path = os.path.join(test_location, "x86_64", "inline_gym_old.so")

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        f = proj.kb.functions["main"]

        # let's decompile without inlining first
        d = proj.analyses[Decompiler].prep(fail_fast=True)(f, cfg=cfg.model, inline_functions={}, use_cache=False)
        print_decompilation_result(d)
        assert "mylloc" in d.codegen.text

        d = proj.analyses[Decompiler].prep(fail_fast=True)(
            f,
            cfg=cfg.model,
            inline_functions={
                proj.kb.functions["mylloc"],
            },
            use_cache=False,
            options=[(angr.analyses.decompiler.decompilation_options.options[0], True)],
        )
        print_decompilation_result(d)

        assert "mylloc" not in d.codegen.text

    def test_inlining_all(self):
        # https://github.com/angr/angr/issues/4573
        bin_path = os.path.join(test_location, "x86_64", "inline_gym.so")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep(fail_fast=True)(
            f,
            cfg=cfg.model,
            inline_functions=f.functions_reachable(),
            options=[(angr.analyses.decompiler.decompilation_options.options[0], True)],
        )
        print_decompilation_result(d)

        assert "five" not in d.codegen.text
        assert "mylloc" not in d.codegen.text
        assert d.codegen.text.count("foo") == 1  # the recursive call
        assert "bar" not in d.codegen.text


if __name__ == "__main__":
    unittest.main()
