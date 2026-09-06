# pylint: disable=missing-class-docstring,no-self-use
"""
Regression on real-world stripped Go builds (gors-bins corpus): no DWARF, no symbol table, names from the pclntab.
Each test decompiles one function on a scoped CFG so it stays within a few seconds.
"""

from __future__ import annotations

import os
import re
import unittest

import cle

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

LINUX = os.path.join(test_location, "x86_64", "go", "corpus", "age-keygen-v1.3.1-linux-amd64")
DARWIN = os.path.join(test_location, "aarch64", "go", "corpus", "age-v1.3.1-darwin-arm64")


class _Corpus(unittest.TestCase):
    """One scoped CFG per binary (built once per class) and one decompilation per test."""

    PATH = ""
    FUNCS: tuple[str, ...] = ()
    proj = None
    cfg = None
    addrs: dict[str, int] = {}

    @classmethod
    def setUpClass(cls):
        loader = cle.Loader(cls.PATH, auto_load_libs=False)
        cls.addrs = {}
        for name in cls.FUNCS:
            sym = loader.find_symbol(name)
            assert sym is not None, f"{name} not in {cls.PATH}"
            cls.addrs[name] = sym.rebased_addr
        first, *rest = cls.addrs.values()
        cls.proj, cls.cfg = load_project_with_scoped_cfg(cls.PATH, first, extra_func_addrs=rest, call_tree_depth=1)

    def decompile(self, name: str) -> str:
        addr = self.addrs[name]
        dec = self.proj.analyses.Decompiler(
            self.proj.kb.functions[addr], cfg=self.cfg.model, flavor="go", fail_fast=True
        )
        assert dec.codegen is not None and dec.codegen.text
        return dec.codegen.text


class TestGoCorpusLinuxAmd64(_Corpus):
    PATH = LINUX
    FUNCS = ("main.convert", "main.generate")

    def test_convert_type_switch_and_print(self):
        text = self.decompile("main.convert")
        # the interface type switch on the parsed identity is recovered, with the concrete cases named
        assert re.search(r"switch \w+ := \w+\.\(type\) \{", text)
        assert "case *filippo.io/age.X25519Identity:" in text
        # the print folds into one call with its format string
        assert re.search(r'fmt\.Fprintf\(.*"%s\\n"', text)
        # GC write barriers and bounds-check sinks are gone
        assert "gcWriteBarrier" not in text and "panicBounds" not in text

    def test_generate_no_runtime_leftovers(self):
        text = self.decompile("main.generate")
        assert "gcWriteBarrier" not in text and "wbMove" not in text


class TestGoCorpusDarwinArm64(_Corpus):
    PATH = DARWIN
    FUNCS = ("filippo.io/age.(*HybridRecipient).String", "filippo.io/age.(*ScryptIdentity).Unwrap")

    def test_method_receiver_and_sinks(self):
        text = self.decompile("filippo.io/age.(*HybridRecipient).String")
        # Mach-O Go builds get the runtime's non-returning seeding: no bounds-panic sinks in the output
        assert "panicBounds" not in text
        # the receiver comes from the type descriptors' method table
        assert re.search(r"^func \(recv \*filippo\.io/age\.HybridRecipient\) String\(\) string \{", text, re.MULTILINE)

    def test_unwrap_ranges_and_results(self):
        text = self.decompile("filippo.io/age.(*ScryptIdentity).Unwrap")
        assert "panicBounds" not in text
        assert re.search(
            r"^func \(recv \*filippo\.io/age\.ScryptIdentity\) Unwrap\(a1 \[\]\*filippo\.io/age\.Stanza\) \(\[\]uint8, error\)",
            text,
            re.MULTILINE,
        )
        assert re.search(r"for \w+ := 0; len\(a1\) > \w+; \w+\+\+ \{", text)


if __name__ == "__main__":
    unittest.main()
