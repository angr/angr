#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
Map creation: makemap calls become make(map[K]V[, hint]) once the map type is known, and maps the compiler builds on
the stack (go1.24+ swiss maps that do not escape) fold back into make() as well.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location

from .test_go_decompiler import GoDecompilationTarget, go_binary

test_location = os.path.join(bin_location, "tests")

AGE_KEYGEN = os.path.join(test_location, "x86_64", "go", "corpus", "age-keygen-v1.3.1-linux-amd64")
AGE_DARWIN_ARM64 = os.path.join(test_location, "aarch64", "go", "corpus", "age-v1.3.1-darwin-arm64")


def _no_stack_map_setup(text: str) -> None:
    assert "0x8080808080808080" not in text, text
    assert "runtime.rand" not in text, text
    assert "memset" not in text, text
    assert "runtime.makemap" not in text, text


class TestStackMapLiteralGo127Inlined(GoDecompilationTarget):
    """
    Two non-escaping map literals whose header words are 16-byte stack variables: the hash seed is an Insert into
    the header's first two words, and len(m) reads the first word of that variable.
    """

    BINARY = go_binary("go1.27.1", "strvals_inlined")
    FUNCS = ("main.main",)
    CALL_TREE_DEPTH = 0

    def test_stack_map_literal(self):
        text = self.texts["main.main"]
        names = re.search(r"(\w+) :?= make\(map\[int\]string\)$", text, re.MULTILINE)
        items = re.search(r"(\w+) :?= make\(map\[int\]\[\]int\)$", text, re.MULTILINE)
        assert names and items, text
        assert re.search(rf"main\.byName\({names.group(1)}, ", text), text
        assert re.search(rf"main\.byItems\({items.group(1)}, ", text), text
        assert f"len({names.group(1)}), len({items.group(1)}))" in text, text
        _no_stack_map_setup(text)


class TestHintedStackMapArm64Corpus(GoDecompilationTarget):
    """
    make(map[string]bool, len(env)) that does not escape: the header is zeroed on the stack and, under
    `if hint <= 8`, so is one group that dirPtr points at; then makemap(type, hint, &header).
    """

    BINARY = AGE_DARWIN_ARM64
    FUNCS = ("os/exec.dedupEnvCase",)
    CALL_TREE_DEPTH = 0

    def test_hinted_stack_map(self):
        text = self.texts["os/exec.dedupEnvCase"]
        assert re.search(r"\w+ :?= make\(map\[string\]bool, len\(env\)\)$", text, re.MULTILINE), text
        _no_stack_map_setup(text)
        assert "<= 8" not in text, text


class TestMakemapSmallTypesAmd64Corpus(GoDecompilationTarget):
    """makemap_small() carries no descriptor: the map type comes from where the new map is stored."""

    BINARY = AGE_KEYGEN
    FUNCS = ("regexp/syntax.(*parser).checkSize", "regexp/syntax.initAliases")
    CALL_TREE_DEPTH = 0

    def test_makemap_small_types(self):
        self.run_checks()

    def check_typed_field_through_spilled_receiver(self):
        # p.size = make(...): the receiver reaches the store through a stack spill and a loop phi
        text = self.texts["regexp/syntax.(*parser).checkSize"]
        assert re.search(r"\.size = make\(map\[\*regexp/syntax\.Regexp\]int64\)$", text, re.MULTILINE), text
        assert "runtime.makemap" not in text, text

    def check_global_named_by_map_operations(self):
        # the perlGroup/posixGroup alias globals are filled by mapassign calls that name the map type
        text = self.texts["regexp/syntax.initAliases"]
        assert len(re.findall(r" = make\(map\[string\]string\)$", text, re.MULTILINE)) == 2, text
        assert "runtime.makemap" not in text, text


# Not in the binaries repository yet: tests_src/go/mapmake.go, built like the other -gcflags=all=-l programs
MAPMAKE_AMD64 = go_binary("go1.27.1", "mapmake")
MAPMAKE_ARM64 = go_binary("go1.27.1", "mapmake", arch="aarch64")


class MapMakeChecks:
    FUNCS = ("main.uniq", "main.counts", "main.boxed", "main.newSet", "main.newRegistry")
    CALL_TREE_DEPTH = 0
    texts: dict[str, str]

    def test_map_make(self):
        self.run_checks()  # type: ignore[attr-defined]

    def check_literal_with_zero_size_values(self):
        # map[string]struct{}{}: the slot pads the zero-size value to 24 bytes, so the group is 200 bytes
        text = self.texts["main.uniq"]
        m = re.search(r"(\w+) :?= make\(map\[string\]struct \{\}\)$", text, re.MULTILINE)
        assert m, text
        assert re.search(rf"{m.group(1)}\[[^\]]+\] = struct\{{\}}\{{\}}$", text, re.MULTILINE), text
        _no_stack_map_setup(text)

    def check_hinted(self):
        text = self.texts["main.counts"]
        assert re.search(r"\w+ :?= make\(map\[string\]int, len\(xs\)\)$", text, re.MULTILINE), text
        _no_stack_map_setup(text)

    def check_boxed(self):
        # any(make(map[string]bool)): the interface's type word names the map type
        assert "return make(map[string]bool)\n" in self.texts["main.boxed"], self.texts["main.boxed"]

    def check_named_result(self):
        assert "return make(main.set)\n" in self.texts["main.newSet"], self.texts["main.newSet"]

    def check_typed_field(self):
        text = self.texts["main.newRegistry"]
        assert re.search(r"\.items = make\(map\[string\]int\)$", text, re.MULTILINE), text


@unittest.skipUnless(os.path.exists(MAPMAKE_AMD64), "mapmake is not in the binaries repository")
class TestMapMakeGo127(MapMakeChecks, GoDecompilationTarget):
    BINARY = MAPMAKE_AMD64


@unittest.skipUnless(os.path.exists(MAPMAKE_ARM64), "mapmake is not in the binaries repository")
class TestMapMakeGo127Arm64(MapMakeChecks, GoDecompilationTarget):
    BINARY = MAPMAKE_ARM64


if __name__ == "__main__":
    unittest.main()
