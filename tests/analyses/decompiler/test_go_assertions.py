#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location

from .test_go_decompiler import GoDecompilationTarget, go_binary

test_location = os.path.join(bin_location, "tests")


class _Bodies(GoDecompilationTarget):
    def body(self, name: str) -> str:
        """The function itself, without the type declarations printed ahead of it."""
        text = self.texts[name]
        return text[text.index("\nfunc ") + 1 :] if "\nfunc " in text else text


class PanickingAssertions(GoDecompilationTarget):
    """
    ``x.(T)`` whose holder is not an interface-typed variable: the sink block calling ``runtime.panicdottype*`` is
    dropped and the data-word reads after the check become the assertion.
    """

    FUNCS = ("main.viaCall", "main.viaField", "main.viaFieldPtr")

    def test_sinks_are_gone(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert "panicdottype" not in text and "panicnildottype" not in text, text
                assert "if " not in text.split("{", 1)[1], text

    def test_call_result_holder(self):
        # the any-typed call result is asserted directly (older renders held it in a variable first)
        assert re.search(r"\n    return (v2|main\.mk\(n\))\.\(int\)\n", self.texts["main.viaCall"]), self.texts[
            "main.viaCall"
        ]

    def test_memory_holder(self):
        # a non-pointer type reads the value behind the data word; a pointer-shaped one is the data word itself.
        # The holder is the interface field of the struct h points at (h.v); older renders spelled it (*h).
        assert re.search(r"return (\(\*h\)|h\.v)\.\(string\)\n", self.texts["main.viaField"]), self.texts[
            "main.viaField"
        ]
        assert re.search(r"return (\(\*h\)|h\.v)\.\(\*main\.holder\)\n", self.texts["main.viaFieldPtr"]), self.texts[
            "main.viaFieldPtr"
        ]


class TestAssertionsGo122(PanickingAssertions):
    BINARY = go_binary("go1.22.5", "asserts")


class TestAssertionsGo127(PanickingAssertions):
    BINARY = go_binary("go1.27.1", "asserts")


class TestTypeAssertCorpus(_Bodies):
    """
    ``h.outer.(marshalable)`` in crypto/internal/fips140/hmac.(*HMAC).Sum: the inline probe of the assertion's
    cache is dropped and the ``runtime.typeAssert`` behind it becomes the assertion, whose itab calls are method
    calls. The descriptors of the type switch ahead of it print as names, not as their first field.
    """

    BINARY = os.path.join(test_location, "x86_64", "go", "corpus", "age-keygen-v1.3.1-linux-amd64")
    FUNCS = ("crypto/internal/fips140/hmac.(*HMAC).Sum",)

    def test_assertion_to_interface(self):
        text = self.body(self.FUNCS[0])
        assert "marshalable := h.outer.(crypto/internal/fips140/hmac.marshalable)" in text, text
        assert "marshalable.UnmarshalBinary(" in text, text
        assert "typeAssert" not in text and ".Cache" not in text, text
        # descriptors print as names, not as their first field
        assert "&go:itab.*crypto/internal/fips140/sha256.Digest,hash.Hash" in text, text
        assert ".Inter" not in text and ".Size_" not in text, text


class CacheProbes(_Bodies):
    """errors.is: the inline cache probes ahead of runtime.typeAssert and runtime.interfaceSwitch are gone."""

    FUNCS = ("errors.is",)

    def test_no_probe_loops(self):
        text = self.body("errors.is")
        assert "Mask" not in text, text
        # the descriptors' caches are only ever passed to the runtime, never probed inline
        for line in text.splitlines():
            if "Cache" in line:
                assert "runtime.typeAssert(" in line or "runtime.interfaceSwitch(" in line, text


class TestCacheProbesGo122(CacheProbes):
    BINARY = go_binary("go1.22.5", "iface")


class TestCacheProbesGo127(CacheProbes):
    BINARY = go_binary("go1.27.1", "iface")


TYPESWITCH = {arch: go_binary("go1.27.1", "typeswitch", arch=arch) for arch in ("x86_64", "aarch64")}


@unittest.skipUnless(os.path.exists(TYPESWITCH["x86_64"]), "typeswitch binaries not built")
class TypeSwitches(_Bodies):
    """
    typeswitch.go: a hash-searched type switch with a multi-type case, assertions and a conversion to interfaces
    through runtime.typeAssert.
    """

    FUNCS = ("main.dispatch", "main.asReader", "main.toWriter")

    def test_type_switch_and_assertions(self):
        text = self.body("main.dispatch")
        assert re.search(r"switch x := \w+\.\(type\) \{", text), text
        m = re.search(r"case (main\.\w+, main\.\w+, main\.\w+):\n\s+main\.onKey\(", text)
        assert m and set(m.group(1).split(", ")) == {"main.KeyEvent", "main.RawEvent", "main.KeySequenceEvent"}, text
        assert re.search(r"case main\.MouseEvent:\n\s+main\.onMouse\(x\.btn, x\.mod, x\.x\)", text), text
        assert "Hash" not in text and "go:itab" not in text, text
        assert "reader, ok := v.(io.Reader)" in self.body("main.asReader"), self.body("main.asReader")
        assert "writer := io.Writer(w)" in self.body("main.toWriter"), self.body("main.toWriter")
        for name in ("main.asReader", "main.toWriter"):
            assert "typeAssert" not in self.body(name) and "Cache" not in self.body(name), self.body(name)


class TestTypeSwitchesAmd64(TypeSwitches):
    BINARY = TYPESWITCH["x86_64"]


@unittest.skipUnless(os.path.exists(TYPESWITCH["aarch64"]), "typeswitch binaries not built")
class TestTypeSwitchesArm64(TypeSwitches):
    # the hash search's unsigned compares stay arm64g_calculate_condition calls
    BINARY = TYPESWITCH["aarch64"]


@unittest.skipUnless(os.path.exists(TYPESWITCH["x86_64"] + "_stripped"), "typeswitch binaries not built")
class TestTypeSwitchesStripped(_Bodies):
    """Without DWARF, the two words compared against itabs (or handed to typeAssert) are one interface parameter."""

    BINARY = TYPESWITCH["x86_64"] + "_stripped"
    FUNCS = ("main.dispatch", "main.asReader")
    WARMUP_PASSES = 1

    def test_interface_parameters(self):
        assert self.header(self.body("main.dispatch")).startswith("func main.dispatch(a0 main.Event)")
        assert "case main.MouseEvent:" in self.body("main.dispatch"), self.body("main.dispatch")
        assert re.search(r"func main\.asReader\(\w+ any\)", self.body("main.asReader")), self.body("main.asReader")
        assert ", ok := " in self.body("main.asReader") and ".(io.Reader)" in self.body("main.asReader")


if __name__ == "__main__":
    unittest.main()
