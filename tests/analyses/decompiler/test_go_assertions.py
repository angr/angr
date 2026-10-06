#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, TargetChecks, go_binary
from .test_go_runtime_idioms import BoxedValueIdioms


def body_of(text: str) -> str:
    """The function itself, without the type declarations printed ahead of it."""
    return text[text.index("\nfunc ") + 1 :] if "\nfunc " in text else text


class PanickingAssertions(TargetChecks):
    """
    ``x.(T)`` whose holder is not an interface-typed variable: the sink block calling ``runtime.panicdottype*`` is
    dropped and the data-word reads after the check become the assertion.
    """

    FUNCS = ("main.viaCall", "main.viaField", "main.viaFieldPtr")

    def test_panicking_assertions(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert "panicdottype" not in text and "panicnildottype" not in text, text
                assert "if " not in text.split("{", 1)[1], text
        # the any-typed call result is asserted directly (older renders held it in a variable first)
        assert re.search(r"\n    return (v2|main\.mk\(n\))\.\(int\)\n", self.texts["main.viaCall"]), self.texts[
            "main.viaCall"
        ]
        # a non-pointer type reads the value behind the data word; a pointer-shaped one is the data word itself.
        # The holder is the interface field of the struct h points at (h.v); older renders spelled it (*h).
        assert re.search(r"return (\(\*h\)|h\.v)\.\(string\)\n", self.texts["main.viaField"]), self.texts[
            "main.viaField"
        ]
        assert re.search(r"return (\(\*h\)|h\.v)\.\(\*main\.holder\)\n", self.texts["main.viaFieldPtr"]), self.texts[
            "main.viaFieldPtr"
        ]


class TestAssertionsGo122(PanickingAssertions, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "asserts")


class TestAssertionsGo127(PanickingAssertions, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "asserts")


class CacheProbes(TargetChecks):
    """errors.is: the inline cache probes ahead of runtime.typeAssert and runtime.interfaceSwitch are gone."""

    FUNCS = ("errors.is",)

    def check_no_probe_loops(self):
        text = body_of(self.texts["errors.is"])
        assert "Mask" not in text, text
        # the descriptors' caches are only ever passed to the runtime, never probed inline
        for line in text.splitlines():
            if "Cache" in line:
                assert "runtime.typeAssert(" in line or "runtime.interfaceSwitch(" in line, text


class TestIfaceGo122(CacheProbes, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "iface")
    FUNCS = (
        "main.describe",
        "main.box",
        "main.unbox",
        "main.asSquare",
        "main.wrap",
        "main.report",
        "main.kind",
        *CacheProbes.FUNCS,
    )

    def test_iface(self):
        self.run_checks()

    def check_interfaces(self):
        go_types = self.proj.kb.go_types
        assert go_types.name_at(go_types.addr_of("int")) == "int"
        assert go_types.itab_at(self.proj.loader.find_symbol("go:itab.*main.Square,main.Shape").rebased_addr) == (
            "main.Shape",
            "*main.Square",
        )

        describe = self.texts["main.describe"]
        assert re.search(r"= s\.Name\(\)$", describe, re.MULTILINE), describe
        assert "strconv.Itoa(s.Area())" in describe
        assert ".tab[" not in describe

        kind = self.texts["main.kind"]
        kind = kind[kind.index("func main.kind") :]
        assert "switch x := v.(type) {" in kind, kind
        assert re.search(r"case string:\n\s+return \"string:\" \+ x$", kind, re.MULTILINE), kind
        assert "case int:" in kind and "strconv.Itoa(x)" in kind
        # the interface case comes from the InterfaceSwitch descriptor; its method call goes through the itab
        assert re.search(r"case main\.Shape:\n\s+return \"shape:\" \+ x\.Name\(\)$", kind, re.MULTILINE), kind
        for gone in ("interfaceSwitch", "Hash", ".tab[", "goto", "&type:"):
            assert gone not in kind, (gone, kind)

        unbox = self.texts["main.unbox"]
        assert "n, ok := v.(int)" in unbox and "if !ok {" in unbox and "return n" in unbox, unbox
        assert "return -1" in unbox
        assert "return s.(*main.Square)" in self.texts["main.asSquare"]
        for name in ("main.unbox", "main.asSquare"):
            assert (
                ".tab" not in self.texts[name]
                and ".data" not in self.texts[name]
                and "panicdottype" not in self.texts[name]
            )

        # a pointer walking the slice becomes the range value; calls through its itab are method calls, and the
        # ...any array on the stack is spread into the call
        report = self.texts["main.report"]
        report = report[report.index("func main.report") :]
        assert re.search(r"for \w+, x := range shapes \{", report), report
        assert re.search(
            r'fmt\.Fprintf\(w, "%d: %s area=%d\\n", \w+, x\.Name\(\), x\.Area\(\)\)$', report, re.MULTILINE
        ), report
        for gone in ("field_", ".ptr", "string{", "len(shapes)"):
            assert gone not in report, (gone, report)

        # a value converted to an interface is the value itself
        assert "return n" in self.texts["main.box"]
        # an interface converted to any through the nil-checked itab.Type load
        assert 'return fmt.Errorf("wrapped: %w", err)' in self.texts["main.wrap"]
        for text in (self.texts["main.box"], self.texts["main.wrap"], report):
            assert "convT" not in text and "[]any{" not in text and "&type:" not in text, text


class TestCacheProbesGo127(CacheProbes, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "iface")

    def test_iface(self):
        self.run_checks()


class TypeSwitches(TargetChecks):
    """
    typeswitch.go: a hash-searched type switch with a multi-type case, assertions and a conversion to interfaces
    through runtime.typeAssert.
    """

    FUNCS = ("main.dispatch", "main.asReader", "main.toWriter")

    def check_type_switch_and_assertions(self):
        text = body_of(self.texts["main.dispatch"])
        assert re.search(r"switch x := \w+\.\(type\) \{", text), text
        m = re.search(r"case (main\.\w+, main\.\w+, main\.\w+):\n\s+main\.onKey\(", text)
        assert m and set(m.group(1).split(", ")) == {"main.KeyEvent", "main.RawEvent", "main.KeySequenceEvent"}, text
        assert re.search(r"case main\.MouseEvent:\n\s+main\.onMouse\(x\.btn, x\.mod, x\.x\)", text), text
        assert "Hash" not in text and "go:itab" not in text, text
        as_reader, to_writer = body_of(self.texts["main.asReader"]), body_of(self.texts["main.toWriter"])
        assert "reader, ok := v.(io.Reader)" in as_reader, as_reader
        assert "writer := io.Writer(w)" in to_writer, to_writer
        for text in (as_reader, to_writer):
            assert "typeAssert" not in text and "Cache" not in text, text


class TestTypeswitchAmd64Go127(TypeSwitches, BoxedValueIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "typeswitch")
    FUNCS = (*TypeSwitches.FUNCS, *BoxedValueIdioms.FUNCS, "fmt.(*pp).fmtComplex")

    def test_typeswitch(self):
        self.run_checks()

    def check_pointer_boxed_into_any(self):
        text = self.texts["main.main"]
        assert 'fmt.Println(main.asReader(strings.NewReader("x")) != nil, main.toWriter(os.Stdout) != nil)' in text

    def check_signed_division_by_two(self):
        text = self.texts["fmt.(*pp).fmtComplex"]
        assert re.search(r"^\s+\w+ := size / 2$", text, re.MULTILINE), text
        assert ">> 63" not in text, text


class TestTypeSwitchesArm64(TypeSwitches, GoDecompilationTarget):
    # the hash search's unsigned compares stay arm64g_calculate_condition calls
    BINARY = go_binary("go1.27.1", "typeswitch", arch="aarch64")

    def test_typeswitch(self):
        self.run_checks()


class TestTypeSwitchesStrippedGo127(GoDecompilationTarget):
    """Without DWARF, the two words compared against itabs (or handed to typeAssert) are one interface parameter."""

    BINARY = go_binary("go1.27.1", "typeswitch_stripped")
    FUNCS = ("main.dispatch", "main.asReader")
    WARMUP_PASSES = 1

    def test_interface_parameters(self):
        dispatch, as_reader = body_of(self.texts["main.dispatch"]), body_of(self.texts["main.asReader"])
        assert self.header(dispatch).startswith("func main.dispatch(a0 main.Event)")
        assert "case main.MouseEvent:" in dispatch, dispatch
        assert re.search(r"func main\.asReader\(\w+ any\)", as_reader), as_reader
        assert ", ok := " in as_reader and ".(io.Reader)" in as_reader


class TestBoxedSmallIntStrippedGo127(GoDecompilationTarget):
    # kept apart from the warm-up class above: decompiled together, each function sees what the other taught
    BINARY = go_binary("go1.27.1", "typeswitch_stripped")
    FUNCS = ("main.main",)

    def test_small_int_constant(self):
        # no runtime.staticuint64s symbol: the table is located by shape
        text = self.texts["main.main"]
        assert re.search(r'\w+\["b"\] = 1$', text, re.MULTILINE), text
        assert "staticuint64s" not in text, text


if __name__ == "__main__":
    unittest.main()
