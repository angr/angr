#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Go runtime calls for maps, channels, goroutines, defer and panic/recover come back as Go statements."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from tests.analyses.decompiler.test_go_decompiler import GoDecompilationTarget, go_binary

RUNTIME_MAP_CALLS = ("runtime.mapaccess", "runtime.mapassign", "runtime.mapdelete", "runtime.makemap(")
RUNTIME_CHAN_CALLS = ("runtime.chansend", "runtime.chanrecv", "runtime.closechan", "runtime.makechan")
RUNTIME_GO_CALLS = (
    "runtime.newproc",
    "runtime.deferproc",
    "runtime.deferreturn",
    "runtime.gopanic",
    "runtime.gorecover",
)


def body(text: str) -> str:
    return text.split("{", 1)[1]


class MapIdioms(GoDecompilationTarget):
    FUNCS = ("main.lookup", "main.lookupOk", "main.store", "main.remove", "main.byInt")

    def test_no_raw_map_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in RUNTIME_MAP_CALLS:
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_lookup_is_an_index_expression(self):
        assert re.search(r"return \w+\[\w+\]$", self.texts["main.lookup"], re.MULTILINE)
        assert re.search(r"return \w+\[\w+\]$", self.texts["main.byInt"], re.MULTILINE)

    def test_lookup_ok_is_a_tuple_valued_index(self):
        text = self.texts["main.lookupOk"]
        m = re.search(r"^\s+(\w+), ok :?= \w+\[\w+\]$", text, re.MULTILINE)
        assert m, text
        assert re.search(rf"return {m.group(1)}, ok$", text, re.MULTILINE), text
        assert "(int, bool)" in text

    def test_store_is_an_index_assignment(self):
        assert re.search(r"^\s+\w+\[\w+\] = \w+$", self.texts["main.store"], re.MULTILINE)

    def test_delete(self):
        assert re.search(r"^\s+delete\(\w+, \w+\)$", self.texts["main.remove"], re.MULTILINE)


class MapBuiltinIdioms(GoDecompilationTarget):
    FUNCS = ("main.counts", "main.keys", "main.total")

    def test_make_map_and_increment(self):
        text = self.texts["main.counts"]
        assert re.search(r"= make\(map\[string\]int\)$", text, re.MULTILINE), text
        assert re.search(r"^\s+(\w+)\[(\*?\w+)\] = \1\[\2\] \+ 1$", text, re.MULTILINE), text

    def test_len_of_map(self):
        assert re.search(r"len\(m\)", self.texts["main.keys"])

    def test_range_over_map(self):
        # mapiterinit / it.key != nil / mapiternext is a range loop; the element read is the range value
        text = self.texts["main.total"]
        assert re.search(r"^\s+for _, v :?= range m \{$", text, re.MULTILINE), text
        assert re.search(r"^\s+\w+ \+= v$", text, re.MULTILINE), text
        for gone in ("mapiterinit", "mapiternext", "duffzero", "hiter", "unsupported"):
            assert gone not in text[text.index("func main.total") :], (gone, text)
        # the key is bound only when it is read whole (go1.24+ types the iterator's key pointer)
        assert re.search(r"^\s+for (_|k) :?= range m \{$", self.texts["main.keys"], re.MULTILINE), self.texts[
            "main.keys"
        ]


class ChannelIdioms(GoDecompilationTarget):
    FUNCS = ("main.producer", "main.recvOne", "main.consume", "main.pick")

    def test_no_raw_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in RUNTIME_CHAN_CALLS:
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_send_and_close(self):
        text = self.texts["main.producer"]
        assert re.search(r"^\s+\w+ <- \w+$", text, re.MULTILINE), text
        assert re.search(r"^\s+close\(\w+\)$", text, re.MULTILINE), text

    def test_select(self):
        text = self.texts["main.pick"]
        body = text[text.index("func main.pick") :]
        assert "select {" in body, body
        assert re.search(r"^\s+case v := <-b:\n\s+return v \+ 100$", body, re.MULTILINE), body
        assert re.search(r"^\s+case v := <-a:\n\s+return v$", body, re.MULTILINE), body
        for gone in ("selectgo", "scase", "&"):
            assert gone not in body, (gone, body)

    def test_counting_loop_is_clean(self):
        # spills and phi copies around the send are gone; the increment is the loop's iterator
        text = self.texts["main.producer"]
        assert re.search(r"^\s+for \w+ := 0; \w+ > \w+; \w+\+\+ \{$", text, re.MULTILINE), text
        assert re.search(r"^\s+ch <- \w+$", text, re.MULTILINE), text
        body = text[text.index("func main.producer") :]
        assert body.count("=") <= 3, body

    def test_receive_with_ok(self):
        text = self.texts["main.recvOne"]
        assert re.search(r"^\s+v, ok :?= <-\w+$", text, re.MULTILINE), text
        assert re.search(r"return v, ok$", text, re.MULTILINE), text

    def test_receive_in_loop_condition(self):
        # the comma-ok receive guarding a loop is a range over the channel
        text = self.texts["main.consume"]
        assert re.search(r"^\s+for v :?= range ch \{$", text, re.MULTILINE), text
        body = text[text.index("func main.consume") :]
        assert "= <-" not in body and "break" not in body, body
        # the accumulator survives the phi copies: one += and a return of the same variable
        m = re.search(r"^\s+(\w+) \+= v$", body, re.MULTILINE)
        assert m and f"return {m.group(1)}" in body, body


class GoroutineIdioms(GoDecompilationTarget):
    FUNCS = ("main.runAll", "main.main")

    def test_no_raw_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in (*RUNTIME_CHAN_CALLS, "runtime.newproc"):
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_go_statement_on_closure(self):
        assert re.search(r"^\s+go \w+\(\)$", self.texts["main.runAll"], re.MULTILINE)
        assert re.search(r"^\s+go \w+\(\)$", self.texts["main.main"], re.MULTILINE)

    def test_make_chan_and_send_constant(self):
        text = self.texts["main.main"]
        assert re.search(r"= make\(chan int, 4\)$", text, re.MULTILINE), text
        assert re.search(r"^\s+\w+ <- 1$", text, re.MULTILINE), text


class DeferIdioms(GoDecompilationTarget):
    FUNCS = ("main.(*counter).inc", "main.safeDiv", "main.runAll.func1")

    def test_no_raw_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in RUNTIME_GO_CALLS:
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_open_coded_defer(self):
        text = self.texts["main.(*counter).inc"]
        assert re.search(r"^\s+defer main\.\(\*counter\)\.inc\.deferwrap1\(\)$", text, re.MULTILINE), text
        # the deferBits byte and the inline call at the exit are gone
        assert not re.search(r"^\s+\w+\(\w+, \w+, \w+", body(text), re.MULTILINE), text
        assert "defer main.safeDiv.func1()" in self.texts["main.safeDiv"]
        assert "defer main.runAll.func1.deferwrap1()" in self.texts["main.runAll.func1"]


class PanicIdioms(GoDecompilationTarget):
    FUNCS = ("main.safeDiv.func1", "main.mustPositive")

    def test_no_raw_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in RUNTIME_GO_CALLS:
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_recover(self):
        assert re.search(r"= recover\(\)$", self.texts["main.safeDiv.func1"], re.MULTILINE)

    def test_panic_with_string_literal(self):
        assert re.search(r'^\s+panic\("not positive"\)$', self.texts["main.mustPositive"], re.MULTILINE)


MAPS_122 = go_binary("go1.22.5", "maps")
MAPS_127 = go_binary("go1.27.1", "maps")
CONC_122 = go_binary("go1.22.5", "conc")
CONC_127 = go_binary("go1.27.1", "conc")


class TestMapsGo122(MapIdioms):
    BINARY = MAPS_122


class TestMapsGo127(MapIdioms):
    BINARY = MAPS_127


class TestMapBuiltinsGo122(MapBuiltinIdioms):
    BINARY = MAPS_122


class TestMapBuiltinsGo127(MapBuiltinIdioms):
    BINARY = MAPS_127


class TestChannelsGo122(ChannelIdioms):
    BINARY = CONC_122


class TestChannelsGo127(ChannelIdioms):
    BINARY = CONC_127


class TestGoroutinesGo122(GoroutineIdioms):
    BINARY = CONC_122


class TestGoroutinesGo127(GoroutineIdioms):
    BINARY = CONC_127


class TestDeferGo122(DeferIdioms):
    BINARY = CONC_122


class TestDeferGo127(DeferIdioms):
    BINARY = CONC_127


class TestPanicGo122(PanicIdioms):
    BINARY = CONC_122


class TestPanicGo127(PanicIdioms):
    BINARY = CONC_127


if __name__ == "__main__":
    unittest.main()
