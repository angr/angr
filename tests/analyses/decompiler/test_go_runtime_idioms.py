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
        # the goroutine runs a closure record: the closure body with its captured variables
        assert re.search(
            r"^\s+go main\.runAll\.func1\{X0: \w+, X1: [^}]+\}\(\)$", self.texts["main.runAll"], re.MULTILINE
        )
        assert re.search(r"^\s+go main\.main\.gowrap1\{X0: \w+\}\(\)$", self.texts["main.main"], re.MULTILINE)

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
        # stack closure records carry their captures (&err; the WaitGroup the wrapper calls Done on)
        assert re.search(r"defer main\.safeDiv\.func1\{cap_0: &\w+\}\(\)", self.texts["main.safeDiv"])
        assert re.search(r"defer main\.runAll\.func1\.deferwrap1\{cap_0: [\w.]+\}\(\)", self.texts["main.runAll.func1"])


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
ATOMICS_ARM64_127 = go_binary("go1.27.1", "atomics", arch="aarch64")
ATOMICS_AMD64_127 = go_binary("go1.27.1", "atomics")


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


class AtomicIdioms(GoDecompilationTarget):
    """
    sync/atomic intrinsics: the compare-and-swap loops the lifter models (arm64's LSE instructions, x86's lock xadd,
    xchg and lock cmpxchg), arm64's arm64HasATOMICS dispatch, fault exits and fences all fold back into the calls the
    source made.
    """

    FUNCS = (
        "main.bump",
        "main.bump64",
        "main.release",
        "main.tryLock",
        "main.lock",
        "main.unlock",
        "main.peek",
        "main.total",
        "main.swap",
        "main.setFlag",
        "main.clearFlag",
    )

    def test_nothing_lifted_leaks(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                body = text[text.index("func ") :]
                for leak in ("unsupported instruction", "goto", "arm64HasATOMICS", "CasCmp", "& 3 != 0"):
                    assert leak not in body, body

    def test_add_returns_the_new_value(self):
        # the fetch-and-add returns the old value and the compiler adds the delta back; atomic.Add returns the sum
        assert re.search(r"^\s+return atomic\.AddInt32\(&c\.hits, d\)$", self.texts["main.bump"], re.MULTILINE)
        assert "return atomic.AddInt64(&c.total, d)" in self.texts["main.bump64"]
        body = self.texts["main.release"]
        m = re.search(r"^\s+(\w+) := atomic\.AddInt32\(&c\.hits, -1\)$", body, re.MULTILINE)
        assert m, body
        assert f"if {m.group(1)} == 0" in body or f"if {m.group(1)} != 0" in body, body

    def test_compare_and_swap_is_the_bool(self):
        # the flag materialization folds into the condition: no `v = 0 / v = 1` diamond, no `v & 1`
        assert "return atomic.CompareAndSwapInt32(&c.state, 0, 1)" in self.texts["main.tryLock"]
        body = self.texts["main.lock"]
        assert "if atomic.CompareAndSwapInt32(&c.state, 0, 1) {" in body, body
        assert body.count("atomic.CompareAndSwapInt32(") == 2 and "& 1" not in body, body

    def test_loads_stores_and_swaps(self):
        assert "c.state = 0" in self.texts["main.unlock"]
        assert "return c.hits" in self.texts["main.peek"]
        assert "return c.total" in self.texts["main.total"]
        assert "return atomic.SwapInt32(&c.state, v)" in self.texts["main.swap"]


class TestAtomicsArm64Go127(AtomicIdioms):
    BINARY = ATOMICS_ARM64_127

    def test_masks(self):
        assert "return atomic.OrUint32(&c.flags, bit)" in self.texts["main.setFlag"]
        assert "return atomic.AndUint32(&c.flags, ^bit)" in self.texts["main.clearFlag"]


class TestAtomicsAmd64Go127(AtomicIdioms):
    BINARY = ATOMICS_AMD64_127

    def test_masks(self):
        # the amd64 compiler writes And/Or out as a compare-and-swap loop, which stays one
        for name in ("main.setFlag", "main.clearFlag"):
            body = self.texts[name]
            assert "for {" in body and "atomic_compare_exchange(" in body, body


class BoxedValueIdioms(GoDecompilationTarget):
    """
    Interface values built in place: bytes boxed through runtime.staticuint64s, convT* results, an eface carried over
    from a call result, and the variadic ``...any`` array of (type word, data word) pairs on the stack.
    """

    FUNCS = ("main.main",)

    def test_no_spelled_out_interface_values(self):
        text = self.texts["main.main"]
        for gone in ("staticuint64s", "any{tab:", "[]any{", "convT"):
            assert gone not in text, (gone, text)

    def test_bools_and_tuple_results_are_spread(self):
        text = self.texts["main.main"]
        assert re.search(r"fmt\.Println\(.+ != nil, .+ != nil\)$", text, re.MULTILINE), text
        assert re.search(r"fmt\.Println\(\w+, ok\)$", text, re.MULTILINE), text


class TestBoxedValuesAmd64Go127(BoxedValueIdioms):
    BINARY = go_binary("go1.27.1", "typeswitch")

    def test_pointer_boxed_into_any(self):
        text = self.texts["main.main"]
        assert 'fmt.Println(main.asReader(strings.NewReader("x")) != nil, main.toWriter(os.Stdout) != nil)' in text


class TestBoxedValuesI386Go127(BoxedValueIdioms):
    BINARY = go_binary("go1.27.1", "typeswitch", arch="i386")


class TestBoxedSmallIntStrippedGo127(GoDecompilationTarget):
    # no runtime.staticuint64s symbol: the table is located by shape
    BINARY = go_binary("go1.27.1", "typeswitch_stripped")
    FUNCS = ("main.main",)

    def test_small_int_constant(self):
        text = self.texts["main.main"]
        assert re.search(r'\w+\["b"\] = 1$', text, re.MULTILINE), text
        assert "staticuint64s" not in text, text


class TestBoxedByteI386Go127(GoDecompilationTarget):
    # &runtime.staticuint64s[b] for a bool result read back from the stack
    BINARY = go_binary("go1.27.1", "atomics", arch="i386")
    FUNCS = ("main.main",)

    def test_bool_through_staticuint64s(self):
        text = self.texts["main.main"]
        assert "staticuint64s" not in text, text
        assert text.count("fmt.Println(") == 3, text
