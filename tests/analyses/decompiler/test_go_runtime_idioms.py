#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Go runtime calls for maps, channels, goroutines, defer and panic/recover come back as Go statements."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from angr.analyses.decompiler.structured_codegen.go import GoConstant, StringLiteralLengths
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from angr.sim_type import SimTypeChar, SimTypeLongLong, SimTypePointer
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


def assert_no_calls(texts: dict[str, str], funcs, calls):
    for name in funcs:
        for call in calls:
            assert call not in texts[name], f"{call} survived in {name}:\n{texts[name]}"


class MapIdioms:
    FUNCS = (
        "main.lookup",
        "main.lookupOk",
        "main.store",
        "main.remove",
        "main.byInt",
        "main.counts",
        "main.keys",
        "main.total",
    )

    def check_map_idioms(self):
        assert_no_calls(self.texts, MapIdioms.FUNCS, RUNTIME_MAP_CALLS)
        # lookups are index expressions, the comma-ok form a tuple-valued one
        assert re.search(r"return \w+\[\w+\]$", self.texts["main.lookup"], re.MULTILINE)
        assert re.search(r"return \w+\[\w+\]$", self.texts["main.byInt"], re.MULTILINE)
        text = self.texts["main.lookupOk"]
        m = re.search(r"^\s+(\w+), ok :?= \w+\[\w+\]$", text, re.MULTILINE)
        assert m, text
        assert re.search(rf"return {m.group(1)}, ok$", text, re.MULTILINE), text
        assert "(int, bool)" in text
        assert re.search(r"^\s+\w+\[\w+\] = \w+$", self.texts["main.store"], re.MULTILINE)
        assert re.search(r"^\s+delete\(\w+, \w+\)$", self.texts["main.remove"], re.MULTILINE)

        text = self.texts["main.counts"]
        assert re.search(r"= make\(map\[string\]int\)$", text, re.MULTILINE), text
        assert re.search(r"^\s+(\w+)\[(\*?\w+)\] = \1\[\2\] \+ 1$", text, re.MULTILINE), text
        assert re.search(r"len\(m\)", self.texts["main.keys"])
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


class ConcIdioms:
    CHANNEL_FUNCS = ("main.producer", "main.recvOne", "main.consume", "main.pick")
    FUNCS = (*CHANNEL_FUNCS, "main.runAll", "main.main", "main.(*counter).inc", "main.safeDiv", "main.runAll.func1")
    FUNCS += ("main.safeDiv.func1", "main.mustPositive")

    def check_channels(self):
        assert_no_calls(self.texts, self.CHANNEL_FUNCS, RUNTIME_CHAN_CALLS)
        text = self.texts["main.producer"]
        assert re.search(r"^\s+\w+ <- \w+$", text, re.MULTILINE), text
        assert re.search(r"^\s+close\(\w+\)$", text, re.MULTILINE), text
        # spills and phi copies around the send are gone; the increment is the loop's iterator
        assert re.search(r"^\s+for \w+ := 0; \w+ > \w+; \w+\+\+ \{$", text, re.MULTILINE), text
        assert re.search(r"^\s+ch <- \w+$", text, re.MULTILINE), text
        body = text[text.index("func main.producer") :]
        assert body.count("=") <= 3, body

        text = self.texts["main.pick"]
        body = text[text.index("func main.pick") :]
        assert "select {" in body, body
        assert re.search(r"^\s+case v := <-b:\n\s+return v \+ 100$", body, re.MULTILINE), body
        assert re.search(r"^\s+case v := <-a:\n\s+return v$", body, re.MULTILINE), body
        for gone in ("selectgo", "scase", "&"):
            assert gone not in body, (gone, body)

        text = self.texts["main.recvOne"]
        assert re.search(r"^\s+v, ok :?= <-\w+$", text, re.MULTILINE), text
        assert re.search(r"return v, ok$", text, re.MULTILINE), text

        # the comma-ok receive guarding a loop is a range over the channel
        text = self.texts["main.consume"]
        assert re.search(r"^\s+for v :?= range ch \{$", text, re.MULTILINE), text
        body = text[text.index("func main.consume") :]
        assert "= <-" not in body and "break" not in body, body
        # the accumulator survives the phi copies: one += and a return of the same variable
        m = re.search(r"^\s+(\w+) \+= v$", body, re.MULTILINE)
        assert m and f"return {m.group(1)}" in body, body

    def check_goroutines_defer_and_panic(self):
        assert_no_calls(self.texts, ("main.runAll", "main.main"), (*RUNTIME_CHAN_CALLS, "runtime.newproc"))
        assert_no_calls(
            self.texts,
            ("main.(*counter).inc", "main.safeDiv", "main.runAll.func1", "main.safeDiv.func1", "main.mustPositive"),
            RUNTIME_GO_CALLS,
        )
        # the goroutine runs a closure record: the closure body with its captured variables
        assert re.search(
            r"^\s+go main\.runAll\.func1\{X0: \w+, X1: [^}]+\}\(\)$", self.texts["main.runAll"], re.MULTILINE
        )
        text = self.texts["main.main"]
        assert re.search(r"^\s+go main\.main\.gowrap1\{X0: \w+\}\(\)$", text, re.MULTILINE)
        assert re.search(r"= make\(chan int, 4\)$", text, re.MULTILINE), text
        assert re.search(r"^\s+\w+ <- 1$", text, re.MULTILINE), text

        text = self.texts["main.(*counter).inc"]
        assert re.search(r"^\s+defer main\.\(\*counter\)\.inc\.deferwrap1\(\)$", text, re.MULTILINE), text
        # the deferBits byte and the inline call at the exit are gone
        assert not re.search(r"^\s+\w+\(\w+, \w+, \w+", body(text), re.MULTILINE), text
        # stack closure records carry their captures (&err; the WaitGroup the wrapper calls Done on)
        assert re.search(r"defer main\.safeDiv\.func1\{cap_0: &\w+\}\(\)", self.texts["main.safeDiv"])
        assert re.search(r"defer main\.runAll\.func1\.deferwrap1\{cap_0: [\w.]+\}\(\)", self.texts["main.runAll.func1"])

        assert re.search(r"= recover\(\)$", self.texts["main.safeDiv.func1"], re.MULTILINE)
        assert re.search(r'^\s+panic\("not positive"\)$', self.texts["main.mustPositive"], re.MULTILINE)


class TestMapsGo122(MapIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "maps")

    def test_maps(self):
        self.run_checks()


class TestMapsGo127(MapIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "maps")
    FUNCS = (*MapIdioms.FUNCS, "main.main", "main.init")

    def test_maps(self):
        self.run_checks()

    def check_stack_map_and_map_global(self):
        # a map literal that does not escape: go1.24+ puts the header and one group on the stack
        text = self.texts["main.main"]
        m = re.search(r"(\w+) :?= make\(map\[int\]string\)$", text, re.MULTILINE)
        assert m, text
        assert re.search(rf'^\s+{m.group(1)}\[1\] = "x"$', text, re.MULTILINE), text
        assert re.search(rf"main\.byInt\({m.group(1)}, 1\)", text), text
        # the group clear, the empty control word and the hash seed are gone
        assert "0x8080808080808080" not in text and "runtime.rand" not in text and "memset" not in text
        # a map-typed package variable keeps its Go type through the variable manager
        init = self.texts["main.init"]
        assert "main.table map[string]int" in init and "main.table = v" in init, init


class TestConcGo122(ConcIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "conc")
    FUNCS = (*ConcIdioms.FUNCS, "os.(*file).close")

    def test_conc(self):
        self.run_checks()

    def check_string_literal_lengths(self):
        # Go string data is not NUL-terminated: a data pointer stored next to its length word prints only those
        # bytes, not the rest of the string pool
        text = self.texts["os.(*file).close"]
        assert re.search(r'\.Op\.ptr = "close"\n', text), "the data pointer is not clipped to its length word"
        assert '"close1' not in text

        codegen = self.codegens["os.(*file).close"]
        loader = self.proj.loader
        addr = next(loader.memory.find("héllo".encode()))
        md = MemoryData(addr, 0, MemoryDataSort.String)
        md.content = loader.memory.load(addr, 32)
        assert md.content.startswith(b"h\xc3\xa9llosysmon")  # the pool runs on
        ptr_ty = SimTypePointer(SimTypeChar()).with_arch(self.proj.arch)
        clipper = StringLiteralLengths(codegen, codegen.cfunc)

        def clip(n):
            ptr = GoConstant(addr, ptr_ty, reference_values={ptr_ty: md}, codegen=codegen)
            length = GoConstant(n, SimTypeLongLong(), reference_values={}, codegen=codegen)
            clipper._clip(ptr, length)
            return "".join(c for c, _ in ptr.c_repr_chunks())

        assert clip(6) == '"héllo"'
        assert clip(3) == '"hé"'
        # a cut inside a character, an empty or an overlong length is not this pointer's length
        unclipped = clip(1000)
        assert unclipped.startswith('"héllosysmon')
        assert clip(2) == unclipped
        assert clip(0) == unclipped


class TestConcGo127(ConcIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "conc")

    def test_conc(self):
        self.run_checks()

    def check_deferred_closure_context(self):
        # a deferred closure capturing a named result by address: the body's context knows it as *any
        text = self.texts["main.safeDiv.func1"]
        assert "func main.safeDiv.func1(ctx *struct { F uintptr; cap_0 *any }) {" in text, text
        assert "field_" not in text and "recover()" in text, text


class AtomicIdioms:
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

    def assert_masks(self):
        raise NotImplementedError

    def test_atomics(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                text = text[text.index("func ") :]
                for leak in ("unsupported instruction", "goto", "arm64HasATOMICS", "CasCmp", "& 3 != 0"):
                    assert leak not in text, text
        # the fetch-and-add returns the old value and the compiler adds the delta back; atomic.Add returns the sum
        assert re.search(r"^\s+return atomic\.AddInt32\(&c\.hits, d\)$", self.texts["main.bump"], re.MULTILINE)
        assert "return atomic.AddInt64(&c.total, d)" in self.texts["main.bump64"]
        text = self.texts["main.release"]
        m = re.search(r"^\s+(\w+) := atomic\.AddInt32\(&c\.hits, -1\)$", text, re.MULTILINE)
        assert m, text
        assert f"if {m.group(1)} == 0" in text or f"if {m.group(1)} != 0" in text, text
        # the flag materialization folds into the condition: no `v = 0 / v = 1` diamond, no `v & 1`
        assert "return atomic.CompareAndSwapInt32(&c.state, 0, 1)" in self.texts["main.tryLock"]
        text = self.texts["main.lock"]
        assert "if atomic.CompareAndSwapInt32(&c.state, 0, 1) {" in text, text
        assert text.count("atomic.CompareAndSwapInt32(") == 2 and "& 1" not in text, text
        assert "c.state = 0" in self.texts["main.unlock"]
        assert "return c.hits" in self.texts["main.peek"]
        assert "return c.total" in self.texts["main.total"]
        assert "return atomic.SwapInt32(&c.state, v)" in self.texts["main.swap"]
        self.assert_masks()


class TestAtomicsArm64Go127(AtomicIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "atomics", arch="aarch64")

    def assert_masks(self):
        assert "return atomic.OrUint32(&c.flags, bit)" in self.texts["main.setFlag"]
        assert "return atomic.AndUint32(&c.flags, ^bit)" in self.texts["main.clearFlag"]


class TestAtomicsAmd64Go127(AtomicIdioms, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "atomics")

    def assert_masks(self):
        # the amd64 compiler writes And/Or out as a compare-and-swap loop, which stays one
        for name in ("main.setFlag", "main.clearFlag"):
            text = self.texts[name]
            assert "for {" in text and "atomic_compare_exchange(" in text, text


class BoxedValueIdioms:
    """
    Interface values built in place: bytes boxed through runtime.staticuint64s, convT* results, an eface carried over
    from a call result, and the variadic ``...any`` array of (type word, data word) pairs on the stack.
    """

    FUNCS = ("main.main",)

    def check_boxed_values(self):
        text = self.texts["main.main"]
        for gone in ("staticuint64s", "any{tab:", "[]any{", "convT"):
            assert gone not in text, (gone, text)
        # bools and tuple results are spread
        assert re.search(r"fmt\.Println\(.+ != nil, .+ != nil\)$", text, re.MULTILINE), text
        assert re.search(r"fmt\.Println\(\w+, ok\)$", text, re.MULTILINE), text


class TestTypeswitchI386Go127(BoxedValueIdioms, GoDecompilationTarget):
    """
    386 (ABI0): growslice returns its slice in one stack-held value whose words are read back through memory. The
    appended element stored past the growslice merge is the append's argument, and the grown header is stored back
    into the receiver's field in one piece.
    """

    BINARY = go_binary("go1.27.1", "typeswitch", arch="i386")
    FUNCS = (*BoxedValueIdioms.FUNCS, "fmt.(*buffer).writeByte", "reflect.(*bitVector).append")
    FUNCS += ("strconv.appendQuotedWith",)

    def test_typeswitch(self):
        self.run_checks()

    def check_abi0_append(self):
        for name, elem in (("fmt.(*buffer).writeByte", "c"), ("reflect.(*bitVector).append", "0")):
            text = self.texts[name]
            assert "not recovered" not in text
            assert re.search(rf"= append\(.+, {elem}\)$", text, re.MULTILINE), name
            # no word-by-word write-back of the grown header
            assert "cap(" not in text and ".ptr = " not in text, name
        # append(buf, `\x`...) stores both bytes with one 16-bit constant store
        assert re.search(r'= append\(.+, "\\\\x"\.\.\.\)$', self.texts["strconv.appendQuotedWith"], re.MULTILINE)


class TestAtomicsI386Go127(GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "atomics", arch="i386")
    FUNCS = ("main.main", "reflect.Value.IsNil")

    def test_boxed_bool_and_struct_receiver_fields(self):
        # &runtime.staticuint64s[b] for a bool result read back from the stack
        text = self.texts["main.main"]
        assert "staticuint64s" not in text, text
        assert text.count("fmt.Println(") == 3, text
        # reflect.Value spans three stack words; IsNil reads ptr and flag (not typ_) and takes the receiver's address.
        # Each word used to be an unassigned local ([bp+0x8], [bp+0xc]) instead of a field of the receiver.
        text = self.texts["reflect.Value.IsNil"]
        assert "func (v reflect.Value) IsNil() bool {" in text
        assert "reflect.flag.kind(v.flag)" in text and "v.ptr" in text, text
        assert not re.search(r"^    var .*// \[bp\+0x(8|c)\]$", text, re.MULTILINE), text


if __name__ == "__main__":
    unittest.main()
