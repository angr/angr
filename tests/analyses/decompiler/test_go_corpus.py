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
    FUNCS = ("main.convert", "main.generate", "main.main", "crypto/internal/fips140/check.init.0")

    def test_itab_reads_use_named_fields(self):
        # an error's itab word points at the runtime's itab struct: its Type pointer is read by name
        text = self.decompile("main.main")
        assert re.search(r"\w+\.tab\.Type\b", text), text
        assert ".tab[" not in text and "padding_0 [8]uint8" not in text
        tab = self.proj.kb.go_signatures.type("error").fields["tab"]
        assert tab.pts_to.go_name in ("internal/abi.ITab", "runtime.itab") and "Type" in tab.pts_to.fields

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

    def test_negated_overflow_guard(self):
        # `neg rdx; cmp rdx, rdi; jae`: the guard negates arithmetically, never with a logical `!`
        text = self.decompile("crypto/internal/fips140/check.init.0")
        assert re.search(r"if -\w+ >= \w+ \{", text), text
        assert not re.search(r"!\w+ >= ", text)


class TestGoCorpusInferredResults(_Corpus):
    """
    Once ParseIdentities is typed ([]Identity, error) by the result inference, main.convert's loop walks a pointer to
    a typed interface element: the switch on the element's itab and the method call through it must survive. A fresh
    project takes the inferred records the way a second sweep pass does (built once for the class).
    """

    PATH = LINUX
    FUNCS = ("main.convert", "filippo.io/age.ParseIdentities")
    text = ""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        callee = "filippo.io/age.ParseIdentities"
        cls.proj.analyses.Decompiler(cls.addrs[callee], cfg=cls.cfg.model, flavor="go", fail_fast=True)
        cls.record = cls.proj.kb.go_signatures.inferred_record(callee)
        proj, cfg = load_project_with_scoped_cfg(
            cls.PATH, cls.addrs["main.convert"], extra_func_addrs=[cls.addrs[callee]], call_tree_depth=1
        )
        if cls.record is not None:
            proj.kb.go_signatures.set_inferred(callee, dict(cls.record))
        dec = proj.analyses.Decompiler(cls.addrs["main.convert"], cfg=cfg.model, flavor="go", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text
        cls.text = dec.codegen.text

    def test_callee_results_are_inferred(self):
        assert self.record is not None and self.record.result_types(2)[0] == "[]filippo.io/age.Identity"
        assert re.search(r", err := filippo\.io/age\.ParseIdentities\(", self.text)

    def test_type_switch_over_typed_elements(self):
        text = self.text
        assert re.search(r"switch \w+ := \w+\.\(type\) \{", text)
        assert "case *filippo.io/age.HybridIdentity:" in text and "case *filippo.io/age.X25519Identity:" in text
        # the method call through the element's itab renders on the bound value
        assert re.search(r"\w+\.k\.PublicKey\(\)", text)
        # no two-word integer result for a function that returns nothing
        assert "int128" not in text.split("{", 1)[0]


class TestGoCorpusErrorConstructors(_Corpus):
    """
    go1.26+ inlines fmt.Errorf as a call to fmt.errorf plus an ``&errors.errorString{format}`` fallback for a nil
    result, and errors.New as the allocation itself: both come back as one call.
    """

    PATH = LINUX
    FUNCS = (
        "filippo.io/age/internal/bech32.convertBits",
        "filippo.io/age.newX25519IdentityFromScalar",
        "filippo.io/age.GenerateX25519Identity",
    )

    def decompile_twice(self, name: str) -> str:
        # the second pass sees the results the first one inferred
        self.decompile(name)
        dec = self.proj.analyses.Decompiler(
            self.addrs[name], cfg=self.cfg.model, flavor="go", fail_fast=True, use_cache=False, regen_clinic=True
        )
        assert dec.codegen is not None and dec.codegen.text
        return dec.codegen.text

    @staticmethod
    def assert_no_fallback(text: str):
        body = text[re.search(r"^func ", text, re.MULTILINE).start() :]
        assert "errorf(" not in body and "errorString" not in body, body

    def test_errorf_fallback_folds(self):
        text = self.decompile_twice("filippo.io/age/internal/bech32.convertBits")
        self.assert_no_fallback(text)
        assert re.search(r'return nil, fmt\.Errorf\("invalid data range: data\[%d\]=%d \(frombits=%d\)", \w+, ', text)
        # no variadic arguments: no nil slice either
        assert 'return nil, fmt.Errorf("illegal zero padding")\n' in text, text
        assert 'return nil, fmt.Errorf("non-zero padding")\n' in text, text

    def test_errorf_wraps_error(self):
        text = self.decompile_twice("filippo.io/age.GenerateX25519Identity")
        self.assert_no_fallback(text)
        assert re.search(r'return \w+, fmt\.Errorf\("internal error: %v", err\)$', text, re.MULTILINE), text
        # the source's own nil check of rand.Read's error stays
        assert re.search(r"if err [!=]= nil \{", text), text

    def test_inlined_errors_new(self):
        text = self.decompile_twice("filippo.io/age.newX25519IdentityFromScalar")
        self.assert_no_fallback(text)
        assert 'return nil, errors.New("invalid X25519 secret key")\n' in text, text


class TestGoCorpusStringCompares(_Corpus):
    """``s == "lit"`` lowered to a length check plus little-endian word compares of the bytes folds back."""

    PATH = LINUX
    FUNCS = (
        "strconv.ParseBool",
        "internal/runtime/cgroup.parseCPUMount",
        "runtime/debug.SetTraceback",
        "fmt.(*pp).missingArg",
    )

    def test_string_switch_cases(self):
        text = self.decompile("strconv.ParseBool")
        for lit in ("0", "1", "t", "T", "f", "F", "TRUE", "True", "true", "FALSE", "False", "false"):
            assert re.search(rf'\bstr [!=]= "{lit}"', text), lit
        # no word compares of the bytes are left, nor a struct made up over them
        assert "int32" not in text and "str[4]" not in text and "struct_" not in text

    def test_string_switch(self):
        text = self.decompile("runtime/debug.SetTraceback")
        # the length and byte dispatch is gone: the cases are a switch on the string
        assert re.search(r"^\s+switch level \{$", text, re.MULTILINE)
        for lit in ("all", "none", "crash", "system"):
            assert re.search(rf'^\s+case "{lit}":$', text, re.MULTILINE), lit
        assert 'level != ""' in text and 'level != "single"' in text
        assert "len(level)" not in text and "*(*int" not in text

    def test_appended_constant_bytes(self):
        # buffer.writeString("%!") appends two bytes stored as one 16-bit word
        text = self.decompile("fmt.(*pp).missingArg")
        assert re.search(r'= append\(\w+\.buf, "%!"\.\.\.\)$', text, re.MULTILINE)
        assert '"(MISSING)"...)' in text
        assert "not recovered" not in text and "8485" not in text

    def test_substring_compare_and_prefix(self):
        text = self.decompile("internal/runtime/cgroup.parseCPUMount")
        assert re.search(r' == "cgroup2" \{', text) and re.search(r' == "cgroup" \{', text)
        assert "1869768547" not in text
        # memequal with a literal under `len >= 3`
        assert re.search(r'= !strings\.HasPrefix\(.*, "/\.\."\)$', text, re.MULTILINE)
        assert 'runtime.memequal("/..",' not in text


class TestGoCorpusStringComparesArm64(_Corpus):
    PATH = DARWIN
    FUNCS = ("strconv.ParseBool",)

    def test_string_switch_cases(self):
        text = self.decompile("strconv.ParseBool")
        for lit in ("0", "1", "t", "T", "f", "F", "TRUE", "True", "true", "FALSE", "False", "false"):
            assert re.search(rf'\bstr [!=]= "{lit}"', text), lit
        assert "int32" not in text and "struct_" not in text


class TestGoCorpusDarwinArm64(_Corpus):
    PATH = DARWIN
    FUNCS = (
        "filippo.io/age.(*HybridRecipient).String",
        "filippo.io/age.(*ScryptIdentity).Unwrap",
        "filippo.io/age/internal/format.splitArgs",
        "main.printfToTerminal.func1",
    )

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

    def test_register_parameters_are_bound(self):
        # arm64 calls push nothing: the Go ABIInternal convention must still match (it used to print "() int32" and
        # read x0/x1 as unassigned locals)
        text = self.decompile("filippo.io/age/internal/format.splitArgs")
        assert re.search(
            r"^func filippo\.io/age/internal/format\.splitArgs\(\w+ [^,()]+, \w+ [^,()]+, \w+ [^,()]+\)",
            text,
            re.MULTILINE,
        )
        assert not re.search(r"^    var .*// x[0-7]$", text, re.MULTILINE), text

    def test_closure_context_is_a_parameter(self):
        text = self.decompile("main.printfToTerminal.func1")
        assert re.search(r"^func main\.printfToTerminal\.func1\(ctx \*\w+, ", text, re.MULTILINE), text
        assert not re.search(r"// x(26|[0-7])$", text, re.MULTILINE), text


if __name__ == "__main__":
    unittest.main()
