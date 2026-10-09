# pylint: disable=missing-class-docstring,no-self-use
"""
Regression on real-world stripped Go builds (gors-bins corpus): no DWARF, no symbol table, names from the pclntab.
A scoped CFG of these binaries costs several seconds, so each class builds one and runs all its checks in one test.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location

from .test_go_decompiler import GoDecompilationTarget, TargetChecks

test_location = os.path.join(bin_location, "tests")


AGE_KEYGEN = os.path.join(test_location, "x86_64", "go", "corpus", "age-keygen-v1.3.1-linux-amd64")


class CorpusChecks(TargetChecks):
    @staticmethod
    def body(text: str) -> str:
        """The function itself, without the type declarations printed ahead of it."""
        m = re.search(r"^func ", text, re.MULTILINE)
        assert m is not None
        return text[m.start() :]

    def test_corpus(self):
        self.run_checks()


class TestGoCorpusLinuxAmd64(CorpusChecks, GoDecompilationTarget):
    """
    age-keygen linux/amd64: the scoped CFG of these functions is costly, so each class covers as many checks as its
    functions allow. Decompilation follows FUNCS order.
    """

    BINARY = AGE_KEYGEN
    FUNCS = (
        "main.convert",
        "main.generate",
        "main.main",
        "crypto/internal/fips140/check.init.0",
        "main.errorf",
        "filippo.io/age.ParseIdentities",
    )

    def check_itab_reads_use_named_fields(self):
        # an error's itab word points at the runtime's itab struct: its Type pointer is read by name
        text = self.texts["main.main"]
        assert re.search(r"\w+\.tab\.Type\b", text), text
        assert ".tab[" not in text and "padding_0 [8]uint8" not in text
        tab = self.proj.kb.go_signatures.type("error").fields["tab"]
        assert tab.pts_to.go_name in ("internal/abi.ITab", "runtime.itab") and "Type" in tab.pts_to.fields

    def check_convert(self):
        text = self.texts["main.convert"]
        # the interface type switch on the parsed identity is recovered, with the concrete cases named
        assert re.search(r"switch \w+ := \w+\.\(type\) \{", text)
        assert "case *filippo.io/age.X25519Identity:" in text
        # the print folds into one call with its format string
        assert re.search(r'fmt\.Fprintf\(.*"%s\\n"', text)
        # GC write barriers and bounds-check sinks are gone
        assert "gcWriteBarrier" not in text and "panicBounds" not in text
        text = self.texts["main.generate"]
        assert "gcWriteBarrier" not in text and "wbMove" not in text

    def check_convert_with_inferred_callee_results(self):
        # ParseIdentities is typed ([]Identity, error) by the result inference; main.convert decompiled again
        # renders with that record
        record = self.proj.kb.go_signatures.inferred_record("filippo.io/age.ParseIdentities")
        assert record is not None and record.result_types(2)[0] == "[]filippo.io/age.Identity"
        dec = self.proj.analyses.Decompiler(
            self.addrs["main.convert"],
            cfg=self.cfg.model,
            flavor="go",
            fail_fast=True,
            use_cache=False,
            regen_clinic=True,
        )
        assert dec.codegen is not None
        text = dec.codegen.text
        assert text is not None
        assert re.search(r", err := filippo\.io/age\.ParseIdentities\(", text)
        # main.convert's loop walks a pointer to a typed interface element: the type switch on the element's itab
        # is recovered with the concrete cases named, and the method call through it renders on the bound value
        assert re.search(r"switch \w+ := \w+\.\(type\) \{", text)
        assert "case *filippo.io/age.HybridIdentity:" in text and "case *filippo.io/age.X25519Identity:" in text
        assert re.search(r"\w+\.k\.PublicKey\(\)", text)
        # no two-word integer result for a function that returns nothing
        assert "int128" not in text.split("{", 1)[0]

    def check_negated_overflow_guard(self):
        # `neg rdx; cmp rdx, rdi; jae`: the guard negates arithmetically, never with a logical `!`
        text = self.texts["crypto/internal/fips140/check.init.0"]
        assert re.search(r"if -\w+ >= \w+ \{", text), text
        assert not re.search(r"!\w+ >= ", text)

    def check_inlined_log_printf(self):
        # std.output(0, 2, log.Printf.func1{format, v}) is log.Printf(format, v...)
        text = self.texts["main.errorf"]
        assert re.search(r'log\.Printf\("age-keygen: error: " \+ ', text), text
        assert "log.(*Logger).output" not in text and "func1{" not in text


class TestGoCorpusLinuxAmd64Errors(CorpusChecks, GoDecompilationTarget):
    BINARY = AGE_KEYGEN
    FUNCS = (
        "filippo.io/age/internal/bech32.convertBits",
        "filippo.io/age.GenerateX25519Identity",
        "filippo.io/age.newX25519IdentityFromScalar",
        "os.runtime_args",
        "flag.(*FlagSet).Var",
    )

    def check_inlined_clone_and_contains(self):
        # append([]string{}, s...) lowered to makeslice + typedslicecopy under a guard mask
        text = self.texts["os.runtime_args"]
        assert re.search(r"^\s+return append\(\[\]string\{\}, \w+\.\.\.\)$", text, re.MULTILINE), text
        # strings.Contains inlines to strings.Index(s, sub) >= 0
        text = self.texts["flag.(*FlagSet).Var"]
        assert '!strings.Contains(name, "=")' in text, text
        assert "strings.Index" not in text, text

    def check_error_constructors(self):
        # go1.26+ inlines fmt.Errorf as a call to fmt.errorf plus an ``&errors.errorString{format}`` fallback for a
        # nil result, and errors.New as the allocation itself: both come back as one call
        for name in (
            "filippo.io/age/internal/bech32.convertBits",
            "filippo.io/age.GenerateX25519Identity",
            "filippo.io/age.newX25519IdentityFromScalar",
        ):
            body = self.body(self.texts[name])
            assert "errorf(" not in body and "errorString" not in body, body
        text = self.texts["filippo.io/age/internal/bech32.convertBits"]
        assert re.search(r'return nil, fmt\.Errorf\("invalid data range: data\[%d\]=%d \(frombits=%d\)", \w+, ', text)
        # no variadic arguments: no nil slice either
        assert 'return nil, fmt.Errorf("illegal zero padding")\n' in text, text
        assert 'return nil, fmt.Errorf("non-zero padding")\n' in text, text
        text = self.texts["filippo.io/age.GenerateX25519Identity"]
        assert re.search(r'return \w+, fmt\.Errorf\("internal error: %v", err\)$', text, re.MULTILINE), text
        # the source's own nil check of rand.Read's error stays
        assert re.search(r"if err [!=]= nil \{", text), text
        text = self.texts["filippo.io/age.newX25519IdentityFromScalar"]
        assert 'return nil, errors.New("invalid X25519 secret key")\n' in text, text


class TestGoCorpusLinuxAmd64Stdlib(CorpusChecks, GoDecompilationTarget):
    BINARY = AGE_KEYGEN
    FUNCS = (
        "strconv.ParseBool",
        "internal/runtime/cgroup.parseCPUMount",
        "runtime/debug.SetTraceback",
        "fmt.(*pp).missingArg",
        "flag.commandLineUsage",
        "slices.medianCmpFunc[go.shape.*uint8]",
        "io.ReadAtLeast",
        "crypto/internal/fips140/hmac.(*HMAC).Sum",
        "filippo.io/age.ParseX25519Identity",
    )

    def check_string_compares(self):
        # ``s == "lit"`` lowered to a length check plus little-endian word compares of the bytes folds back
        text = self.texts["strconv.ParseBool"]
        for lit in ("0", "1", "t", "T", "f", "F", "TRUE", "True", "true", "FALSE", "False", "false"):
            assert re.search(rf'\bstr [!=]= "{lit}"', text), lit
        # no word compares of the bytes are left, nor a struct made up over them
        assert "int32" not in text and "str[4]" not in text and "struct_" not in text

        # the length and byte dispatch is gone: the cases are a switch on the string
        text = self.texts["runtime/debug.SetTraceback"]
        assert re.search(r"^\s+switch level \{$", text, re.MULTILINE)
        for lit in ("all", "none", "crash", "system"):
            assert re.search(rf'^\s+case "{lit}":$', text, re.MULTILINE), lit
        assert 'level != ""' in text and 'level != "single"' in text
        assert "len(level)" not in text and "*(*int" not in text

        # buffer.writeString("%!") appends two bytes stored as one 16-bit word
        text = self.texts["fmt.(*pp).missingArg"]
        assert re.search(r'= append\(\w+\.buf, "%!"\.\.\.\)$', text, re.MULTILINE)
        assert '"(MISSING)"...)' in text
        assert "not recovered" not in text and "8485" not in text

        text = self.texts["internal/runtime/cgroup.parseCPUMount"]
        assert re.search(r' == "cgroup2" \{', text) and re.search(r' == "cgroup" \{', text)
        assert "1869768547" not in text
        # memequal with a literal under `len >= 3`
        assert re.search(r'= !strings\.HasPrefix\(.*, "/\.\."\)$', text, re.MULTILINE)
        assert 'runtime.memequal("/..",' not in text

    def check_func_value_calls(self):
        # the register holding the code pointer (or the funcval as context) is not a trailing argument
        text = self.texts["flag.commandLineUsage"]
        assert re.search(r"^\s+\(\*g_\w+\)\(\)$", text, re.MULTILINE), text
        text = self.texts["slices.medianCmpFunc[go.shape.*uint8]"]
        calls = re.findall(r"\(\*(a\d+)\)\((.*)\) [<>]=? 0", text)
        assert len(calls) == 3, text
        for fv, args in calls:
            assert not re.search(rf"\*?{fv}$", args), text
        # a call through an itab slot whose callee type is not known is a method call
        text = self.texts["io.ReadAtLeast"]
        assert re.search(r"\br\.Read\(", text), text
        assert ".Fun" not in text, text

    def check_untyped_result_pairs(self):
        # No bech32 function is decompiled here, so the result binder only counts its five result words. The
        # caller's reads type them: the trailing pair is nil-checked and boxed into fmt.Errorf's argument (an
        # interface pair, hence ``error``), the leading pair is built as a string. The Decompiler's re-run
        # destructures both calls.
        record = self.proj.kb.go_signatures.inferred_record("filippo.io/age/internal/bech32.Decode")
        assert record is not None
        types = record.result_types(1)
        assert types == ["string", "uintptr", "uintptr", "uintptr", "error"], types
        text = self.texts["filippo.io/age.ParseX25519Identity"]
        assert re.search(
            r"^    \w+, \w+, \w+, \w+, err := filippo\.io/age/internal/bech32\.Decode\(", text, re.MULTILINE
        ), text
        assert "if err != nil {" in text, text
        assert re.search(r'fmt\.Errorf\("malformed secret key: %v", err\)', text), text
        assert re.search(r"^\s+\w+, err2 := filippo\.io/age\.newX25519IdentityFromScalar\(", text, re.MULTILINE), text
        assert ".~r" not in text and "unsafe.Pointer(&" not in text, text

    def check_assertion_to_interface(self):
        # h.outer.(marshalable): the inline probe of the assertion's cache is dropped and the runtime.typeAssert
        # behind it becomes the assertion, whose itab calls are method calls
        text = self.body(self.texts["crypto/internal/fips140/hmac.(*HMAC).Sum"])
        assert "marshalable := h.outer.(crypto/internal/fips140/hmac.marshalable)" in text, text
        assert "marshalable.UnmarshalBinary(" in text, text
        assert "typeAssert" not in text and ".Cache" not in text, text
        # the descriptors of the type switch ahead of it print as names, not as their first field
        assert "&go:itab.*crypto/internal/fips140/sha256.Digest,hash.Hash" in text, text
        assert ".Inter" not in text and ".Size_" not in text, text


class TestGoCorpusDarwinArm64(CorpusChecks, GoDecompilationTarget):
    BINARY = os.path.join(test_location, "aarch64", "go", "corpus", "age-v1.3.1-darwin-arm64")
    FUNCS = (
        "filippo.io/age.(*HybridRecipient).String",
        "filippo.io/age.(*ScryptIdentity).Unwrap",
        "filippo.io/age/internal/format.splitArgs",
        "main.printfToTerminal.func1",
        "filippo.io/age.(*ScryptRecipient).Wrap",
        "strconv.ParseBool",
        "filippo.io/age.(*X25519Recipient).Wrap",
    )

    def check_method_receiver_and_sinks(self):
        text = self.texts["filippo.io/age.(*HybridRecipient).String"]
        # Mach-O Go builds get the runtime's non-returning seeding: no bounds-panic sinks in the output
        assert "panicBounds" not in text
        # the receiver comes from the type descriptors' method table
        assert re.search(r"^func \(recv \*filippo\.io/age\.HybridRecipient\) String\(\) string \{", text, re.MULTILINE)

    def check_unwrap_ranges_and_results(self):
        text = self.texts["filippo.io/age.(*ScryptIdentity).Unwrap"]
        assert "panicBounds" not in text
        assert re.search(
            r"^func \(recv \*filippo\.io/age\.ScryptIdentity\) Unwrap\(a1 \[\]\*filippo\.io/age\.Stanza\) \(\[\]uint8, error\)",
            text,
            re.MULTILINE,
        )
        assert re.search(r"for \w+ := 0; len\(a1\) > \w+; \w+\+\+ \{", text)

    def check_register_parameters_are_bound(self):
        # arm64 calls push nothing: the Go ABIInternal convention must still match (it used to print "() int32" and
        # read x0/x1 as unassigned locals)
        text = self.texts["filippo.io/age/internal/format.splitArgs"]
        assert re.search(
            r"^func filippo\.io/age/internal/format\.splitArgs\(\w+ [^,()]+, \w+ [^,()]+, \w+ [^,()]+\)",
            text,
            re.MULTILINE,
        )
        assert not re.search(r"^    var .*// x[0-7]$", text, re.MULTILINE), text

    def check_closure_context_is_a_parameter(self):
        text = self.texts["main.printfToTerminal.func1"]
        assert re.search(r"^func main\.printfToTerminal\.func1\(ctx \*\w+, ", text, re.MULTILINE), text
        assert not re.search(r"// x(26|[0-7])$", text, re.MULTILINE), text

    def check_inlined_itoa(self):
        # internal/strconv.FormatInt(x, 10) is what strconv.Itoa inlines to
        text = self.texts["filippo.io/age.(*ScryptRecipient).Wrap"]
        assert re.search(r"strconv\.Itoa\(\w+\)", text), text
        assert "internal/strconv" not in text

    def check_string_switch_cases(self):
        text = self.texts["strconv.ParseBool"]
        for lit in ("0", "1", "t", "T", "f", "F", "TRUE", "True", "true", "FALSE", "False", "false"):
            assert re.search(rf'\bstr [!=]= "{lit}"', text), lit
        assert "int32" not in text and "struct_" not in text

    def check_whole_result_spread_reads_the_first_result(self):
        # x25519 returns ([]byte, error) with no signature source; the caller tests the error and spreads the whole
        # result into append, so append's argument types its first words and the spread reads the first result
        text = self.texts["filippo.io/age.(*X25519Recipient).Wrap"]
        m = re.search(r"^\s+(\w+), (err\d*) := golang\.org/x/crypto/curve25519\.x25519\(", text, re.MULTILINE)
        assert m is not None, text
        assert f"if {m.group(2)} != nil {{" in text, text
        assert re.search(rf"append\(.*, {m.group(1)}\.\.\.\)", text), text
        assert ".~r" not in text, text


if __name__ == "__main__":
    unittest.main()
