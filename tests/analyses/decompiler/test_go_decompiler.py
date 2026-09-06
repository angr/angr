#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import cle

import angr
from angr.analyses.decompiler.structured_codegen.go import GoStructuredCodeGenerator
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def go_binary(version: str, name: str, arch: str = "x86_64") -> str:
    return os.path.join(test_location, arch, "go", version, name)


def go_func_addrs(path: str, *names: str) -> dict[str, int]:
    """Resolve Go function names through the symbol table (pclntab-derived for stripped binaries)."""
    loader = cle.Loader(path, auto_load_libs=False)
    addrs = {}
    for name in names:
        sym = loader.find_symbol(name)
        assert sym is not None, f"{name} not found in {path}"
        addrs[name] = sym.rebased_addr
    return addrs


class GoDecompilationTarget(unittest.TestCase):
    """
    Per-binary base: pins one corpus binary and the functions to decompile. Decompilation runs once per class on a
    scoped CFG so every feature assertion stays cheap.
    """

    BINARY: str = ""
    FUNCS: tuple[str, ...] = ()
    CALL_TREE_DEPTH = 1
    # decompile everything this many extra times first, so signatures inferred from one function reach the others
    WARMUP_PASSES = 0

    proj = None
    cfg = None
    addrs: dict[str, int] = {}
    texts: dict[str, str] = {}

    @classmethod
    def setUpClass(cls):
        if not cls.BINARY:
            raise unittest.SkipTest("abstract target")
        cls.addrs = go_func_addrs(cls.BINARY, *cls.FUNCS)
        first, *rest = (cls.addrs[n] for n in cls.FUNCS)
        cls.proj, cls.cfg = load_project_with_scoped_cfg(
            cls.BINARY, first, extra_func_addrs=rest, call_tree_depth=cls.CALL_TREE_DEPTH
        )
        for _ in range(cls.WARMUP_PASSES):
            for name in cls.FUNCS:
                cls.proj.analyses.Decompiler(
                    cls.addrs[name], cfg=cls.cfg.model, flavor="go", fail_fast=True, use_cache=False, regen_clinic=True
                )
        cls.texts = {name: cls.decompile(name) for name in cls.FUNCS}

    @classmethod
    def decompile(cls, name: str) -> str:
        func = cls.proj.kb.functions[cls.addrs[name]]
        fresh = {"use_cache": False, "regen_clinic": True} if cls.WARMUP_PASSES else {}
        dec = cls.proj.analyses.Decompiler(func, cfg=cls.cfg.model, flavor="go", fail_fast=True, **fresh)
        assert dec.codegen is not None, f"no codegen for {name}"
        assert isinstance(dec.codegen, GoStructuredCodeGenerator)
        assert dec.codegen.text
        print_decompilation_result(dec)
        return dec.codegen.text

    @staticmethod
    def header(text: str) -> str:
        return next(line for line in text.splitlines() if line.startswith("func "))


class TestBasicsGo122(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "basics")
    FUNCS = (
        "main.fib",
        "main.add",
        "main.main",
        "main.parse",
        "main.divmod",
        "main.count",
        "main.bump",
        "runtime.acquirem",
    )

    def test_go_flavor_is_selected(self):
        assert self.proj.is_go_binary
        assert (self.addrs["main.fib"], "go") in self.proj.kb.decompilations
        assert "go" in self.proj.kb.decompilations.all_flavors(self.addrs["main.fib"])

    def test_function_header_is_go(self):
        header = self.header(self.texts["main.fib"])
        assert header.startswith("func main.fib(")
        assert header.endswith(") int {"), header
        assert "long" not in header
        assert "void" not in self.texts["main.main"]

    def test_main_data_flow_and_literals(self):
        # the parsed value reaches n through the phi of a call's result register; a stack array is a slice literal
        main = self.texts["main.main"]
        main = main[main.index("func main.main") :]
        m = re.search(r"^\s+(\w+), err := main\.parse\(os\.Args\[1\]\)$", main, re.MULTILINE)
        assert m, main
        assert re.search(rf"^\s+\w+ = {m.group(1)}$", main, re.MULTILINE), main
        assert re.search(r"main\.bump\(\[\]int\{1, 2, 3, \w+\}\)", main), main

    def test_locals_use_var_declarations(self):
        text = self.texts["main.fib"]
        # locals are declared the Go way: a short declaration at first assignment, or a var line
        assert " := " in text or "    var " in text, text
        assert ";  //" not in text  # C-style declaration trailer

    def test_main_header(self):
        header = self.header(self.texts["main.main"])
        assert header.startswith("func main.main(")
        assert header.endswith(" {"), header

    def test_recursion_renders(self):
        assert "main.fib(" in self.texts["main.fib"].split("{", 1)[1]

    def test_stack_growth_check_is_removed(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert "morestack" not in text
                # the compare against g.stackguard0 (r14+16) must not survive either
                assert "+ 16)" not in text

    def test_argument_spills_are_removed(self):
        # parse spills its string argument into the caller-provided slot and never reads it back
        body = self.texts["main.parse"].split("{", 1)[1]
        assert not re.search(r"^\s+\w+ = a\d+;$", body, re.MULTILINE), body

    def test_zero_register_is_not_a_variable(self):
        assert "xmm15" not in self.texts["main.main"]

    def test_prototypes_come_from_dwarf(self):
        assert self.header(self.texts["main.parse"]) == "func main.parse(s string) (int, error) {"
        assert self.header(self.texts["main.divmod"]) == "func main.divmod(a int, b int) (int, int) {"
        assert self.header(self.texts["main.fib"]) == "func main.fib(n int) int {"
        assert self.header(self.texts["main.main"]) == "func main.main() {"

    def test_multiple_results_are_returned_together(self):
        assert re.search(r"return \w+, \w+$", self.texts["main.divmod"], re.MULTILINE)
        parse = self.texts["main.parse"]
        # multi-result calls are destructured and the error checked idiomatically
        assert re.search(r"^\s+\w+, err :?= strconv\.Atoi\(s\)$", parse, re.MULTILINE), parse
        assert "if err != nil {" in parse
        assert "return 0, err\n" in parse
        assert "return 0, main.errNegative\n" in parse
        assert re.search(r"return \w+, nil$", parse, re.MULTILINE), parse
        assert "~r" not in parse

    def test_values_are_fused_at_call_sites(self):
        main = self.texts["main.main"]
        assert 'main.count("hello, world", ' in main
        assert re.search(r"main\.sum\(\w+\)", main), main
        assert re.search(r"main\.parse\([^,()]+\)$", main, re.MULTILINE), main

    def test_go_statement_syntax(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                body = text.split("{", 1)[1]
                assert not re.search(r";\s*$", body, re.MULTILINE), text
                assert "if (" not in body and "while" not in body and "->" not in body
        fib = self.texts["main.fib"]
        assert "if n > 1 {" in fib
        assert "return n\n" in fib
        parse = self.texts["main.parse"]
        assert "!= nil {" in parse or "== nil {" in parse
        assert "else if " in parse

    def test_package_variables_are_typed(self):
        main = self.texts["main.main"]
        assert "os.Args []string" in main
        assert "if len(os.Args) <= 1 {" in main
        assert "main.parse(os.Args[1])" in main
        assert "main.counter int" in self.texts["main.main"]

    def test_println_is_folded(self):
        main = self.texts["main.main"]
        assert re.search(r"^\s+println\([^\n]+, main\.counter\)$", main, re.MULTILINE), main
        assert "runtime.print" not in main
        assert not main.rstrip().endswith("return\n}")

    def test_range_loops(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert ".ptr[" not in text and ".len" not in text, text
        assert re.search(r"for \w+ :?= range s \{", self.texts["main.count"]), self.texts["main.count"]
        assert re.search(r"if s\[\w+\] == c \{", self.texts["main.count"])
        assert re.search(r"for \w+ :?= range xs \{", self.texts["main.bump"])
        assert "return xs\n" in self.texts["main.bump"]

    def test_g_register_is_named(self):
        text = self.texts["runtime.acquirem"]
        assert "var g *runtime.g" in text
        assert "g.m" in text


class TestIfaceGo122(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "iface")
    FUNCS = ("main.describe", "main.box", "main.unbox", "main.asSquare", "main.wrap", "main.report", "main.kind")

    def test_interface_method_calls(self):
        describe = self.texts["main.describe"]
        assert re.search(r"= s\.Name\(\)$", describe, re.MULTILINE), describe
        assert "strconv.Itoa(s.Area())" in describe
        assert ".tab[" not in describe

    def test_type_descriptors_are_named(self):
        go_types = self.proj.kb.go_types
        assert go_types.name_at(go_types.addr_of("int")) == "int"
        assert go_types.itab_at(self.proj.loader.find_symbol("go:itab.*main.Square,main.Shape").rebased_addr) == (
            "main.Shape",
            "*main.Square",
        )

    def test_type_switch(self):
        kind = self.texts["main.kind"]
        kind = kind[kind.index("func main.kind") :]
        assert "switch x := v.(type) {" in kind, kind
        assert re.search(r"case string:\n\s+return \"string:\" \+ x$", kind, re.MULTILINE), kind
        assert "case int:" in kind and "strconv.Itoa(x)" in kind
        # the interface case comes from the InterfaceSwitch descriptor; its method call goes through the itab
        assert re.search(r"case main\.Shape:\n\s+return \"shape:\" \+ x\.Name\(\)$", kind, re.MULTILINE), kind
        for gone in ("interfaceSwitch", "Hash", ".tab[", "goto", "&type:"):
            assert gone not in kind, (gone, kind)

    def test_type_assertions(self):
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

    def test_range_over_slice_of_interfaces(self):
        # a pointer walking the slice becomes the range value; calls through its itab are method calls
        report = self.texts["main.report"]
        report = report[report.index("func main.report") :]
        assert re.search(r"for \w+, x := range shapes \{", report), report
        assert "x.Name()" in report and "x.Area()" in report, report
        assert re.search(
            r'fmt\.Fprintf\(w, "%d: %s area=%d\\n", \w+, x\.Name\(\), x\.Area\(\)\)$', report, re.MULTILINE
        ), report
        for gone in ("field_", ".ptr", "string{", "len(shapes)"):
            assert gone not in report, (gone, report)

    def test_boxing(self):
        # a value converted to an interface is the value itself
        assert "return n" in self.texts["main.box"]
        # an interface converted to any through the nil-checked itab.Type load
        assert 'return fmt.Errorf("wrapped: %w", err)' in self.texts["main.wrap"]
        # the ...any array on the stack is spread into the call
        report = self.texts["main.report"]
        assert re.search(r'fmt\.Fprintf\(w, "%d: %s area=%d\\n", \w+, .*\)$', report, re.MULTILINE), report
        for text in (self.texts["main.box"], self.texts["main.wrap"], report):
            assert "convT" not in text and "[]any{" not in text and "&type:" not in text, text


class TestBasicsGo122AArch64(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "basics", arch="aarch64")
    FUNCS = ("main.fib", "main.parse", "main.count")

    def test_arm64_headers_and_idioms(self):
        assert self.header(self.texts["main.fib"]) == "func main.fib(n int) int {"
        assert self.header(self.texts["main.parse"]) == "func main.parse(s string) (int, error) {"
        parse = self.texts["main.parse"]
        assert re.search(r"^\s+\w+, err :?= strconv\.Atoi\(s\)$", parse, re.MULTILINE), parse
        assert "if err != nil {" in parse
        for text in self.texts.values():
            assert "morestack" not in text
        assert "for i < len(s) {" in self.texts["main.count"] or "range s" in self.texts["main.count"]


class TestLangdetectWindowsPE(GoDecompilationTarget):
    BINARY = os.path.join(test_location, "x86_64", "windows", "langdetect_go.exe")
    FUNCS = ("main.fibonacci", "main.main")

    def test_pe_go_binary(self):
        assert self.proj.is_go_binary
        assert self.header(self.texts["main.main"]) == "func main.main() {"
        fib = self.texts["main.fibonacci"]
        assert self.header(fib).startswith("func main.fibonacci(")
        for text in self.texts.values():
            assert "morestack" not in text
        main = self.texts["main.main"]
        assert re.search(r'fmt\.Fprintf\(.*, "fibonacci\(%d\) = %d\\n", .+\)$', main, re.MULTILINE), main
        assert "go:itab" not in main and "convT" not in main


class TestBasicsGo122Stripped(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "basics_stripped")
    FUNCS = ("main.fib",)

    def test_pclntab_names_survive_stripping(self):
        assert self.header(self.texts["main.fib"]).startswith("func main.fib(")


class TestBasicsGo127(GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "basics")
    FUNCS = ("main.fib", "main.add")

    def test_function_header_is_go(self):
        assert self.header(self.texts["main.add"]).startswith("func main.add(")


class TestUninitializedStackReadGo127(GoDecompilationTarget):
    """
    A header struct is built in a temporary and copied over with 16-byte moves; the 4-byte field read afterwards
    reaches no definition ssailification tracks. It must take the guesstimated-variable path under fail_fast too.
    """

    BINARY = go_binary("go1.27.1", "uninit_inlined")
    FUNCS = ("main.(*context).handleHeader",)

    def test_read_of_undefined_stack_slot_decompiles(self):
        text = self.texts["main.(*context).handleHeader"]
        assert self.header(text).startswith("func (ctx *main.context) handleHeader(")
        # the body past the read is intact
        assert "internal/sync.(*Mutex).lockSlow" in text
        assert "make([]*int" in text


class TestStructValueReceiver386(unittest.TestCase):
    """
    A struct value receiver on a stack convention: the string field's layout runs past the two words the receiver
    occupies on 386, and refine_locs_with_struct_type falls back to the unrefined words instead of raising.
    """

    def test_struct_value_receiver_falls_back_to_words(self):
        from angr.calling_conventions import SimComboArg, default_cc_for_project
        from angr.knowledge_plugins.functions.function import PrototypeSource
        from angr.sim_type import SimTypeFunction

        binary = go_binary("go1.27.1", "recv", arch="i386")
        name = "main.gitHubRecipientError.Error"
        addr = go_func_addrs(binary, name)[name]
        proj, cfg = load_project_with_scoped_cfg(binary, addr, call_tree_depth=1)
        func = proj.kb.functions[addr]
        proj.kb.go_signatures.load_sources()
        recv = proj.kb.go_signatures.type("main.gitHubRecipientError").with_arch(proj.arch)
        ret = proj.kb.go_signatures.type("string").with_arch(proj.arch)
        func.prototype = SimTypeFunction([recv], ret, arg_names=["e"]).with_arch(proj.arch)
        func.prototype_source = PrototypeSource.USER
        func.calling_convention = default_cc_for_project(proj)(proj.arch)

        (loc,) = func.calling_convention.arg_locs(func.prototype)
        assert isinstance(loc, SimComboArg) and len(loc.locations) == 2

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, flavor="go", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text
        print_decompilation_result(dec)
        header = next(line for line in dec.codegen.text.splitlines() if line.startswith("func "))
        assert "gitHubRecipientError" in header and "Error(" in header


if __name__ == "__main__":
    unittest.main()


class TestInferredResultsGo127Stripped(GoDecompilationTarget):
    """
    ``main.parse`` has no signature source (stripped, not in the stdlib database): its results come from its own
    returns (``strconv.Atoi``'s error, the int it returns as is) and reach ``main.main`` on the second pass.
    """

    BINARY = go_binary("go1.27.1", "basics_stripped")
    FUNCS = ("main.parse", "main.main")
    WARMUP_PASSES = 1

    def test_results_inferred_from_returns(self):
        assert self.header(self.texts["main.parse"]) == "func main.parse(a0 string) (int, error) {"
        rec = self.proj.kb.go_signatures.inferred_record("main.parse")
        assert rec is not None and rec.result_types(1) == ["int", "error"]

    def test_caller_uses_inferred_results(self):
        text = self.texts["main.main"]
        assert re.search(r", err := main\.parse\(", text)
        assert "err == nil" in text
        assert "int128" not in text


class TestInferredResultsIfaceGo127Stripped(GoDecompilationTarget):
    """Results of guessed callees: an itab pair is its interface, a ``(ptr, len)`` from a known callee a string."""

    BINARY = go_binary("go1.27.1", "iface_stripped")
    FUNCS = ("main.wrap", "main.box", "main.describe", "main.main")
    WARMUP_PASSES = 1

    def test_interface_and_string_results(self):
        assert self.header(self.texts["main.wrap"]).endswith(") error {")
        assert self.header(self.texts["main.box"]) == "func main.box(a0 int) any {"
        assert self.header(self.texts["main.describe"]).endswith(") string {")
        assert "return fmt.Errorf(" in self.texts["main.wrap"]

    def test_caller_sees_typed_results(self):
        text = self.texts["main.main"]
        assert "main.describe(" in text
        assert "int128" not in text and "int192" not in text


class TestHeaderWordPinsGo127Stripped(unittest.TestCase):
    """
    ``main.appendOne`` returns ``[]int{ptr, len, cap}`` whose len word is a phi over the appended length: the pass
    pins that word (and the words passed to growslice) to ``int`` as ground truth for type inference.
    """

    def test_len_and_cap_words_are_pinned(self):
        from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
        from angr.analyses.decompiler.optimization_passes.optimization_pass import (
            OptimizationPass,
            OptimizationPassStage,
        )
        from angr.go.optimization_passes import GoHeaderWordTypes, get_go_optimization_passes
        from angr.go.optimization_passes.header_word_types import GROUND_TRUTH_KEY
        from angr.go.sim_type import go_type_repr

        binary = go_binary("go1.27.1", "builtins_stripped")
        addr = go_func_addrs(binary, "main.appendOne")["main.appendOne"]
        proj, cfg = load_project_with_scoped_cfg(binary, addr, call_tree_depth=1)
        pinned: dict = {}

        class Recorder(OptimizationPass):
            ARCHES = None
            PLATFORMS = None
            STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
            NAME = "record pins"

            def __init__(self, func, manager, **kwargs):
                super().__init__(func, manager, **kwargs)
                pinned.update(self._scratch.get(GROUND_TRUTH_KEY, {}))

            def _check(self):
                return True, None

            def _analyze(self, cache=None):
                pass

        passes = DECOMPILATION_PRESETS["default"].get_optimization_passes(proj.arch, proj.simos.name)
        passes += get_go_optimization_passes()
        passes.insert(passes.index(GoHeaderWordTypes) + 1, Recorder)
        # first pass: the ([]int) result is inferred from the return; second pass: rendered with it
        proj.analyses.Decompiler(addr, cfg=cfg.model, flavor="go", fail_fast=True, use_cache=False, regen_clinic=True)
        dec = proj.analyses.Decompiler(
            addr,
            cfg=cfg.model,
            flavor="go",
            fail_fast=True,
            use_cache=False,
            regen_clinic=True,
            optimization_passes=passes,
        )
        assert dec.codegen is not None
        print_decompilation_result(dec)
        assert pinned and all(go_type_repr(t) == "int" for t in pinned.values())
        text = dec.codegen.text
        assert re.search(r"return \[\]int\{ptr: \w+, len: \w+, cap: \w+\}", text)
        assert "(*int8)(&" not in text


class TestReceiverFromName(unittest.TestCase):
    """A method's receiver type is spelled in its name, even when the linker pruned it from the method table."""

    def test_receiver_type_from_name(self):
        from angr.go.optimization_passes.prototypes import receiver_type_from_name

        proj = angr.Project(go_binary("go1.27.1", "iface_stripped"), auto_load_libs=False)
        proj.kb.go_signatures.load_sources()
        kb, arch = proj.kb, proj.arch
        assert str(receiver_type_from_name(kb, arch, "main.(*Rect).Area")) == "*main.Rect"
        assert str(receiver_type_from_name(kb, arch, "main.(*Square).Name")) == "*main.Square"
        # a two-word struct receiver passed by value spans several registers: left to the guess
        assert receiver_type_from_name(kb, arch, "main.Rect.Area") is None
        assert receiver_type_from_name(kb, arch, "main.describe") is None
        assert receiver_type_from_name(kb, arch, "main.(*Rect).Area.func1") is None
        assert receiver_type_from_name(kb, arch, "main.(*Nope).Area") is None
