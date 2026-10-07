#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import json
import os
import re
import unittest
from types import MethodType, SimpleNamespace
from typing import TYPE_CHECKING, cast

import archinfo
import cle

import angr
from angr.ailment import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Load,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, ConditionalJump
from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPass,
    OptimizationPassStage,
)
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
from angr.analyses.decompiler.structured_codegen.go import (
    GoStructuredCodeGenerator,
    _go_method_name,
)
from angr.calling_conventions import SimCCGoARM, SimCCGoX86, SimStackArg, SimStructArg
from angr.go import GO_FLAVOR
from angr.go.analyses.runtime_globals import find_write_barrier
from angr.go.knowledge_plugins.go_signatures import (
    GoInferredSignature,
    is_placeholder_type,
    placeholder_group,
)
from angr.go.optimization_passes import GoHeaderWordTypes, get_go_optimization_passes
from angr.go.optimization_passes.header_word_types import GROUND_TRUTH_KEY
from angr.go.optimization_passes.prototype_inference import (
    GoPrototypeInference,
    _is_interface_pair,
    _ResultEvidence,
)
from angr.go.optimization_passes.prototypes import receiver_type_from_name
from angr.go.sim_type import GoSimType, GoSimTypeFunction, go_type_repr
from angr.go.utils.names import is_go_closure_name
from angr.knowledge_plugins.functions.function import PrototypeSource
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def go_binary(version: str, name: str, arch: str = "x86_64") -> str:
    return os.path.join(test_location, arch, "go", version, name)


def stack_offsets(locs) -> set[int]:
    """Stack offsets of argument locations that must all be on the stack."""
    locs = list(locs)
    assert all(isinstance(loc, SimStackArg) for loc in locs), locs
    return {loc.stack_offset for loc in locs if isinstance(loc, SimStackArg)}


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
    Per-binary base: pins one corpus binary and the functions to decompile. Decompilation runs once per class, in
    FUNCS order, on a scoped CFG so every feature assertion stays cheap.
    """

    BINARY: str = ""
    FUNCS: tuple[str, ...] = ()
    CALL_TREE_DEPTH = 1
    # bytes scanned after each function start (load_project_with_scoped_cfg's window)
    WINDOW = 0x2000
    # decompile everything this many extra times first, so signatures inferred from one function reach the others
    WARMUP_PASSES = 0

    proj: angr.Project
    cfg: angr.analyses.cfg.CFGFast
    addrs: dict[str, int] = {}
    texts: dict[str, str] = {}
    codegens: dict = {}

    @classmethod
    def setUpClass(cls):
        if not cls.BINARY:
            raise unittest.SkipTest("abstract target")
        cls.addrs = go_func_addrs(cls.BINARY, *cls.FUNCS)
        first, *rest = (cls.addrs[n] for n in cls.FUNCS)
        cls.proj, cls.cfg = load_project_with_scoped_cfg(
            cls.BINARY, first, extra_func_addrs=rest, call_tree_depth=cls.CALL_TREE_DEPTH, window=cls.WINDOW
        )
        for _ in range(cls.WARMUP_PASSES):
            for name in cls.FUNCS:
                cls.proj.analyses.Decompiler(
                    cls.addrs[name], cfg=cls.cfg.model, flavor="go", fail_fast=True, use_cache=False, regen_clinic=True
                )
        cls.codegens = {}
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
        cls.codegens[name] = dec.codegen
        return dec.codegen.text

    @staticmethod
    def header(text: str) -> str:
        return next(line for line in text.splitlines() if line.startswith("func "))

    def run_checks(self):
        """Run every check_* method as a subtest: one test item per class, so xdist never repeats the setup."""
        checks = sorted(name for name in dir(self) if name.startswith("check_"))
        assert checks
        for name in checks:
            with self.subTest(check=name.removeprefix("check_")):
                getattr(self, name)()


# check mixins are combined with a target class; type them as one
if TYPE_CHECKING:
    TargetChecks = GoDecompilationTarget
else:
    TargetChecks = object


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

    def test_basics(self):
        self.run_checks()

    def check_prototypes_and_declarations(self):
        assert self.proj.is_go_binary
        assert (self.addrs["main.fib"], "go") in self.proj.kb.decompilations
        assert "go" in self.proj.kb.decompilations.all_flavors(self.addrs["main.fib"])
        assert self.header(self.texts["main.parse"]) == "func main.parse(s string) (int, error) {"
        assert self.header(self.texts["main.divmod"]) == "func main.divmod(a int, b int) (int, int) {"
        assert self.header(self.texts["main.fib"]) == "func main.fib(n int) int {"
        assert self.header(self.texts["main.main"]) == "func main.main() {"
        assert "void" not in self.texts["main.main"]
        text = self.texts["main.fib"]
        # locals are declared the Go way: a short declaration at first assignment, or a var line
        assert " := " in text or "    var " in text, text
        assert ";  //" not in text  # C-style declaration trailer
        assert "main.fib(" in text.split("{", 1)[1]

    def check_flavor_owned_knowledge(self):
        # Go prototypes and package-variable types belong to the "go" flavor; the C flavor's knowledge is untouched
        parse = self.proj.kb.functions[self.addrs["main.parse"]]
        assert parse.has_prototype_for_flavor(GO_FLAVOR)
        proto = parse.get_prototype(GO_FLAVOR)
        assert isinstance(proto, GoSimTypeFunction) and proto.repr("f") == "func f(s string) (int, error)"
        assert parse.get_prototype_source(GO_FLAVOR) == PrototypeSource.SIGNATURES
        assert not isinstance(parse.prototype, GoSimTypeFunction)
        dvars = self.proj.kb.dec_variables
        go_globals = {
            v.name: dvars.get_global_manager(GO_FLAVOR).get_variable_type(v)
            for v in dvars.get_global_manager(GO_FLAVOR).get_variables()
        }
        assert str(go_globals["os.Args"]) == "[]string"
        c_globals = dvars.get_global_manager(None)
        assert not any(isinstance(c_globals.get_variable_type(v), GoSimType) for v in c_globals.get_variables())

    def check_main(self):
        main = self.texts["main.main"]
        # package variables are typed
        assert "os.Args []string" in main
        assert "main.counter int" in main
        assert "if len(os.Args) <= 1 {" in main
        assert "main.parse(os.Args[1])" in main
        assert "xmm15" not in main
        # print/println sequences fold into one call
        assert re.search(r"^\s+println\([^\n]+, main\.counter\)$", main, re.MULTILINE), main
        assert "runtime.print" not in main
        assert not main.rstrip().endswith("return\n}")
        # values are fused at call sites
        assert 'main.count("hello, world", ' in main
        assert re.search(r"main\.sum\(\w+\)", main), main
        assert re.search(r"main\.parse\([^,()]+\)$", main, re.MULTILINE), main
        # the parsed value reaches n through the phi of a call's result register; a stack array is a slice literal
        main = main[main.index("func main.main") :]
        m = re.search(r"^\s+(\w+), err := main\.parse\(os\.Args\[1\]\)$", main, re.MULTILINE)
        assert m, main
        assert re.search(rf"^\s+\w+ = {m.group(1)}$", main, re.MULTILINE), main
        assert re.search(r"main\.bump\(\[\]int\{1, 2, 3, \w+\}\)", main), main

    def check_multiple_results_and_spills(self):
        assert re.search(r"return \w+, \w+$", self.texts["main.divmod"], re.MULTILINE)
        parse = self.texts["main.parse"]
        # multi-result calls are destructured and the error checked idiomatically
        assert re.search(r"^\s+\w+, err :?= strconv\.Atoi\(s\)$", parse, re.MULTILINE), parse
        assert "if err != nil {" in parse
        assert "return 0, err\n" in parse
        assert "return 0, main.errNegative\n" in parse
        assert re.search(r"return \w+, nil$", parse, re.MULTILINE), parse
        assert "~r" not in parse
        # parse spills its string argument into the caller-provided slot and never reads it back
        body = parse.split("{", 1)[1]
        assert not re.search(r"^\s+\w+ = a\d+;$", body, re.MULTILINE), body

    def check_statements_and_runtime_cleanup(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert "morestack" not in text
                # the compare against g.stackguard0 (r14+16) must not survive either
                assert "+ 16)" not in text
                body = text.split("{", 1)[1]
                assert not re.search(r";\s*$", body, re.MULTILINE), text
                assert "if (" not in body and "while" not in body and "->" not in body
                assert ".ptr[" not in text and ".len" not in text, text
        fib = self.texts["main.fib"]
        assert "if n > 1 {" in fib
        assert "return n\n" in fib
        parse = self.texts["main.parse"]
        assert "!= nil {" in parse or "== nil {" in parse
        assert "else if " in parse
        assert re.search(r"for \w+ :?= range s \{", self.texts["main.count"]), self.texts["main.count"]
        assert re.search(r"if s\[\w+\] == c \{", self.texts["main.count"])
        assert re.search(r"for \w+ :?= range xs \{", self.texts["main.bump"])
        assert "return xs\n" in self.texts["main.bump"]
        text = self.texts["runtime.acquirem"]
        assert "var g *runtime.g" in text
        assert "g.m" in text


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


class TestCIsmsGo127AArch64(GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "basics", arch="aarch64")
    FUNCS = ("main.divmod", "main.parse", "main.fib", "main.manhattan")

    def test_frame_saves_arithmetic_and_comparisons(self):
        # the prologue's x30/x29 stores are not program state
        for name in ("main.divmod", "main.parse", "main.fib"):
            text = self.texts[name]
            assert "// x30" not in text and "[bp+0x0]" not in text, text
        divmod_text = self.texts["main.divmod"]
        assert "return a / b, a - b * (a / b)" in divmod_text, divmod_text
        parse = self.texts["main.parse"]
        assert "} else if num < 0 {" in parse, parse
        assert "if n > 1 {" in self.texts["main.fib"], self.texts["main.fib"]
        manhattan = self.texts["main.manhattan"]
        assert "if p.x >= 0 {" in manhattan and "0 <=" not in manhattan, manhattan


class TestEndlessLoopGo127(GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "basics")
    FUNCS = ("os.ignoringEINTR",)

    def test_endless_loop_has_no_condition(self):
        text = self.texts["os.ignoringEINTR"]
        assert re.search(r"^\s+for \{$", text, re.MULTILINE), text
        assert "for 1" not in text, text


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


class Swaps(TargetChecks):
    """
    ``s[i], s[j] = s[j], s[i]``: the element loaded before the first store must reach the second store as a
    temporary, not be re-read after it was overwritten.
    """

    FUNCS = ("main.swapInts", "main.swapPairs", "main.swapNodes")

    @staticmethod
    def body(text: str) -> list[str]:
        lines = text[text.index("func main.") :].splitlines()[1:]
        return [line.strip() for line in lines if line.strip() not in ("", "}")]

    def test_swaps_keep_their_temporaries(self):
        body = self.body(self.texts["main.swapInts"])
        m = re.fullmatch(r"(\w+) := s\[(\w+)\]", body[0])
        assert m, body
        tmp, i = m.groups()
        m = re.fullmatch(rf"s\[{i}\] = s\[(\w+)\]", body[1])
        assert m, body
        assert body[2] == f"s[{m.group(1)}] = {tmp}", body
        # a slot written by an earlier statement is never loaded by a later one; casts do not tell slots apart
        for name in self.FUNCS:
            stored: list[str] = []
            for line in self.body(self.texts[name]):
                lhs, sep, rhs = re.sub(r"\(\*u?int\d+\)", "", line).partition(" = ")
                if not sep:
                    continue
                assert not any(slot in rhs for slot in stored), (name, line, stored)
                stored.append(lhs)
            assert len(stored) >= 2, name


class TestSwapGo127(Swaps, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "swap")


class TestSwapGo122(Swaps, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "swap")


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


class TestRecvI386Go127(GoDecompilationTarget):
    """
    386 lays string headers out as two 4-byte words: a struct holding one is 8 bytes, its ``len`` sits at 4, a
    struct value receiver spans two stack words, and the stack result of ``Error`` is read back as ``len(...)``.
    """

    BINARY = go_binary("go1.27.1", "recv", arch="i386")
    FUNCS = ("main.gitHubRecipientError.Error", "main.main", "runtime/debug.SetTraceback")

    def test_recv(self):
        self.run_checks()

    def check_string_layout_and_struct_receiver(self):
        name = "main.gitHubRecipientError.Error"
        sigs = self.proj.kb.go_signatures
        sigs.load_sources()
        string = sigs.type("string").with_arch(self.proj.arch)
        assert string.size == 64 and string.offsets == {"ptr": 0, "len": 4}
        recv = sigs.type("main.gitHubRecipientError").with_arch(self.proj.arch)
        assert recv.size == 64 and recv.fields["username"].offsets == {"ptr": 0, "len": 4}
        assert sigs.type("[]byte").with_arch(self.proj.arch).size == 96

        proto = sigs.prototype(name)
        cc = SimCCGoX86.for_prototype(self.proj.arch, proto)
        (loc,) = cc.arg_locs(proto)
        assert isinstance(loc, SimStructArg)
        assert stack_offsets(loc.get_footprint()) == {4, 8}
        # the string result follows the receiver on the stack
        ret_loc = cc.return_val(proto.returnty)
        assert ret_loc is not None
        assert stack_offsets(ret_loc.get_footprint()) == {12, 16}

        text = self.texts[name]
        assert "func (e main.gitHubRecipientError) Error() string {" in text
        assert 'return "github recipient " + e' in text and '+ " has no public keys"' in text
        assert "os.Exit(len(main.gitHubRecipientError.Error(" in self.texts["main.main"]

    def check_switch_cases_are_string_compares(self):
        # 386 compares strings four bytes at a time: the switch cases of SetTraceback still come back as strings
        text = self.texts["runtime/debug.SetTraceback"]
        for lit in ("all", "none", "crash", "single", "system"):
            assert re.search(rf' [!=]= "{lit}"', text), lit
        assert "1701736302" not in text and "1935766115" not in text


class TestMapsArmGo127(GoDecompilationTarget):
    """
    A map read on 32-bit arm folds to m[k]: the fold labels the result words with arm's r0/r1 (it raised KeyError for
    an arch other than amd64/arm64/386).
    """

    BINARY = os.path.join(test_location, "armel", "go", "go1.27.1", "maps")
    FUNCS = ("main.lookup", "main.byInt", "main.lookupOk")
    WINDOW = 0x400

    def test_maps_arm(self):
        self.run_checks()

    def check_map_index(self):
        for name in ("main.lookup", "main.byInt"):
            text = self.texts[name]
            assert re.search(r"^\s+return m\[k\]$", text, re.MULTILINE), text
            assert "mapaccess1" not in text, text
        # the comma-ok read decompiles; its results live on the stack, which the two-word fold does not handle yet
        assert "func main.lookupOk(" in self.texts["main.lookupOk"]


class TestLangdetectArmGo127(GoDecompilationTarget):
    """
    32-bit arm is ABI0 only: arguments from 4(R13), above the saved-LR slot, and results after them. Under AAPCS the
    string argument of strconv.Atoi came out with its words swapped and both of its results were lost.
    """

    BINARY = os.path.join(test_location, "armel", "langdetect_go")
    FUNCS = ("main.main",)
    WINDOW = 0x400

    def test_langdetect_arm(self):
        self.run_checks()

    def check_stack_args_and_results(self):
        assert isinstance(self.proj.kb.functions[self.addrs["main.main"]].calling_convention, SimCCGoARM)
        proto = self.proj.kb.go_signatures.prototype("strconv.Atoi")
        cc = SimCCGoARM.for_prototype(self.proj.arch, proto)
        (loc,) = cc.arg_locs(proto)
        assert stack_offsets(loc.get_footprint()) == {4, 8}
        ret_loc = cc.return_val(proto.returnty)
        assert ret_loc is not None
        assert stack_offsets(ret_loc.get_footprint()) == {12, 16, 20}

        text = self.texts["main.main"]
        assert re.search(r"(\w+), (\w+) := strconv\.Atoi\(os\.Args\[1\]\)\n\s+if \2 == nil", text)
        assert re.search(r"\w+, \w+ := fmt\.Fprintf\(os\.Stdout, \"fibonacci\(%d\) = %d\\n\"", text)


class TestBasicsGo127Stripped(GoDecompilationTarget):
    """
    ``main.parse`` has no signature source (stripped, not in the stdlib database): its results come from its own
    returns (``strconv.Atoi``'s error, the int it returns as is) and reach ``main.main`` on the second pass. Package
    variables have no symbols: runtime globals are located by shape, package variables typed by their initializers.
    """

    BINARY = go_binary("go1.27.1", "basics_stripped")
    FUNCS = ("main.parse", "main.main", "main.init")
    WARMUP_PASSES = 1

    def test_basics_stripped(self):
        self.run_checks()

    def check_results_inferred_from_returns(self):
        assert self.header(self.texts["main.parse"]) == "func main.parse(a0 string) (int, error) {"
        rec = self.proj.kb.go_signatures.inferred_record("main.parse")
        assert rec is not None and rec.result_types(1) == ["int", "error"]
        text = self.texts["main.main"]
        assert re.search(r", err := main\.parse\(", text)
        assert "err == nil" in text
        assert "int128" not in text

    def check_package_variables(self):
        # the unstripped twin carries the data symbols the shapes must reproduce
        loader = cle.Loader(go_binary("go1.27.1", "basics"), auto_load_libs=False)
        found = {v.name: v.addr for v in self.proj.kb.go_globals.variables.values()}
        for name in ("runtime.writeBarrier", "runtime.zerobase", "runtime.staticuint64s", "runtime.firstmoduledata"):
            assert found[name] == loader.find_symbol(name).rebased_addr, name
        init = self.texts["main.init"]
        assert "main.var_0 error" in init
        assert "main.var_0.tab = " in init and "main.var_0.data = " in init
        main = self.texts["main.main"]
        assert re.search(r"os\.var_\d+ \[\]string", main), main
        assert re.search(r"if len\(os\.var_\d+\) <= 1 \{", main), main


class TestIfaceGo127Stripped(GoDecompilationTarget):
    """
    Results of guessed callees: an itab pair is its interface, a ``(ptr, len)`` from a known callee a string. Calls
    through an itab bind both result registers, so a string's length is no unassigned ``rbx`` local after the call.
    """

    BINARY = go_binary("go1.27.1", "iface_stripped")
    FUNCS = ("main.wrap", "main.box", "main.describe", "main.report", "main.main")
    WARMUP_PASSES = 1

    def test_interface_and_string_results(self):
        assert self.header(self.texts["main.wrap"]).endswith(") error {")
        assert self.header(self.texts["main.box"]) == "func main.box(a0 int) any {"
        assert self.header(self.texts["main.describe"]).endswith(") string {")
        assert "return fmt.Errorf(" in self.texts["main.wrap"]
        text = self.texts["main.main"]
        assert "main.describe(" in text
        assert "int128" not in text and "int192" not in text
        for name in ("main.describe", "main.report"):
            text = self.texts[name]
            assert not re.search(r"^    var \w+ [^/]*// (rbx|rcx|rdi|rsi|r8|r9|r10|r11)$", text, re.MULTILINE), text


class TestSpilledHeadersGo127Stripped(GoDecompilationTarget):
    """
    ``spill.go``: a slice and a string whose address is taken live in stack memory and are returned from there. The
    header words of the returned value form one variable of the slice/string type (seeded from the fused return once
    the callee results are inferred), so the return is ``return v, err`` rather than the words spelled out.
    """

    BINARY = go_binary("go1.27.1", "spill_stripped")
    FUNCS = ("main.piece", "main.name", "main.gather", "main.joined")
    WARMUP_PASSES = 1

    def test_headers_are_one_variable(self):
        text = self.texts["main.gather"]
        assert self.header(text).endswith(") ([]uint8, error) {")
        assert re.search(r"^\s+var (\w+) \[\]uint8", text, re.MULTILINE)
        assert re.search(r"return \w+, nil$", text, re.MULTILINE)
        assert re.search(r"return \w+, \S+$", text, re.MULTILINE)
        returns = [line for line in text.splitlines() if line.strip().startswith("return ")]
        assert returns and all("{" not in line and "unsafe.Pointer" not in line for line in returns)
        # the fields the append reads are the variable itself, and the grown header is written back in one piece
        assert re.search(r"(\w+) = append\(\1, \w+\.\.\.\)", text)
        assert not re.search(r"\w+\.(ptr|len|cap) = ", text)
        # zeroed word by word (one word plus a 16-byte store) before its address escapes
        assert re.search(r"^\s+\w+ = nil$", text, re.MULTILINE)

        text = self.texts["main.joined"]
        assert self.header(text).endswith(") (string, error) {")
        assert re.search(r"return \w+, err$", text, re.MULTILINE)
        assert re.search(r"return \w+, nil$", text, re.MULTILINE)
        assert "unsafe.Pointer(&" not in text and "string{ptr:" not in text


class TestHeaderWordPinsGo127Stripped(unittest.TestCase):
    """
    ``main.appendOne`` returns ``[]int{ptr, len, cap}`` whose len word is a phi over the appended length: the pass
    pins that word (and the words passed to growslice) to ``int`` as ground truth for type inference.
    """

    def test_len_and_cap_words_are_pinned(self):
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
        assert text is not None
        # the slice header is returned (or fed to the folded append) with its len and cap words as plain ints, or
        # is the parameter itself
        assert re.search(r"return (?:append\()?(?:\[\]int\{ptr: \w+, len: \w+, cap: \w+\}|a0, a1\))", text)
        assert "(*int8)(&" not in text
        assert self.header(text).endswith(") []int {")

    @staticmethod
    def header(text: str) -> str:
        return next(line for line in text.splitlines() if line.startswith("func "))


class TestNames(unittest.TestCase):
    def test_receivers_and_closures_from_names(self):
        # a method's receiver type is spelled in its name, even when the linker pruned it from the method table
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
        # a method value wrapper gets its receiver through the closure context, not its first argument
        assert receiver_type_from_name(kb, arch, "main.(*Rect).Area-fm") is None
        # without a CFG there are no write-barrier call sites to locate runtime.writeBarrier by
        assert find_write_barrier(proj) is None

        # a closure in a function with an exported name looks like a method of a type with that name
        assert _go_method_name("github.com/junegunn/fzf/src.NewTerminal.func2") is None
        assert _go_method_name("main.Rect.Area") == "Area"
        for name in ("pkg.F.func1", "pkg.F.func1.2", "pkg.F.func1.gowrap3", "pkg.(*T).M-fm", "pkg.F-range1"):
            assert is_go_closure_name(name), name
        assert not is_go_closure_name("pkg.(*T).funcName")


class TestInferredSignatureRecords(unittest.TestCase):
    def test_result_words_and_groups(self):
        rec = GoInferredSignature()
        rec.merge(caller_results={1: ("bool", 1)}, result_words=2)
        assert rec.has_results and rec.result_types(1) == ["uintptr", "bool"]
        rec.merge(result_words=3)
        assert rec.result_types(1) == ["uintptr", "bool", "uintptr"]
        # records survive a JSON round trip through set_inferred
        again = GoInferredSignature()
        again.merge(dict(rec)["params"], dict(rec)["results"], dict(rec)["caller_results"], dict(rec)["result_words"])
        assert again.result_words == 3

        rec = GoInferredSignature()
        rec.merge(groups={2: (2, None)}, result_words=4)
        # an untyped group stays one element, as a struct of words (an array would leave the result registers)
        assert rec.result_types(1) == ["uintptr", "uintptr", placeholder_group(2)]
        assert is_placeholder_type(placeholder_group(2)) and not is_placeholder_type("error")
        # a typed caller-side pair wins over the placeholder
        rec.merge(caller_results={2: ("error", 2)})
        assert rec.result_types(1) == ["uintptr", "uintptr", "error"]
        # the callee's own results win over both
        rec.merge(results={2: ("int", 1), 3: ("int", 1)})
        assert rec.result_types(1) == ["uintptr", "uintptr", "int", "int"]
        # groups survive the JSON round trip of a whole record
        again = GoInferredSignature()
        again.merge(None, None, None, 0, json.loads(json.dumps(dict(rec)))["groups"])
        assert again.groups == {2: (2, None)}


class TestResultPairEvidence(unittest.TestCase):
    """
    The itab-shape rule: a nil-checked result word dereferenced at +8 is an interface pair only when the load is the
    nil-guarded ``itab.Type`` read (an iface-to-eface conversion); a bare nil check plus ``Load(w + 8)`` is what a
    ``(*T, n)`` result looks like and must stay two scalars.
    """

    def _evidence(self, guarded: bool):
        arch = archinfo.ArchAMD64()
        stub = SimpleNamespace(
            project=SimpleNamespace(arch=arch),
            kb=SimpleNamespace(go_types=SimpleNamespace(itab_at=lambda a: None)),
            _values=SimpleNamespace(resolve=lambda e: e, combo_of={}, defs={}),
        )
        stub._piece = MethodType(GoPrototypeInference._piece, stub)
        r0 = VirtualVariable(0, 1, 64, VVC.REGISTER, oident=16)
        r1 = VirtualVariable(1, 2, 64, VVC.REGISTER, oident=40)
        combo = VirtualVariable(
            2,
            3,
            128,
            VVC.COMBO_REGISTER,
            reg_vvars=[r0, r1],  # pyright: ignore[reportArgumentType]  # the stub types reg_vvars as a dict
        )
        word = Load(3, UnaryOp(4, "Reference", combo), 8, "Iend_LE")
        nil_check = ConditionalJump(
            1, BinaryOp(5, "CmpEQ", [word, Const(6, 0, 64)]), Const(7, 0x20, 64), Const(8, 0x30, 64), ins_addr=0x10
        )
        deref8 = Load(9, BinaryOp(10, "Add", [word, Const(11, 8, 64)]), 8, "Iend_LE")
        if guarded:
            deref8 = ITE(14, BinaryOp(15, "CmpEQ", [word, Const(16, 0, 64)]), Const(17, 0, 64), deref8, bits=64)
        x = VirtualVariable(12, 4, 64, VVC.REGISTER, oident=24)
        block = Block(
            0x10,
            16,
            statements=[
                Assignment(0, combo, Call(13, "f", [], bits=128), ins_addr=0x10),
                nil_check,
                Assignment(2, x, deref8, ins_addr=0x10),
            ],
        )
        evidence = _ResultEvidence(cast(GoPrototypeInference, stub), {3: ("f", 2)})
        evidence.walk(block)
        return evidence.flags[(3, 0)]

    def test_bare_nil_check_and_load_is_not_an_interface(self):
        assert self._evidence(guarded=False) == {"nil"}
        assert not _is_interface_pair(self._evidence(guarded=False))
        assert _is_interface_pair(self._evidence(guarded=True))


if __name__ == "__main__":
    unittest.main()
