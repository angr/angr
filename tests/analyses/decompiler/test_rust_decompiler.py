#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import networkx

import angr
from angr.analyses.decompiler.edits import rename_variable
from angr.rust.sim_type import RustSimEnum, RustSimType
from angr.rust.utils.rust_sigs import get_default_sig_dir
from tests.common import bin_location, recover_call_tree_cfg

RUST_BINARIES_BASE = os.path.join(bin_location, "tests", "x86_64", "rust", "coreutils")


def rust_binary_path(configuration: str, binary: str) -> str:
    return os.path.join(RUST_BINARIES_BASE, configuration, binary)


def executable_regions(proj: angr.Project) -> list[tuple[int, int]]:
    """Address ranges of the executable sections of the main object."""
    return [
        (sec.vaddr, sec.vaddr + sec.memsize)
        for sec in proj.loader.main_object.sections
        if sec.is_executable and sec.memsize > 0
    ]


class TestRustcVersionIdentification(unittest.TestCase):
    """Test that RustcVersionIdentification correctly identifies the rustc version for coreutils binaries."""

    EXPECTED_VERSIONS = {
        "nightly-2023-05-22-O3": "1.71.0",
        "nightly-2025-05-22-O3": "1.88.0",
        "nightly-2025-05-22-O0": "1.88.0",
    }

    #: How many bytes at the end of each executable section the pre-built CFG covers.
    CFG_TAIL_BYTES = 128 * 1024

    def test_default_sig_dir(self):
        sig_dir = get_default_sig_dir()
        self.assertTrue(sig_dir is not None, "get_default_sig_dir() returned None")

    def _check_fmt_version(self, configuration):
        path = rust_binary_path(configuration, "fmt")
        assert os.path.isfile(path)
        expected = self.EXPECTED_VERSIONS[configuration]
        p = angr.Project(path)
        # Pre-build a sampled, region-limited CFG so this test does not pay for a whole-binary one.
        #
        # rustc ships std/core/alloc as prebuilt rlibs, and the linker emits the crate's own object files before those
        # rlibs, so the library code the FLIRT signatures actually describe sits at the end of .text. Hence we limit
        # the CFG to the last 128 KB of each executable section for better speed.
        regions = [
            (sec.vaddr + sec.memsize - min(self.CFG_TAIL_BYTES, sec.memsize), sec.vaddr + sec.memsize)
            for sec in p.loader.main_object.sections
            if sec.is_executable and sec.memsize > 0
        ]
        p.analyses.CFGFast(normalize=True, regions=regions)
        p.analyses.RustcVersionIdentification()
        version = p.rustc_version
        self.assertEqual(version, expected, f"fmt [{configuration}]: expected {expected}, got {version}")

    def test_fmt_version_nightly_2023_05_22_O3(self):
        self._check_fmt_version("nightly-2023-05-22-O3")

    def test_fmt_version_nightly_2025_05_22_O3(self):
        self._check_fmt_version("nightly-2025-05-22-O3")

    def test_fmt_version_nightly_2025_05_22_O0(self):
        self._check_fmt_version("nightly-2025-05-22-O0")


class RustDecompilationTarget(unittest.TestCase):
    """Base class for per-binary Rust decompilation tests.

    A subclass pins one binary (``BINARY``) and any number of functions inside it
    (``FUNC_ADDRS``: ``{func_label: {configuration: address}}``).
    :meth:`decompile_functions` builds one Project per referenced configuration,
    decompiles every listed function against it, and returns the codegen text
    keyed as ``{label: {configuration: text}}``. Each feature ``test_*`` method
    calls it and asserts against the function it cares about under ``subTest`` so
    a failure in one configuration doesn't hide failures in others.

    Adding a feature assertion = a new ``test_*`` method. Adding a function to
    an existing binary = a new ``FUNC_ADDRS`` entry. Adding a binary = a new
    subclass.
    """

    BINARY: str = ""
    FUNC_ADDRS: dict[str, dict[str, int]] = {}

    #: When set, CFG recovery is scoped to the functions in ``FUNC_ADDRS`` plus this many levels of
    #: callees instead of scanning the whole binary.
    CALL_TREE_DEPTH: int | None = None

    #: Recover the CFG by recursive descent from the functions under test instead of scanning the whole binary.
    CFG_FROM_FUNCS_UNDER_TEST: bool = False

    #: Limit the call depth of complete calling convention analysis. None refers to the entire call tree.
    #: We manually tuned CCC_CALL_DEPTH for each test case to get equivalent decompilation output to a whole-binary
    #: run; we may need a different CCC_CALL_DEPTH value in the future when angr decompiler changes substantially.
    CCC_CALL_DEPTH: int | None = None

    def decompile_functions(self):
        """Decompile every function in ``FUNC_ADDRS`` and return ``{label: {configuration: codegen_text}}``.

        One Project is built per configuration referenced by ``FUNC_ADDRS``;
        configurations whose binary is missing are skipped.
        """
        decompilations = {label: {} for label in self.FUNC_ADDRS}
        configs_needed = {config for addrs in self.FUNC_ADDRS.values() for config in addrs}
        for config in configs_needed:
            path = rust_binary_path(config, self.BINARY)
            assert os.path.isfile(path), f"{path} not found"
            # The function and CFG-node spill caches cost ~20% of CFG recovery on these binaries and save no
            # measurable memory at this size, so keep everything resident.
            proj = angr.Project(path, auto_load_libs=False, cache_limits={"functions": None, "cfg_nodes": None})
            assert proj.is_rust_binary, f"{path} is not identified as a rust binary."
            func_addrs = {
                addr for per_config_addrs in self.FUNC_ADDRS.values() if (addr := per_config_addrs.get(config))
            }
            if self.CALL_TREE_DEPTH is not None:
                recover_call_tree_cfg(proj, func_addrs, depth=self.CALL_TREE_DEPTH)
            elif self.CFG_FROM_FUNCS_UNDER_TEST:
                proj.analyses.CFGFast(
                    normalize=True,
                    regions=executable_regions(proj),
                    start_at_entry=False,
                    function_starts=sorted(func_addrs),
                    force_smart_scan=False,
                )
            else:
                proj.analyses.CFGFast(normalize=True)
            callgraph = proj.kb.functions.callgraph
            ccc_funcs = set(func_addrs)
            for addr in func_addrs:
                if self.CCC_CALL_DEPTH is None:
                    ccc_funcs |= networkx.descendants(callgraph, addr)
                else:
                    ccc_funcs |= set(
                        networkx.single_source_shortest_path_length(callgraph, addr, cutoff=self.CCC_CALL_DEPTH)
                    )
            proj.analyses.CompleteCallingConventions(prioritize_func_addrs=ccc_funcs, skip_other_funcs=True)
            proj.rustc_version = TestRustcVersionIdentification.EXPECTED_VERSIONS[config]
            proj.analyses.RustSymbolRecovery()
            proj.analyses.TypeDBLoader()
            for label, per_config_addrs in self.FUNC_ADDRS.items():
                func_addr = per_config_addrs.get(config)
                if func_addr is None:
                    continue
                func = proj.kb.functions[func_addr]
                dec = proj.analyses.Decompiler(func=func, flavor="rust")
                assert dec.codegen is not None, f"Decompiler produced no codegen for {self.BINARY}::{label} [{config}]"
                assert dec.codegen.text is not None, (
                    f"Decompiler produced no codegen text for {self.BINARY}::{label} [{config}]"
                )
                decompilations[label][config] = dec.codegen.text
        return decompilations


class _FmtTests(RustDecompilationTarget):
    """Feature tests for functions in the ``fmt`` coreutils binary.

    The concrete subclasses below each pin a single rustc configuration so the
    decompilation work (one Project build per configuration) is split across
    independently-runnable test cases instead of one slow case that builds
    every configuration up front. Each function gets a single ``test_*`` method
    that asserts every recovered feature, skipping configurations whose binary
    does not contain that function.
    """

    BINARY = "fmt"

    def _check_uumain(self):
        uumain = self.decompile_functions().get("uumain")
        assert uumain, "uumain not decompiled for this configuration"
        for config, text in uumain.items():
            with self.subTest(configuration=config):
                self.assertIn('format!("invalid width: {}"', text, f"Expected to see the format! macro [{config}]")
                self.assertRegex(text, r"Option<struct\d+>", f"Expected an Option<T> type annotation [{config}]")
                self.assertRegex(
                    text,
                    r"Result<struct\d+, struct\d+>",
                    f"Expected a Result<T, E> type annotation [{config}]",
                )
                # The optimized build lowers the Result match to an `if let Ok(...)`; the -O0 build does not.
                if config == "nightly-2025-05-22-O3":
                    self.assertRegex(
                        text,
                        r"if let Ok\([^)]*\) = v\d+ \{",
                        f"Expected to see an if let Ok(...) pattern [{config}]",
                    )

        self._check_codegen_recovers_struct_literals("fmt:uumain", uumain)

    def _check_parse_arguments(self):
        parse_arguments = self.decompile_functions().get("parse_arguments")
        assert parse_arguments, "parse_arguments not decompiled for this configuration"
        expected_macros = (
            'format!("Invalid WIDTH specification: {}: {}"',
            "format!(\"invalid width: '{}': Numerical result out of range\"",
            'format!("Invalid GOAL specification: {}: {}"',
            'format!("Invalid TABWIDTH specification: {}: {}"',
        )
        for config, text in parse_arguments.items():
            with self.subTest(configuration=config):
                for needle in expected_macros:
                    self.assertIn(needle, text, f"Expected to see {needle!r} [{config}]")
                self.assertRegex(
                    text,
                    r"fn sub_[0-9a-f]+\(.*\) -> Result<struct\d+, struct\d+>",
                    f"Expected Result<T, E> function return type [{config}]",
                )
                self.assertIn("return Ok(struct112 {", text, f"Expected Ok(struct112 {{ ... }}) return [{config}]")

        self._check_codegen_recovers_struct_literals("fmt:parse_arguments", parse_arguments)

    def _check_codegen_recovers_struct_literals(self, label, decompilations):
        struct_literal = re.compile(r"=\s*struct\d+ \{\n\s+field_")
        for config, text in decompilations.items():
            with self.subTest(function=label, configuration=config):
                self.assertRegex(text, struct_literal, f"Expected a recovered struct literal [{label} {config}]")


class TestFmtNightly20250522O3(_FmtTests):
    """``fmt`` decompilation feature tests for the nightly-2025-05-22-O3 build."""

    FUNC_ADDRS = {
        "uumain": {"nightly-2025-05-22-O3": 0x496920},
    }
    CFG_FROM_FUNCS_UNDER_TEST = True
    CCC_CALL_DEPTH = 4

    def test_uumain_2025052203(self):
        self._check_uumain()


class TestFmtNightly20250522O0(_FmtTests):
    """``fmt`` decompilation feature tests for the nightly-2025-05-22-O0 build."""

    FUNC_ADDRS = {
        "uumain": {"nightly-2025-05-22-O0": 0x4D42F0},
    }
    CALL_TREE_DEPTH = 5

    def test_uumain_2025052200(self):
        self._check_uumain()


class TestFmtNightly20230522O3(_FmtTests):
    """``fmt`` decompilation feature tests for the nightly-2023-05-22-O3 build."""

    FUNC_ADDRS = {
        "parse_arguments": {"nightly-2023-05-22-O3": 0x416160},
    }
    CFG_FROM_FUNCS_UNDER_TEST = True
    CCC_CALL_DEPTH = 4

    def test_parse_arguments_2023052203(self):
        self._check_parse_arguments()


class TestFlavorSwitch(unittest.TestCase):
    """Decompiling a function with the Rust flavor and then the C flavor must not reuse Rust-flavor variables."""

    FUNC_ADDR = 0x4359E0  # its local v2 is typed Result<T, E> by the Rust flavor

    @classmethod
    def _project(cls) -> angr.Project:
        proj = angr.Project(rust_binary_path("nightly-2023-05-22-O3", "fmt"), auto_load_libs=False)
        recover_call_tree_cfg(proj, [cls.FUNC_ADDR], depth=1)
        proj.analyses.CompleteCallingConventions(prioritize_func_addrs=[cls.FUNC_ADDR], skip_other_funcs=True)
        proj.rustc_version = TestRustcVersionIdentification.EXPECTED_VERSIONS["nightly-2023-05-22-O3"]
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        return proj

    def test_rust_then_c_flavor(self):
        func_addr = self.FUNC_ADDR
        # the reference: a C-only decompilation
        proj = self._project()
        c_only = proj.analyses.Decompiler(proj.kb.functions[func_addr], fail_fast=True)
        assert c_only.codegen is not None and c_only.codegen.text is not None
        c_only_prototype = str(proj.kb.functions[func_addr].prototype)

        proj = self._project()
        func = proj.kb.functions[func_addr]
        c_prototype_before = str(func.prototype)
        assert not func.has_prototype_for_flavor("rust")

        dec = proj.analyses.Decompiler(func, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        # the Rust flavor keeps its prototype apart from the C one
        assert func.has_prototype_for_flavor("rust")
        assert str(func.prototype) == c_prototype_before
        varman = proj.kb.dec_variables[func_addr]
        assert varman.flavor == "rust"
        assert any(isinstance(ty, RustSimEnum) for ty in varman.variable_to_types.values())
        rust_varman = varman
        rust_var_ids = {id(v) for v in rust_varman.variable_to_types}
        # globals are kept per flavor too: the Rust run never touches the C global manager
        global_managers = proj.kb.dec_variables.global_managers
        assert "rust" in global_managers
        assert global_managers["rust"].flavor == "rust"
        assert global_managers["rust"].get_variables()
        assert not any(
            isinstance(ty, RustSimType) for ty in proj.kb.dec_variables.global_manager.variable_to_types.values()
        )

        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        varman = proj.kb.dec_variables[func_addr]
        assert varman.flavor == "pseudocode"
        # a fresh manager: no variables (or their types) left over from the Rust-flavor run
        assert varman is not rust_varman
        assert rust_var_ids.isdisjoint(id(v) for v in varman.variable_to_types)
        # the C flavor never runs the Rust type translator, so no Rust type at all
        assert not any(isinstance(ty, RustSimType) for ty in varman.variable_to_types.values())
        assert not any(
            isinstance(ty, RustSimType) for ty in proj.kb.dec_variables.global_manager.variable_to_types.values()
        )
        assert "Result<" not in dec.codegen.text
        # the Rust run left no trace in the C output or the C prototype
        assert str(func.prototype) == c_only_prototype
        assert dec.codegen.text == c_only.codegen.text

        # user renames of the Rust flavor survive switching back to it
        rename_variable(proj, func, "v1", "user_named", flavor="rust")
        dec = proj.analyses.Decompiler(func, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "user_named" in dec.codegen.text


FMT_ARGUMENTS_BASE = os.path.join(bin_location, "tests", "x86_64", "rust", "fmt_arguments")


class TestRustcVersionFromComment(unittest.TestCase):
    """RustcVersionIdentification reads the rustc version from .comment without matching any signatures."""

    def _detect(self, binary: str) -> str | None:
        proj = angr.Project(os.path.join(FMT_ARGUMENTS_BASE, binary), auto_load_libs=False)
        proj.analyses.RustcVersionIdentification()
        return proj.rustc_version

    def test_patch_release_maps_to_minor_release(self):
        # "rustc version 1.93.1"
        assert self._detect("fmtdemo-1.93.1") == "1.93.0"

    def test_newer_than_known_signatures(self):
        # "rustc version 1.98.1"; 1.93.0 is the newest version with signatures
        newest = max(
            tuple(int(x) for x in f.split("-O")[0].split("."))
            for f in os.listdir(os.path.join(get_default_sig_dir(), "inline"))
            if f.endswith("-O3.sig")
        )
        assert self._detect("fmtdemo-1.98.1") == ".".join(str(x) for x in newest)


class TestPastel(unittest.TestCase):
    """Regression tests on pastel 0.12.0 built with rustc 1.92.0 -O3."""

    BINARY = os.path.join(bin_location, "tests", "x86_64", "rust", "pastel")

    def _decompile(self, func_addr: int, depth: int = 0):
        proj = angr.Project(self.BINARY, auto_load_libs=False)
        recover_call_tree_cfg(proj, [func_addr], depth=depth)
        proj.analyses.CompleteCallingConventions(prioritize_func_addrs=[func_addr], skip_other_funcs=True)
        proj.rustc_version = "1.92.0"
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(proj.kb.functions[func_addr], flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_float_comparison_in_string_cmp_outliner(self):
        # pastel::Color::to_rgb_hex_string: CmpEQ against a float constant
        self._decompile(0x4E3CD0)

    def test_rust_calling_convention_phi_with_undefined_source(self):
        # pastel::commands::io::number_arg: a Phi source on the ret2arg0 path has no definition
        with self.assertNoLogs("angr.rust.analyses.rust_calling_convention.rust_calling_convention", level="ERROR"):
            self._decompile(0x47BD20)

    def test_return_type_without_colon(self):
        # pastel::Color::to_rgb_hex_string returns a struct; Rust types render as `name: type` and the name is empty
        text = self._decompile(0x4E3CD0, depth=1)
        assert " -> struct" in text and " -> :" not in text


class TestRustFormatMacrosTemplateLayout(unittest.TestCase):
    """rustc >= 1.93 passes fmt::Arguments as a {template, args} pair with a byte-encoded template."""

    @staticmethod
    def _decompile(binary: str, func_addrs: list[int], call_depth: int | None = None) -> dict[int, str]:
        proj = angr.Project(os.path.join(FMT_ARGUMENTS_BASE, binary), auto_load_libs=False)
        if call_depth is None:
            proj.analyses.CFGFast(
                normalize=True,
                regions=executable_regions(proj),
                start_at_entry=False,
                function_starts=func_addrs,
                force_smart_scan=False,
            )
        else:
            recover_call_tree_cfg(proj, func_addrs, depth=call_depth)
        callgraph = proj.kb.functions.callgraph
        ccc_funcs = set(func_addrs)
        for addr in func_addrs:
            if call_depth is None:
                ccc_funcs |= networkx.descendants(callgraph, addr)
            else:
                ccc_funcs |= set(networkx.single_source_shortest_path_length(callgraph, addr, cutoff=call_depth))
        proj.analyses.CompleteCallingConventions(prioritize_func_addrs=ccc_funcs, skip_other_funcs=True)
        proj.analyses.RustcVersionIdentification()
        assert proj.rustc_version == "1.93.0"
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        out = {}
        for addr in func_addrs:
            dec = proj.analyses.Decompiler(proj.kb.functions[addr], flavor="rust", fail_fast=True)
            assert dec.codegen is not None and dec.codegen.text is not None
            out[addr] = dec.codegen.text
        return out

    def test_format_macros(self):
        expected = {
            0x411150: 'println!("value = {}", &v0);',  # print_one
            0x411190: 'println!("name {} at {:?}!", &v1, &v0);',  # print_two
            0x410520: 'println!("just a literal");',  # print_const: string-literal representation
            0x4104C0: 'format!("{}-{}", &v0, &v1)',  # make_string
            0x411100: 'format!("0x{:08x} {:>5}", &v0, &v0)',  # hex_width
            0x4110B0: 'println!("{0} {1} {0}", &v1, &v0);',  # reorder: explicit argument indices
            0x4111F0: 'writeln!(a0, "v: {}", &v0)',  # write_out
            0x411230: 'write!(a0, "[{}]", &v1)',  # write_str
        }
        texts = self._decompile("fmtdemo-1.93.1", list(expected))
        for addr, needle in expected.items():
            with self.subTest(func=hex(addr)):
                assert needle in texts[addr], texts[addr]
                assert "_print(" not in texts[addr] and "format_inner(" not in texts[addr]

    def test_lto_specialized_eprint(self):
        # LTO specialized std::io::stdio::_eprint for its only caller and dropped the constant template argument
        text = self._decompile("hexyl-0.17.0-1.93.1", [0x460400], call_depth=1)[0x460400]
        assert 'eprintln!("Error: {:?}", &v0);' in text, text
        assert "_eprint(" not in text


class TestXsv(unittest.TestCase):
    """Regression tests on xsv 0.13.0 built with rustc 1.92.0 -O3."""

    BINARY = os.path.join(bin_location, "tests", "x86_64", "rust", "xsv")

    def _decompile(self, func_addr: int, depth: int = 0):
        proj = angr.Project(self.BINARY, auto_load_libs=False)
        recover_call_tree_cfg(proj, [func_addr], depth=depth)
        proj.analyses.CompleteCallingConventions(prioritize_func_addrs=[func_addr], skip_other_funcs=True)
        proj.rustc_version = "1.92.0"
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(proj.kb.functions[func_addr], flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_function_like_macro_returnty(self):
        # xsv::cmd::split::Args::new_writer: DerefCoercionSimplifier reads the return type of a format!() macro
        text = self._decompile(0x576300, depth=1)
        assert "format!(" in text


def _rust_showcase_binary(name: str) -> str:
    return os.path.join(bin_location, "tests", "x86_64", "rust", name)


class TestHyperfineMain(unittest.TestCase):
    """hyperfine::main calls hyperfine::run(), which returns Result<(), anyhow::Error> in rax."""

    FUNC_ADDR = 0x471850
    RUN_ADDR = 0x46D350

    @classmethod
    def _decompile(cls) -> str:
        proj = angr.Project(_rust_showcase_binary("hyperfine"), auto_load_libs=False)
        recover_call_tree_cfg(proj, [cls.FUNC_ADDR], depth=1)
        proj.analyses.CompleteCallingConventions(
            prioritize_func_addrs=[cls.FUNC_ADDR, cls.RUN_ADDR], skip_other_funcs=True
        )
        dec = proj.analyses.Decompiler(cls.FUNC_ADDR, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_main_has_no_arguments(self):
        # callees of main should clobber caller-saved registers even without prototypes
        assert "hyperfine::main(void)" in self._decompile()


class TestJqlNicheDecodedSwitches(unittest.TestCase):
    """jql_runner::array::get_array_index dispatches on niche-encoded serde_json::Value discriminants through two jump
    tables without bounds checks: `idx = (d <s 0) ? d ^ 0x8000000000000000 : 5`."""

    FUNC_ADDR = 0x4E63B0
    ENTRY_CHECK = r"if v\d+ == 9223372036854775812 && a1 < \*\(\(a2 \+ 24\) as &i64\) \{"

    @classmethod
    def _project_and_cfg(cls, **cfg_kwargs):
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "rust", "jql"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True, regions=[(cls.FUNC_ADDR, 0x4E6D80)], function_starts=[cls.FUNC_ADDR], **cfg_kwargs
        )
        return proj, cfg

    def test_unresolved_jump_tables_keep_function_body(self):
        # blocks ending in an unresolved indirect jump have unknown successors and must not be removed as redundant
        proj, cfg = self._project_and_cfg(resolve_indirect_jumps=False)
        dec = proj.analyses.Decompiler(self.FUNC_ADDR, cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "9223372036854775812" in dec.codegen.text
        assert dec.codegen.text.count("goto ") == 2

    def test_niche_decoded_switches(self):
        proj, cfg = self._project_and_cfg()
        for flavor, keyword in (("pseudocode", "switch ("), ("rust", "match (")):
            with self.subTest(flavor=flavor):
                dec = proj.analyses.Decompiler(self.FUNC_ADDR, cfg=cfg.model, flavor=flavor, fail_fast=True)
                assert dec.codegen is not None and dec.codegen.text is not None
                text = dec.codegen.text
                assert text.count(keyword) == 2
                assert "goto" not in text
                assert "incomplete" not in text
                assert text.count("<alloc::string::String as core::clone::Clone>::clone(") == 2
                assert text.count("<indexmap::inner::Core<K,V> as core::clone::Clone>::clone(") == 2
                if flavor == "rust":
                    assert re.search(self.ENTRY_CHECK, text)
                    assert "5 => {" in text


class TestGrexMain(unittest.TestCase):
    """grex::cli::handle_input returns an Option in rax:rdx."""

    FUNC_ADDR = 0x50F250

    def test_option_returned_in_two_registers(self):
        proj = angr.Project(_rust_showcase_binary("grex"), auto_load_libs=False)
        recover_call_tree_cfg(proj, [self.FUNC_ADDR], depth=2)
        callgraph = proj.kb.functions.callgraph
        ccc_funcs = set(networkx.single_source_shortest_path_length(callgraph, self.FUNC_ADDR, cutoff=2))
        proj.analyses.CompleteCallingConventions(prioritize_func_addrs=ccc_funcs, skip_other_funcs=True)
        proj.rustc_version = "1.92.0"
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(self.FUNC_ADDR, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "fn grex::main() {" in text
        m = re.search(r"(v\d+) = grex::cli::handle_input\(&v\d+, &v\d+\);", text)
        assert m is not None
        # the low register of the returned Option carries its discriminant
        assert f"if let Some(_) = {m.group(1)} {{" in text


if __name__ == "__main__":
    unittest.main()
