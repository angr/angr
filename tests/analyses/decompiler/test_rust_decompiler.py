#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import networkx

import angr
from angr.rust.utils.rust_sigs import get_default_sig_dir
from tests.common import bin_location, recover_call_tree_cfg

RUST_BINARIES_BASE = os.path.join(bin_location, "tests", "x86_64", "rust", "coreutils")

# These coreutils binaries are small (1-3 MB) but statically linked, so CFGFast recovers well over ten thousand
# functions - roughly six times the size-derived default cache limit, which assumes ~512 bytes of code per function
# while these average ~50. The knowledge base then spends most of CFG recovery, and most of the FLIRT passes in
# RustSymbolRecovery, serializing functions and CFG nodes in and out of LMDB. Keeping everything resident costs
# ~0.6 GB here and is purely a memory/speed trade-off: the recovered CFG and the decompilation are byte-identical.
UNLIMITED_CACHES: dict[str, int | None] = {"functions": None, "cfg_nodes": None, "cfg_edges": None}


def rust_binary_path(configuration: str, binary: str) -> str:
    return os.path.join(RUST_BINARIES_BASE, configuration, binary)


class TestRustcVersionIdentification(unittest.TestCase):
    """Test that RustcVersionIdentification correctly identifies the rustc version for coreutils binaries."""

    EXPECTED_VERSIONS = {
        "nightly-2023-05-22-O3": "1.71.0",
        "nightly-2025-05-22-O3": "1.88.0",
        "nightly-2025-05-22-O0": "1.88.0",
    }

    #: How many bytes at the end of each executable section the pre-built CFG covers. See
    #: :meth:`_check_fmt_version` for why the *end* of the section is the right place to look.
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
        # rustc ships std/core/alloc as prebuilt rlibs, and the linker emits the crate's own object
        # files before those rlibs, so the library code the FLIRT signatures actually describe sits
        # at the *end* of .text. Measured against a whole-binary CFG of these three binaries, every
        # single core::/std::/alloc:: match in the -O0 build falls in the last 20% of .text (0 in the
        # first 80%), and in both -O3 builds the trailing deciles hold the largest share. Sampling
        # the tail therefore hits the code the signatures were built from, whereas sampling the head
        # mostly scans crate code compiled at whatever level the crate used -- which is why a
        # head-of-section sample scored the -O0 build 44 vs 43 for the runner-up (a near coin flip),
        # while the tail sample scores it 149 vs 135.
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
    #: callees instead of scanning the whole binary. Statically linked coreutils binaries carry
    #: 10k-17k functions, of which only the shallow part of the call tree influences the
    #: decompilation of the function under test; see :func:`tests.common.recover_call_tree_cfg`.
    #: Leave as ``None`` (whole-binary CFG) unless the scoped result has been verified to be
    #: byte-identical to the unscoped one.
    CALL_TREE_DEPTH: int | None = None

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
            proj = angr.Project(path, auto_load_libs=False, cache_limits=UNLIMITED_CACHES)
            assert proj.is_rust_binary, f"{path} is not identified as a rust binary."
            func_addrs = {
                addr for per_config_addrs in self.FUNC_ADDRS.values() if (addr := per_config_addrs.get(config))
            }
            if self.CALL_TREE_DEPTH is None:
                proj.analyses.CFGFast(normalize=True)
            else:
                recover_call_tree_cfg(proj, func_addrs, depth=self.CALL_TREE_DEPTH)
            call_tree = set(func_addrs)
            for addr in func_addrs:
                call_tree |= networkx.descendants(proj.kb.functions.callgraph, addr)
            proj.analyses.CompleteCallingConventions(prioritize_func_addrs=call_tree, skip_other_funcs=True)
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

    def test_uumain_2025052203(self):
        self._check_uumain()


class TestFmtNightly20250522O0(_FmtTests):
    """``fmt`` decompilation feature tests for the nightly-2025-05-22-O0 build.

    The -O0 build has 16729 functions and a whole-binary CFG costs ~90s, but ``uumain`` only needs
    the top of its call tree: five levels of callees (865 functions) reproduce the whole-binary
    decompilation byte for byte, while four levels do not (two callee prototypes lose their
    struct-return form, so ``format!`` stops yielding a ``String``).
    """

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

    def test_parse_arguments_2023052203(self):
        self._check_parse_arguments()


if __name__ == "__main__":
    unittest.main()
