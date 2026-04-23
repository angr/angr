#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from functools import wraps

import angr
from angr.rust.utils.rust_sigs import get_default_sig_dir

from tests.common import bin_location

RUST_BINARIES_BASE = os.path.join(bin_location, "tests", "x86_64", "rust", "coreutils")

ALL_RUST_CONFIGS = (
    "nightly-2023-05-22-O3",
    "nightly-2025-05-22-O3",
    "nightly-2025-05-22-O0",
)


def rust_binary_path(configuration: str, binary: str) -> str:
    return os.path.join(RUST_BINARIES_BASE, configuration, binary)


def for_all_rust_configs(func):
    """Run a test once per configuration in ALL_RUST_CONFIGS, injecting ``configuration`` as a kwarg."""

    @wraps(func)
    def inner(self, *args, **kwargs):
        ran = 0
        for config in ALL_RUST_CONFIGS:
            try:
                func(self, *args, configuration=config, **kwargs)
                ran += 1
            except unittest.SkipTest:
                continue
        if ran == 0:
            raise unittest.SkipTest("no rust binaries found for any configuration")

    return inner


class TestRustcVersionIdentification(unittest.TestCase):
    """Test that RustcVersionIdentification correctly identifies the rustc version for coreutils binaries."""

    EXPECTED_VERSIONS = {
        "nightly-2023-05-22-O3": "1.71.0",
        "nightly-2025-05-22-O3": "1.88.0",
        "nightly-2025-05-22-O0": "1.88.0",
    }

    def test_default_sig_dir(self):
        sig_dir = get_default_sig_dir()
        self.assertTrue(sig_dir is not None, "get_default_sig_dir() returned None")

    @for_all_rust_configs
    def test_fmt_version(self, configuration):
        path = rust_binary_path(configuration, "fmt")
        if not os.path.isfile(path):
            self.skipTest(f"{configuration}/fmt not found")
        expected = self.EXPECTED_VERSIONS[configuration]
        p = angr.Project(path)
        p.analyses.RustcVersionIdentification()
        version = p.rustc_version
        self.assertEqual(version, expected, f"fmt [{configuration}]: expected {expected}, got {version}")


class RustDecompilationTarget(unittest.TestCase):
    """Base class for per-binary Rust decompilation tests.

    A subclass pins one binary (``BINARY``) and any number of functions inside it
    (``FUNC_ADDRS``: ``{func_label: {configuration: address}}``). ``setUpClass``
    builds the Project once per configuration, then decompiles every listed function
    against it, stashing the codegen text in ``cls.decompilations[label][config]``.
    Each feature test iterates the configs for the label it cares about under
    ``subTest`` so a failure in one configuration doesn't hide failures in others.

    Adding a feature assertion = a new method. Adding a function to an existing
    binary = a new ``FUNC_ADDRS`` entry. Adding a binary = a new subclass.
    """

    BINARY: str = ""
    FUNC_ADDRS: dict[str, dict[str, int]] = {}

    decompilations: dict[str, dict[str, str]] = {}

    @classmethod
    def setUpClass(cls):
        if cls is RustDecompilationTarget:
            raise unittest.SkipTest("base class")
        cls.decompilations = {label: {} for label in cls.FUNC_ADDRS}

        configs_needed = {config for addrs in cls.FUNC_ADDRS.values() for config in addrs}
        for config in configs_needed:
            path = rust_binary_path(config, cls.BINARY)
            if not os.path.isfile(path):
                continue
            proj = angr.Project(path, auto_load_libs=False)
            assert proj.is_rust_binary, f"{path} is not identified as a rust binary."
            proj.analyses.CFGFast(normalize=True)
            proj.analyses.CompleteCallingConventions(recover_variables=False)
            proj.analyses.RustSymbolRecovery()
            proj.analyses.TypeDBLoader()
            for label, per_config_addrs in cls.FUNC_ADDRS.items():
                func_addr = per_config_addrs.get(config)
                if func_addr is None:
                    continue
                func = proj.kb.functions[func_addr]
                dec = proj.analyses.Decompiler(func=func, flavor="rust")
                assert dec.codegen is not None, f"Decompiler produced no codegen for {cls.BINARY}::{label} [{config}]"
                assert (
                    dec.codegen.text is not None
                ), f"Decompiler produced no codegen text for {cls.BINARY}::{label} [{config}]"
                cls.decompilations[label][config] = dec.codegen.text

        if not any(cls.decompilations.values()):
            raise unittest.SkipTest(f"no rust binaries found for {cls.BINARY} in any target configuration")


class TestFmt(RustDecompilationTarget):
    """Feature tests for functions in the ``fmt`` coreutils binary."""

    BINARY = "fmt"
    FUNC_ADDRS = {
        "uumain": {
            "nightly-2025-05-22-O3": 0x496920,
            "nightly-2025-05-22-O0": 0x4D42F0,
        },
        "parse_arguments": {
            "nightly-2023-05-22-O3": 0x416160,
        },
    }

    def test_uumain_codegen_nonempty(self):
        for config, text in self.decompilations["uumain"].items():
            with self.subTest(configuration=config):
                self.assertTrue(text.strip(), f"decompilation output was empty [{config}]")

    def test_uumain_macro_recovery_format(self):
        for config, text in self.decompilations["uumain"].items():
            with self.subTest(configuration=config):
                self.assertIn('format!("invalid width: {}"', text, f"Expected to see the format! macro [{config}]")

    def test_parse_arguments_codegen_nonempty(self):
        for config, text in self.decompilations["parse_arguments"].items():
            with self.subTest(configuration=config):
                self.assertTrue(text.strip(), f"decompilation output was empty [{config}]")

    def test_parse_arguments_macro_recovery_format(self):
        expected = (
            'format!("Invalid WIDTH specification: {}: {}"',
            "format!(\"invalid width: '{}': Numerical result out of range\"",
        )
        for config, text in self.decompilations["parse_arguments"].items():
            for needle in expected:
                with self.subTest(configuration=config, needle=needle):
                    self.assertIn(needle, text, f"Expected to see {needle!r} [{config}]")


if __name__ == "__main__":
    unittest.main()
