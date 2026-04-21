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
        for cfg in ALL_RUST_CONFIGS:
            try:
                func(self, *args, configuration=cfg, **kwargs)
                ran += 1
            except unittest.SkipTest:
                continue
        if ran == 0:
            raise unittest.SkipTest("no rust binaries found for any configuration")

    return inner


def rust_configs(*configs: str):
    """Run a test once per configuration passed to the decorator, injecting ``configuration`` as a kwarg."""

    def _wrap(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            ran = 0
            for cfg in configs:
                try:
                    func(self, *args, configuration=cfg, **kwargs)
                    ran += 1
                except unittest.SkipTest:
                    continue
            if ran == 0:
                raise unittest.SkipTest(f"no rust binaries found for any of {list(configs)}")

        return inner

    return _wrap


class TestRustcVersionIdentification(unittest.TestCase):
    """Test that RustcVersionIdentification correctly identifies the rustc version for coreutils binaries."""

    EXPECTED_VERSIONS = {
        "nightly-2023-05-22-O3": "1.71.0",
        "nightly-2025-05-22-O3": "1.88.0",
        "nightly-2025-05-22-O0": "1.88.0",
    }

    def test_default_sig_dir(self):
        sig_dir = get_default_sig_dir()
        self.assertTrue(os.path.isdir(sig_dir), f"Default sig dir {sig_dir} does not exist")

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


if __name__ == "__main__":
    unittest.main()
