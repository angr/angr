from __future__ import annotations

import os
import unittest

import pytest

# angr.rust.utils.rust_sigs locates the Rust FLIRT signature directory via angrmanagement's bundled
# submodule (angrmanagement/resources/flirt_signatures), but only when angrmanagement has already
# been imported. Importing it here puts it in sys.modules so RustcVersionIdentification can find the
# signatures. angr-management is installed in the main CI test jobs; environments without it
# (e.g., the smoketest on Windows/macOS) skip the whole module at collection time.
pytest.importorskip("angrmanagement")

import angr

BINARIES_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries", "tests", "x86_64", "rust", "coreutils"
)

COREUTILS_BINS = [
    "fmt",
]


def _detect_version(binary_path):
    p = angr.Project(binary_path)
    p.analyses.RustcVersionIdentification()
    return p.rustc_version


class TestRustcVersionIdentification(unittest.TestCase):
    """Test that RustcVersionIdentification correctly identifies the rustc version for coreutils binaries."""

    def test_nightly_2023_O3(self):
        bin_dir = os.path.join(BINARIES_BASE, "nightly-2023-05-22-O3")
        if not os.path.isdir(bin_dir):
            self.skipTest("nightly-2023-05-22-O3 binaries not found")
        for name in COREUTILS_BINS:
            path = os.path.join(bin_dir, name)
            if not os.path.isfile(path):
                continue
            with self.subTest(binary=name, toolchain="nightly-2023-05-22-O3"):
                version = _detect_version(path)
                self.assertEqual(version, "1.71.0", f"{name}: expected 1.71.0, got {version}")

    def test_nightly_2025_O3(self):
        bin_dir = os.path.join(BINARIES_BASE, "nightly-2025-05-22-O3")
        if not os.path.isdir(bin_dir):
            self.skipTest("nightly-2025-05-22-O3 binaries not found")
        for name in COREUTILS_BINS:
            path = os.path.join(bin_dir, name)
            if not os.path.isfile(path):
                continue
            with self.subTest(binary=name, toolchain="nightly-2025-05-22-O3"):
                version = _detect_version(path)
                self.assertEqual(version, "1.88.0", f"{name}: expected 1.88.0, got {version}")

    def test_nightly_2025_O0(self):
        bin_dir = os.path.join(BINARIES_BASE, "nightly-2025-05-22-O0")
        if not os.path.isdir(bin_dir):
            self.skipTest("nightly-2025-05-22-O0 binaries not found")
        for name in COREUTILS_BINS:
            path = os.path.join(bin_dir, name)
            if not os.path.isfile(path):
                continue
            with self.subTest(binary=name, toolchain="nightly-2025-05-22-O0"):
                version = _detect_version(path)
                self.assertEqual(version, "1.88.0", f"{name}: expected 1.88.0, got {version}")


if __name__ == "__main__":
    unittest.main()
