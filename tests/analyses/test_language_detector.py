#!/usr/bin/env python3
# pylint:disable=no-self-use
"""Tests for the LanguageDetector analysis using mock binary objects."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
from collections import defaultdict
import unittest
from unittest.mock import MagicMock

import angr
from angr.analyses.language_detector import LanguageDetector, LanguageDetectionResult, LanguageDetectionConfidenceLevel

from tests.common import bin_location


def _make_mock_project(
    symbols=None,
    sections=None,
    deps=None,
    compiler=(None, None),
    compilation_units=None,
    memory_data=None,
):
    """Build a mock angr.Project with the given binary metadata."""
    # Build mock symbol objects
    mock_symbols = []
    for name in symbols or []:
        sym = MagicMock()
        sym.name = name
        mock_symbols.append(sym)

    # Build mock section objects
    mock_sections = []
    for name in sections or []:
        sec = MagicMock()
        sec.name = name
        mock_sections.append(sec)

    # Build mock compilation units
    mock_cus = []
    for lang in compilation_units or []:
        cu = MagicMock()
        cu.language = lang
        mock_cus.append(cu)

    # Build mock memory
    mock_memory = MagicMock()
    if memory_data is not None:
        mock_memory.backers.return_value = [(0, memory_data)]
    else:
        mock_memory.backers.return_value = []

    # Assemble main_object
    main_obj = MagicMock()
    main_obj.symbols = mock_symbols
    main_obj.sections = mock_sections
    main_obj.deps = deps or []
    main_obj.compiler = compiler
    main_obj.compilation_units = mock_cus or None
    main_obj.memory = mock_memory

    # Assemble loader
    loader = MagicMock()
    loader.main_object = main_obj

    # Assemble project
    project = MagicMock(spec=angr.Project)
    project.loader = loader
    project.kb = angr.KnowledgeBase(project)

    return project


def _run_detector(project) -> LanguageDetector:
    """Instantiate LanguageDetector with a mock project, bypassing Analysis.__init__."""
    det = LanguageDetector.__new__(LanguageDetector)
    det.project = project
    det.kb = project.kb
    det.errors = []
    det.named_errors = defaultdict(list)
    det._fail_fast = False
    det.result = LanguageDetectionResult()
    det._detect()
    return det


class TestLanguageDetectorRust(unittest.TestCase):
    """Test Rust detection via symbols."""

    def test_rust_symbols(self):
        det = _run_detector(
            _make_mock_project(
                symbols=[
                    "__rust_alloc",
                    "__rust_dealloc",
                    "__rust_realloc",
                    "some_other_func",
                ]
            )
        )
        assert det.language == "rust"
        assert det.compiler == "rustc"
        assert det.confidence in (LanguageDetectionConfidenceLevel.HIGH, LanguageDetectionConfidenceLevel.MEDIUM)
        assert any("rust" in e.lower() for e in det.evidence) is True

    def test_rust_mangled_symbols(self):
        det = _run_detector(
            _make_mock_project(
                symbols=[
                    "_ZN4core3fmt5write17h1234567890abcdefE",
                    "_ZN3std2io5stdio6_print17habcdef1234567890E",
                    "_ZN5alloc3vec8Vec$LT$T17h0000000000000000E",
                ]
            )
        )
        assert det.language == "rust"
        assert det.compiler == "rustc"

    def test_rust_string_marker(self):
        det = _run_detector(
            _make_mock_project(
                symbols=["__rust_alloc"],
                memory_data=b"\x00\x00rustc 1.75.0 (abcdef 2024-01-01)\x00\x00",
            )
        )
        assert det.language == "rust"
        assert any("string" in e or "rustc" in e for e in det.evidence) is True


class TestLanguageDetectorGo(unittest.TestCase):
    """Test Go detection via symbols and sections."""

    def test_go_symbols(self):
        det = _run_detector(
            _make_mock_project(
                symbols=[
                    "runtime.gopanic",
                    "runtime.goexit",
                    "runtime.main",
                    "main.main",
                ]
            )
        )
        assert det.language == "go"
        assert det.compiler == "gc"
        assert det.confidence in (LanguageDetectionConfidenceLevel.HIGH, LanguageDetectionConfidenceLevel.MEDIUM)

    def test_go_sections(self):
        det = _run_detector(
            _make_mock_project(
                sections=[".text", ".data", ".gopclntab", ".gosymtab"],
            )
        )
        assert det.language == "go"

    def test_go_combined(self):
        det = _run_detector(
            _make_mock_project(
                symbols=["runtime.gopanic", "runtime.goexit", "runtime.main"],
                sections=[".gopclntab"],
                memory_data=b"\x00go1.21.5\x00",
            )
        )
        assert det.language == "go"
        assert det.confidence == LanguageDetectionConfidenceLevel.HIGH


class TestLanguageDetectorSwift(unittest.TestCase):
    """Test Swift detection."""

    def test_swift_symbols(self):
        det = _run_detector(
            _make_mock_project(
                symbols=[
                    "swift_bridgeObjectRelease",
                    "swift_bridgeObjectRetain",
                    "swift_release",
                ]
            )
        )
        assert det.language == "swift"
        assert det.compiler == "swiftc"

    def test_swift_sections(self):
        det = _run_detector(
            _make_mock_project(
                sections=[".text", ".swift5_typeref", ".swift5_fieldmd"],
            )
        )
        assert det.language == "swift"

    def test_swift_dependency(self):
        det = _run_detector(
            _make_mock_project(
                deps=["libc.so.6", "libswiftCore.so"],
            )
        )
        assert det.language == "swift"
        assert any("dependency" in e for e in det.evidence) is True


class TestLanguageDetectorC(unittest.TestCase):
    """Test C detection via compiler field and DWARF."""

    def test_c_gcc_comment(self):
        det = _run_detector(
            _make_mock_project(
                compiler=("gcc", "12.2.0"),
            )
        )
        assert det.language == "c"
        assert det.compiler == "gcc"
        assert det.compiler_version == "12.2.0"

    def test_c_clang_comment(self):
        det = _run_detector(
            _make_mock_project(
                compiler=("clang", "15.0.7"),
            )
        )
        assert det.language == "c"
        assert det.compiler == "clang"
        assert det.compiler_version == "15.0.7"

    def test_c_dwarf_language(self):
        det = _run_detector(
            _make_mock_project(
                compilation_units=["DW_LANG_C99"],
            )
        )
        assert det.language == "c"

    def test_c_dwarf_cpp(self):
        det = _run_detector(
            _make_mock_project(
                compilation_units=["DW_LANG_C_plus_plus"],
            )
        )
        assert det.language == "c"


class TestLanguageDetectorUnknown(unittest.TestCase):
    """Test edge cases and unknown binaries."""

    def test_empty_binary(self):
        det = _run_detector(_make_mock_project())
        assert det.language == "unknown"
        assert det.confidence == LanguageDetectionConfidenceLevel.LOW

    def test_no_evidence(self):
        det = _run_detector(
            _make_mock_project(
                symbols=["main", "printf", "exit"],
                sections=[".text", ".data", ".bss"],
            )
        )
        # With only generic symbols, should be unknown or low confidence
        assert det.language in ("unknown", "c")

    def test_result_dataclass(self):
        r = LanguageDetectionResult()
        assert r.language == "unknown"
        assert r.compiler is None
        assert r.compiler_version is None
        assert r.confidence == LanguageDetectionConfidenceLevel.LOW
        assert r.evidence == []  # pylint:disable=use-implicit-booleaness-not-comparison


class TestLanguageDetectorMixedSignals(unittest.TestCase):
    """Test binaries with evidence from multiple languages."""

    def test_rust_dominates(self):
        """Rust symbols should dominate over a gcc .comment section."""
        det = _run_detector(
            _make_mock_project(
                compiler=("gcc", "12.2.0"),
                symbols=[
                    "__rust_alloc",
                    "__rust_dealloc",
                    "__rust_realloc",
                    "__rust_alloc_zeroed",
                ],
            )
        )
        # Rust symbols (10 pts) should beat C compiler comment (5 pts)
        assert det.language == "rust"

    def test_go_sections_plus_symbols(self):
        """Go sections + symbols reinforce each other."""
        det = _run_detector(
            _make_mock_project(
                symbols=["runtime.gopanic"],
                sections=[".gopclntab"],
            )
        )
        assert det.language == "go"
        assert det.confidence == LanguageDetectionConfidenceLevel.HIGH


class TestLanguageDetectorWithRealBinaries(unittest.TestCase):
    """Integration tests using real compiled test binaries."""

    def _try_load(self, path):
        full = os.path.join(bin_location, "tests", path)
        if not os.path.exists(full):
            self.skipTest(f"Test binary not found: {full}")
        return angr.Project(full, auto_load_libs=False)

    def test_x86_64_fauxware(self):
        """fauxware is a simple C binary compiled with gcc."""
        proj = self._try_load("x86_64/fauxware")
        det = proj.analyses.LanguageDetector()
        # fauxware is C, but without .comment it may be unknown
        assert det.language in ("c", "unknown")

    # ---- Real compiled binaries in language_detector/ ----

    def test_real_gcc(self):
        """C binary compiled with gcc - detected via .comment section."""
        proj = self._try_load("x86_64/langdetect_gcc")
        det = proj.analyses.LanguageDetector()
        assert det.language == "c"
        assert det.compiler == "gcc"
        assert det.compiler_version is not None
        assert any("gcc" in e for e in det.evidence) is True

    def test_real_gcc_dwarf(self):
        """C binary compiled with gcc -g, has DWARF debug info."""
        proj = self._try_load("x86_64/langdetect_gcc_dwarf")
        det = proj.analyses.LanguageDetector()
        assert det.language == "c"
        assert det.compiler == "gcc"
        # Should find both DWARF and .comment evidence
        has_dwarf = any("dwarf" in e.lower() for e in det.evidence)
        has_compiler = any("cle_compiler" in e for e in det.evidence)
        assert has_dwarf or has_compiler is True

    def test_real_gcc_stripped(self):
        """Fully stripped C binary with no symbols and no .comment."""
        proj = self._try_load("x86_64/langdetect_gcc_stripped")
        det = proj.analyses.LanguageDetector()
        # Stripped binary with no .comment - very little to go on
        assert det.language in ("c", "unknown")
        assert det.confidence in (LanguageDetectionConfidenceLevel.LOW, LanguageDetectionConfidenceLevel.MEDIUM)

    def test_real_clang(self):
        """Binary with .comment section patched to look like clang output."""
        proj = self._try_load("x86_64/langdetect_clang")
        det = proj.analyses.LanguageDetector()
        assert det.language == "c"
        assert det.compiler == "clang"
        assert det.compiler_version is not None
        assert any("clang" in e for e in det.evidence) is True

    def test_real_rust(self):
        """Real Rust binary compiled with rustc."""
        proj = self._try_load("x86_64/langdetect_rust")
        det = proj.analyses.LanguageDetector()
        assert det.language == "rust"
        assert det.compiler == "rustc"
        assert det.confidence == LanguageDetectionConfidenceLevel.HIGH
        # Should have symbol-based evidence
        assert len(det.evidence) > 0

    def test_real_go(self):
        """Real Go binary compiled with gc."""
        proj = self._try_load("x86_64/langdetect_go")
        det = proj.analyses.LanguageDetector()
        assert det.language == "go"
        assert det.compiler == "gc"
        assert det.confidence == LanguageDetectionConfidenceLevel.HIGH
        # Should have multiple kinds of evidence (symbols + sections + strings)
        assert len(det.evidence) >= 2

    def test_real_swift(self):
        """Binary with Swift-like symbols and sections."""
        proj = self._try_load("x86_64/langdetect_swift")
        det = proj.analyses.LanguageDetector()
        assert det.language == "swift"
        assert det.compiler == "swiftc"
        assert det.confidence in (LanguageDetectionConfidenceLevel.HIGH, LanguageDetectionConfidenceLevel.MEDIUM)
        # Should have both symbol and section evidence
        has_symbol = any("symbol" in e or "swift" in e.lower() for e in det.evidence)
        has_section = any("section" in e for e in det.evidence)
        assert has_symbol is True
        assert has_section is True


class TestLanguageDetectorWithDynamicBinaries(unittest.TestCase):
    """Integration tests using dynamically linked test binaries."""

    def _try_load(self, path):
        full = os.path.join(bin_location, "tests", path)
        if not os.path.exists(full):
            self.skipTest(f"Test binary not found: {full}")
        return angr.Project(full, auto_load_libs=False)

    def test_dynamic_gcc(self):
        """Dynamically linked C/gcc binary."""
        proj = self._try_load("x86_64/langdetect_gcc_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language == "c"
        assert det.compiler == "gcc"
        assert det.compiler_version is not None

    def test_dynamic_gcc_dwarf(self):
        """Dynamically linked C/gcc binary with DWARF."""
        proj = self._try_load("x86_64/langdetect_gcc_dwarf_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language == "c"
        assert det.compiler == "gcc"
        has_dwarf = any("dwarf" in e.lower() for e in det.evidence)
        has_compiler = any("cle_compiler" in e for e in det.evidence)
        assert has_dwarf or has_compiler is True

    def test_dynamic_gcc_stripped(self):
        """Dynamically linked, fully stripped C binary."""
        proj = self._try_load("x86_64/langdetect_gcc_stripped_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language in ("c", "unknown")
        assert det.confidence in (LanguageDetectionConfidenceLevel.LOW, LanguageDetectionConfidenceLevel.MEDIUM)

    def test_dynamic_clang(self):
        """Dynamically linked binary with clang .comment."""
        proj = self._try_load("x86_64/langdetect_clang_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language == "c"
        assert det.compiler == "clang"
        assert det.compiler_version is not None

    def test_dynamic_rust(self):
        """Dynamically linked Rust binary."""
        proj = self._try_load("x86_64/langdetect_rust_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language == "rust"
        assert det.compiler == "rustc"
        assert det.confidence in (LanguageDetectionConfidenceLevel.HIGH, LanguageDetectionConfidenceLevel.MEDIUM)

    def test_dynamic_go(self):
        """Dynamically linked Go binary (CGO_ENABLED=1)."""
        proj = self._try_load("x86_64/langdetect_go_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language == "go"
        assert det.compiler == "gc"
        assert det.confidence in (LanguageDetectionConfidenceLevel.HIGH, LanguageDetectionConfidenceLevel.MEDIUM)

    def test_dynamic_swift(self):
        """Dynamically linked fake Swift binary."""
        proj = self._try_load("x86_64/langdetect_swift_dyn")
        det = proj.analyses.LanguageDetector()
        assert det.language == "swift"
        assert det.compiler == "swiftc"
        has_symbol = any("symbol" in e or "swift" in e.lower() for e in det.evidence)
        has_section = any("section" in e for e in det.evidence)
        assert has_symbol is True
        assert has_section is True


if __name__ == "__main__":
    unittest.main()
