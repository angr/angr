from __future__ import annotations

import logging
import re
import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.analyses import Analysis, AnalysesHub

if TYPE_CHECKING:
    from cle.backends import Backend

log = logging.getLogger(name=__name__)


class LanguageDetectionConfidenceLevel(enum.Enum):
    """Confidence level of language detection results."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class LanguageDetectionResult:
    """Result of language/compiler detection on a binary."""

    language: str = "unknown"  # "c", "rust", "go", "swift", "unknown"
    compiler: str | None = None  # "gcc", "clang", "msvc", "rustc", "gc", "gccgo", "swiftc", None
    compiler_version: str | None = None
    confidence: LanguageDetectionConfidenceLevel = LanguageDetectionConfidenceLevel.LOW
    evidence: list[str] = field(default_factory=list)


# Rust-specific symbol patterns
_RUST_SYMBOLS = frozenset(
    {
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "__rust_alloc_zeroed",
        "__rust_alloc_error_handler",
        "rust_begin_unwind",
        "rust_panic",
        "__rust_start_panic",
        "_ZN4core9panicking5panic",
        "_ZN3std2rt10lang_start",
    }
)

# Go-specific symbol patterns
_GO_SYMBOLS = frozenset(
    {
        "runtime.gopanic",
        "runtime.goexit",
        "runtime.mstart",
        "runtime.main",
        "runtime.newproc",
        "runtime.schedinit",
        "main.main",
        "go.buildid",
        "runtime.gcStart",
        "runtime.mallocgc",
    }
)

# Swift-specific symbol patterns
_SWIFT_SYMBOLS = frozenset(
    {
        "swift_bridgeObjectRelease",
        "swift_bridgeObjectRetain",
        "swift_release",
        "swift_retain",
        "_swift_release",
        "_swift_retain",
        "swift_allocObject",
        "_swift_allocObject",
        "$ss5print_9separator10terminatoryypd_S2StF",
    }
)

# Go-specific section names
_GO_SECTIONS = frozenset(
    {
        ".gosymtab",
        ".gopclntab",
        ".go.buildinfo",
        ".noptrdata",
        ".noptrbss",
    }
)

# Swift-specific section names (ELF and Mach-O)
_SWIFT_SECTIONS = frozenset(
    {
        ".swift5_typeref",
        ".swift5_reflstr",
        ".swift5_fieldmd",
        ".swift5_assocty",
        ".swift5_proto",
        ".swift5_types",
        ".swift5_protos",
        "__swift5_typeref",
        "__swift5_reflstr",
        "__swift5_fieldmd",
        "__swift5_types",
        "__swift5_proto",
        "__swift5_protos",
    }
)

# Regex for Rust mangled symbols: _ZN<len><module>...<len><name><17h><hex_hash>E
_RUST_MANGLED_RE = re.compile(r"_ZN[\dA-Za-z]+17h[0-9a-f]{16}E")

# Regex for Swift mangled symbols: $s..., _$s...
_SWIFT_MANGLED_RE = re.compile(r"_?\$s[A-Za-z0-9_]+")

# Regex for Go symbols: <pkg>.<name> with typical go package patterns
_GO_SYMBOL_RE = re.compile(r"^(runtime|main|sync|fmt|os|io|net|math|strings|bytes)\.")


class LanguageDetector(Analysis):
    """
    Detect the original programming language and compiler used to build a binary.

    Supports detection of C (gcc, clang, msvc), Rust, Go, and Swift through
    multiple heuristic layers: DWARF debug info, .comment sections, symbol
    patterns, section names, and linked library names.

    Usage::

        result = project.analyses.LanguageDetector()
        print(result.language)     # "rust"
        print(result.compiler)     # "rustc"
        print(result.confidence)   # "high"
        print(result.evidence)     # ["symbol: __rust_alloc", ...]
    """

    def __init__(self):
        self.result = LanguageDetectionResult()
        self._detect()

    # Convenience properties to access result fields directly
    @property
    def language(self) -> str:
        return self.result.language

    @property
    def compiler(self) -> str | None:
        return self.result.compiler

    @property
    def compiler_version(self) -> str | None:
        return self.result.compiler_version

    @property
    def confidence(self) -> LanguageDetectionConfidenceLevel:
        return self.result.confidence

    @property
    def evidence(self) -> list[str]:
        return self.result.evidence

    def _detect(self):
        obj: Backend = self.project.loader.main_object

        scores: dict[str, int] = {
            "c": 0,
            "rust": 0,
            "go": 0,
            "swift": 0,
        }
        compiler_hint: str | None = None
        compiler_version_hint: str | None = None
        evidence: list[str] = []

        # --- Layer 1: DWARF compilation units ---
        self._check_dwarf(obj, scores, evidence)

        # --- Layer 2: CLE .comment / compiler field ---
        comp_name, comp_ver = self._check_cle_compiler(obj, scores, evidence)
        if comp_name:
            compiler_hint = comp_name
            compiler_version_hint = comp_ver

        # --- Layer 3: Symbol-based heuristics ---
        self._check_symbols(obj, scores, evidence)

        # --- Layer 4: Section-based heuristics ---
        self._check_sections(obj, scores, evidence)

        # --- Layer 5: Dependencies / linked libraries ---
        self._check_dependencies(obj, scores, evidence)

        # --- Layer 6: String scanning for version markers ---
        self._check_strings(obj, scores, evidence)

        # --- Aggregate results ---
        self._aggregate(scores, evidence, compiler_hint, compiler_version_hint)

    # ------------------------------------------------------------------
    # Layer 1: DWARF
    # ------------------------------------------------------------------
    @staticmethod
    def _check_dwarf(obj: Backend, scores: dict[str, int], evidence: list[str]):
        compilation_units = getattr(obj, "compilation_units", None)
        if not compilation_units:
            return

        for cu in compilation_units:
            lang = getattr(cu, "language", None)
            if not lang:
                continue
            lang_lower = lang.lower() if isinstance(lang, str) else ""
            if "rust" in lang_lower:
                scores["rust"] += 10
                evidence.append(f"dwarf_language: {lang}")
            elif "go" in lang_lower:
                scores["go"] += 10
                evidence.append(f"dwarf_language: {lang}")
            elif "swift" in lang_lower:
                scores["swift"] += 10
                evidence.append(f"dwarf_language: {lang}")
            elif "c_plus_plus" in lang_lower or "c99" in lang_lower or "c89" in lang_lower or "c11" in lang_lower:
                scores["c"] += 5
                evidence.append(f"dwarf_language: {lang}")
            elif "c" in lang_lower:
                scores["c"] += 3
                evidence.append(f"dwarf_language: {lang}")

    # ------------------------------------------------------------------
    # Layer 2: CLE compiler field (.comment section)
    # ------------------------------------------------------------------
    @staticmethod
    def _check_cle_compiler(obj: Backend, scores: dict[str, int], evidence: list[str]) -> tuple[str | None, str | None]:
        compiler_info = getattr(obj, "compiler", (None, None))
        if compiler_info is None:
            return None, None

        comp_name, comp_ver = compiler_info
        if comp_name:
            scores["c"] += 5
            evidence.append(f"cle_compiler: {comp_name} {comp_ver}")
            return comp_name, comp_ver
        return None, None

    # ------------------------------------------------------------------
    # Layer 3: Symbols
    # ------------------------------------------------------------------
    @staticmethod
    def _check_symbols(obj: Backend, scores: dict[str, int], evidence: list[str]):
        symbols = getattr(obj, "symbols", None)
        if not symbols:
            return

        rust_count = 0
        go_count = 0
        swift_count = 0

        for sym in symbols:
            name = getattr(sym, "name", None)
            if not name:
                continue

            # Exact matches
            if name in _RUST_SYMBOLS:
                rust_count += 1
                if rust_count <= 3:
                    evidence.append(f"symbol: {name}")
            elif name in _GO_SYMBOLS:
                go_count += 1
                if go_count <= 3:
                    evidence.append(f"symbol: {name}")
            elif name in _SWIFT_SYMBOLS:
                swift_count += 1
                if swift_count <= 3:
                    evidence.append(f"symbol: {name}")
            else:
                # Regex-based matching
                if _RUST_MANGLED_RE.match(name):
                    rust_count += 1
                    if rust_count <= 3:
                        evidence.append(f"rust_mangled_symbol: {name[:60]}")
                elif _GO_SYMBOL_RE.match(name):
                    go_count += 1
                    if go_count <= 3:
                        evidence.append(f"go_symbol: {name[:60]}")
                elif _SWIFT_MANGLED_RE.match(name) and len(name) > 5:
                    swift_count += 1
                    if swift_count <= 3:
                        evidence.append(f"swift_mangled_symbol: {name[:60]}")

        if rust_count >= 3:
            scores["rust"] += 10
        elif rust_count >= 1:
            scores["rust"] += 5

        if go_count >= 3:
            scores["go"] += 10
        elif go_count >= 1:
            scores["go"] += 5

        if swift_count >= 3:
            scores["swift"] += 10
        elif swift_count >= 1:
            scores["swift"] += 5

    # ------------------------------------------------------------------
    # Layer 4: Section names
    # ------------------------------------------------------------------
    @staticmethod
    def _check_sections(obj: Backend, scores: dict[str, int], evidence: list[str]):
        sections = getattr(obj, "sections", None)
        if not sections:
            return

        section_names = set()
        for sec in sections:
            name = getattr(sec, "name", None)
            if name:
                section_names.add(name)

        go_sections = section_names & _GO_SECTIONS
        if go_sections:
            scores["go"] += 8
            for s in sorted(go_sections):
                evidence.append(f"section: {s}")

        swift_sections = section_names & _SWIFT_SECTIONS
        if swift_sections:
            scores["swift"] += 8
            for s in sorted(swift_sections):
                evidence.append(f"section: {s}")

    # ------------------------------------------------------------------
    # Layer 5: Dependencies
    # ------------------------------------------------------------------
    @staticmethod
    def _check_dependencies(obj: Backend, scores: dict[str, int], evidence: list[str]):
        deps = getattr(obj, "deps", None)
        if not deps:
            return

        for dep in deps:
            dep_lower = dep.lower() if isinstance(dep, str) else ""
            if "libswiftcore" in dep_lower or "libswift" in dep_lower:
                scores["swift"] += 6
                evidence.append(f"dependency: {dep}")
            elif "libstd" in dep_lower and "rust" in dep_lower:
                scores["rust"] += 6
                evidence.append(f"dependency: {dep}")

    # ------------------------------------------------------------------
    # Layer 6: String scanning (limited, for version markers)
    # ------------------------------------------------------------------
    @staticmethod
    def _check_strings(obj: Backend, scores: dict[str, int], evidence: list[str]):
        """Scan a limited amount of binary data for compiler/language version strings."""
        memory = getattr(obj, "memory", None)
        if memory is None:
            return

        # Only scan up to 2MB to avoid performance issues
        max_scan = 2 * 1024 * 1024
        scanned = 0
        rustc_found = False
        go_found = False

        for _start, data in memory.backers():
            if isinstance(data, bytes):
                chunk = data
            elif hasattr(data, "read"):
                continue  # skip stream-backed regions
            else:
                try:
                    chunk = bytes(data)
                except (TypeError, ValueError):
                    continue

            remaining = max_scan - scanned
            if remaining <= 0:
                break
            chunk = chunk[:remaining]
            scanned += len(chunk)

            if not rustc_found and b"rustc" in chunk:
                rustc_found = True
                scores["rust"] += 3
                # Try to extract version
                idx = chunk.find(b"rustc")
                snippet = chunk[idx : idx + 40]
                try:
                    evidence_str = snippet.split(b"\x00")[0].decode("ascii", errors="replace")[:40]
                except (IndexError, UnicodeDecodeError):
                    evidence_str = "rustc version marker (undecodable)"
                evidence.append(f"string: {evidence_str}")

            if not go_found and (b"go1." in chunk or b"Go build" in chunk or b"go.buildinfo" in chunk):
                go_found = True
                scores["go"] += 3
                evidence.append("string: Go version/build marker")

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------
    def _aggregate(
        self,
        scores: dict[str, int],
        evidence: list[str],
        compiler_hint: str | None,
        compiler_version_hint: str | None,
    ):
        result = self.result
        result.evidence = evidence

        if not any(scores.values()):
            result.language = "unknown"
            result.confidence = LanguageDetectionConfidenceLevel.LOW
            return

        best_lang = max(scores, key=scores.get)  # type:ignore
        best_score = scores[best_lang]

        # Check for ambiguity: if second-best is close, lower confidence
        sorted_scores = sorted(scores.values(), reverse=True)
        second_best = sorted_scores[1] if len(sorted_scores) > 1 else 0

        if best_score == 0:
            result.language = "unknown"
            result.confidence = LanguageDetectionConfidenceLevel.LOW
            return

        result.language = best_lang

        # Determine confidence
        if best_score >= 10 and best_score > second_best * 2:
            result.confidence = LanguageDetectionConfidenceLevel.HIGH
        elif best_score >= 5:
            result.confidence = LanguageDetectionConfidenceLevel.MEDIUM
        else:
            result.confidence = LanguageDetectionConfidenceLevel.LOW

        # Set compiler based on language and hints
        if best_lang == "rust":
            result.compiler = "rustc"
        elif best_lang == "go":
            result.compiler = "gc"  # default Go compiler
        elif best_lang == "swift":
            result.compiler = "swiftc"
        elif best_lang == "c":
            result.compiler = compiler_hint  # gcc, clang, msvc, or None

        # Compiler version
        if best_lang == "c" and compiler_version_hint:
            result.compiler_version = compiler_version_hint


AnalysesHub.register_default("LanguageDetector", LanguageDetector)
