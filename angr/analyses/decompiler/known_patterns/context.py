"""PatternContext: the architecture / platform / language facts a KnownPattern
template needs to instantiate itself for a given binary.

A pattern is defined once as a :class:`~.pattern.KnownPatternTemplate` whose
``build(ctx)`` computes concrete field offsets, load sizes, and return types
from a ``PatternContext`` — so a single definition covers 32- and 64-bit,
libstdc++ and MSVC, etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr.project import Project

# MSVC RTTI type descriptor: ``.?AV<name>@@`` (class) / ``.?AU<name>@@`` (struct).
_MSVC_RTTI_RE = re.compile(rb"\.\?A[VU][\w@?$]{1,255}?@@")
# Itanium ABI (libstdc++/libc++) typeinfo-name / typeinfo / vtable symbol names.
_ITANIUM_RTTI_RE = re.compile(rb"_ZT[ISV][A-Za-z0-9_]{2,255}")

# C++ runtime identifiers
LIBSTDCXX = "libstdcxx"
MSVC = "msvc"

# language identifiers
C = "c"
CPP = "cpp"

# the Intel arch family the STL/vecmath patterns are calibrated on
INTEL = frozenset({"X86", "AMD64"})


def size_t_typename(bits: int) -> str:
    """The C spelling of size_t for a given word width."""
    return "unsigned long long" if bits >= 64 else "unsigned int"


def _deps(project: Project) -> list[str]:
    return [d.lower() for d in getattr(project.loader.main_object, "deps", None) or []]


def _mangled_symbol_prefixes(project: Project) -> set[str]:
    """The set of C++ mangling prefixes present among the binary's own symbols
    ({"_Z"} Itanium/libstdc++, {"?"} MSVC)."""
    prefixes: set[str] = set()
    try:
        symbols = project.loader.main_object.symbols
    except (AttributeError, TypeError):
        return prefixes
    for sym in symbols:
        name = getattr(sym, "name", None)
        if not name:
            continue
        if name.startswith("_Z"):
            prefixes.add("_Z")
        elif name.startswith("?"):
            prefixes.add("?")
    return prefixes


def _rtti_evidence(project: Project) -> str | None:
    """Scan initialized data sections for C++ RTTI type descriptors, which
    survive even when a binary is statically linked (no runtime-DLL dependency)
    and stripped (no C++ symbols) — e.g. a static MSVC build whose only import
    is kernel32. MSVC emits ``.?AV…@@`` / ``.?AU…@@`` type descriptors; the
    Itanium ABI (libstdc++/libc++) emits ``_ZTS``/``_ZTI``/``_ZTV`` names."""
    try:
        sections = project.loader.main_object.sections
    except (AttributeError, TypeError):
        return None
    for sec in sections or []:
        if getattr(sec, "is_executable", False) or getattr(sec, "only_contains_uninitialized_data", False):
            continue
        size = min(getattr(sec, "filesize", 0) or 0, getattr(sec, "memsize", 0) or 0)
        if size <= 0:
            continue
        try:
            data = project.loader.memory.load(sec.vaddr, size)
        except Exception:  # pylint:disable=broad-except  (best-effort fallback)
            continue
        if _MSVC_RTTI_RE.search(data):
            return MSVC
        if _ITANIUM_RTTI_RE.search(data):
            return LIBSTDCXX
    return None


def detect_cxx_runtime(project: Project) -> str | None:
    """Identify the C++ standard-library runtime: ``"msvc"``, ``"libstdcxx"``,
    or None. Mirrors the old is_cpp_binary / is_msvc_cpp_binary heuristics:
    dependency names first, then mangled-symbol evidence (mingw PEs link
    libstdc++ and use its layouts even though they are PEs), then — for
    statically-linked, stripped binaries that carry neither — RTTI type
    descriptors embedded in data sections."""
    deps = _deps(project)
    if any("msvcp" in d for d in deps):
        return MSVC
    if any("libstdc++" in d for d in deps):
        return LIBSTDCXX
    prefixes = _mangled_symbol_prefixes(project)
    if "_Z" in prefixes:
        return LIBSTDCXX
    if "?" in prefixes:
        return MSVC
    return _rtti_evidence(project)


@dataclass(frozen=True)
class PatternContext:
    """Target facts used to instantiate pattern templates."""

    arch_name: str
    bits: int
    ptr_size: int  # bytes
    platform: str | None  # "linux" / "windows" / ...
    cxx_runtime: str | None  # LIBSTDCXX / MSVC / None
    is_cpp: bool

    @classmethod
    def from_project(cls, project: Project) -> PatternContext:
        os_name = getattr(project.simos, "name", None) if project.simos is not None else None
        simos = os_name.lower() if os_name else None
        # normalize a few common simos names to a platform family
        platform = simos
        if simos is not None:
            if "win" in simos:
                platform = "windows"
            elif "linux" in simos:
                platform = "linux"
        runtime = detect_cxx_runtime(project)
        return cls(
            arch_name=project.arch.name,
            bits=project.arch.bits,
            ptr_size=project.arch.bytes,
            platform=platform,
            cxx_runtime=runtime,
            is_cpp=runtime is not None,
        )

    def word(self, n: int) -> int:
        """Byte offset of the ``n``-th pointer-word field."""
        return n * self.ptr_size

    @property
    def word_size(self) -> int:
        """Load size (bytes) of a pointer / size_t field."""
        return self.ptr_size

    @property
    def language(self) -> str:
        return CPP if self.is_cpp else C
