"""Known code patterns: declarative descriptions of library/macro idioms that
compilers inline, and machinery (KnownPatternFinder) to find them in Clinic AIL
graphs and outline them back into calls."""

from __future__ import annotations

from .containing_record import CONTAINING_RECORD_PATTERN
from .dsl import (
    PAny,
    PAssign,
    PBinOp,
    PBlockPat,
    PChoice,
    PConst,
    PConv,
    PGraphPat,
    PLoad,
    PStmtSeq,
    PStore,
    PUnaryOp,
    PVVar,
)
from .finder import KnownPatternFinder, KnownPatternMatch, OutlineResult, UnsupportedOutlineError
from .pattern import CppRef, KnownPattern, PatternParam, TypeRef
from .std_string_length import STD_STRING_LENGTH
from .std_vector_size import (
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_SHORT_SIZE,
    make_std_vector_size_pattern,
)

ALL_KNOWN_PATTERNS: list[KnownPattern] = []
KNOWN_PATTERNS_BY_CALL_NAME: dict[str, KnownPattern] = {}


def register_known_pattern(pattern: KnownPattern) -> None:
    """Register a KnownPattern so that finders and the decompiler pipeline can
    use it, and so that its call prototype is applied wherever its synthesized
    call appears."""
    if pattern.call_name in KNOWN_PATTERNS_BY_CALL_NAME:
        raise ValueError(f"a known pattern with call name {pattern.call_name!r} is already registered")
    ALL_KNOWN_PATTERNS.append(pattern)
    KNOWN_PATTERNS_BY_CALL_NAME[pattern.call_name] = pattern


register_known_pattern(STD_STRING_LENGTH)
register_known_pattern(STD_VECTOR_SHORT_SIZE)
register_known_pattern(STD_VECTOR_INT_SIZE)
register_known_pattern(STD_VECTOR_LONG_LONG_SIZE)
register_known_pattern(CONTAINING_RECORD_PATTERN)


__all__ = [
    "ALL_KNOWN_PATTERNS",
    "CONTAINING_RECORD_PATTERN",
    "KNOWN_PATTERNS_BY_CALL_NAME",
    "STD_STRING_LENGTH",
    "STD_VECTOR_INT_SIZE",
    "STD_VECTOR_LONG_LONG_SIZE",
    "STD_VECTOR_SHORT_SIZE",
    "CppRef",
    "KnownPattern",
    "KnownPatternFinder",
    "KnownPatternMatch",
    "OutlineResult",
    "PAny",
    "PAssign",
    "PBinOp",
    "PBlockPat",
    "PChoice",
    "PConst",
    "PConv",
    "PGraphPat",
    "PLoad",
    "PStmtSeq",
    "PStore",
    "PUnaryOp",
    "PVVar",
    "PatternParam",
    "TypeRef",
    "UnsupportedOutlineError",
    "make_std_vector_size_pattern",
    "register_known_pattern",
]
