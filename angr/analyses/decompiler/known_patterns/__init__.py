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
    PCondJump,
    PConst,
    PConv,
    PGraphPat,
    PLoad,
    PPhi,
    PStmtSeq,
    PStore,
    PUnaryOp,
    PVVar,
)
from .finder import KnownPatternFinder, KnownPatternMatch, OutlineResult, UnsupportedOutlineError
from .generator import PatternGenerationError, PatternGenerator
from .linked_list import (
    ALL_LINKED_LIST_PATTERNS,
    INITIALIZE_LIST_HEAD,
    IS_LIST_EMPTY,
    REMOVE_ENTRY_LIST,
)
from .pattern import CppRef, KnownPattern, PatternParam, TypeRef
from .protobuf_hasbits import ALL_PROTOBUF_PATTERNS
from .std_string_length import STD_STRING_LENGTH, STD_STRING_LENGTH_MSVC
from .std_swap import STD_SWAP_8
from .std_vector_size import (
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_SHORT_SIZE,
    make_std_vector_size_pattern,
)
from .stl_containers import ALL_STL_CONTAINER_PATTERNS

ALL_KNOWN_PATTERNS: list[KnownPattern] = []
KNOWN_PATTERNS_BY_CALL_NAME: dict[str, KnownPattern] = {}


def register_known_pattern(pattern: KnownPattern) -> None:
    """Register a KnownPattern so that finders and the decompiler pipeline can
    use it, and so that its call prototype is applied wherever its synthesized
    call appears.

    Several patterns may share a call name (e.g. libstdc++ and MSVC layout
    variants of the same accessor) as long as their call signatures agree,
    since prototypes are applied by call name; the first registered pattern
    provides the prototype."""
    existing = KNOWN_PATTERNS_BY_CALL_NAME.get(pattern.call_name)
    if existing is not None:
        same_signature = (
            existing.params == pattern.params
            and existing.returnty == pattern.returnty
            and existing.returnty_factory is pattern.returnty_factory
            and existing.extra_args == pattern.extra_args
        )
        if not same_signature:
            raise ValueError(
                f"a known pattern with call name {pattern.call_name!r} and a different call signature "
                f"is already registered"
            )
    ALL_KNOWN_PATTERNS.append(pattern)
    if existing is None:
        KNOWN_PATTERNS_BY_CALL_NAME[pattern.call_name] = pattern


register_known_pattern(STD_STRING_LENGTH)
register_known_pattern(STD_STRING_LENGTH_MSVC)
register_known_pattern(STD_VECTOR_SHORT_SIZE)
register_known_pattern(STD_VECTOR_INT_SIZE)
register_known_pattern(STD_VECTOR_LONG_LONG_SIZE)
register_known_pattern(STD_SWAP_8)
register_known_pattern(CONTAINING_RECORD_PATTERN)
for _p in ALL_LINKED_LIST_PATTERNS:
    register_known_pattern(_p)
for _p in ALL_STL_CONTAINER_PATTERNS:
    register_known_pattern(_p)
for _p in ALL_PROTOBUF_PATTERNS:
    register_known_pattern(_p)


__all__ = [
    "ALL_KNOWN_PATTERNS",
    "ALL_LINKED_LIST_PATTERNS",
    "ALL_PROTOBUF_PATTERNS",
    "ALL_STL_CONTAINER_PATTERNS",
    "CONTAINING_RECORD_PATTERN",
    "INITIALIZE_LIST_HEAD",
    "IS_LIST_EMPTY",
    "KNOWN_PATTERNS_BY_CALL_NAME",
    "REMOVE_ENTRY_LIST",
    "STD_STRING_LENGTH",
    "STD_STRING_LENGTH_MSVC",
    "STD_SWAP_8",
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
    "PCondJump",
    "PConst",
    "PConv",
    "PGraphPat",
    "PLoad",
    "PPhi",
    "PStmtSeq",
    "PStore",
    "PUnaryOp",
    "PVVar",
    "PatternGenerationError",
    "PatternGenerator",
    "PatternParam",
    "TypeRef",
    "UnsupportedOutlineError",
    "make_std_vector_size_pattern",
    "register_known_pattern",
]
