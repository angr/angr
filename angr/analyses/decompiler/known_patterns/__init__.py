"""Known code patterns: context-aware, declarative descriptions of library/macro
idioms that compilers inline, plus machinery (KnownPatternFinder) to find them
in Clinic AIL graphs and outline them back into calls.

Each idiom is defined once as a :class:`KnownPatternTemplate` that instantiates
itself into a concrete :class:`KnownPattern` for the target's
:class:`PatternContext` (architecture / platform / C++ runtime), so a single
definition covers 32- and 64-bit, libstdc++ and MSVC, etc.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .containing_record import CONTAINING_RECORD_PATTERN
from .context import PatternContext
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
from .kernel_err import ALL_KERNEL_ERR_TEMPLATES, IS_ERR, IS_ERR_OR_NULL
from .libm_bits import ALL_LIBM_TEMPLATES
from .linked_list import (
    ALL_LINKED_LIST_TEMPLATES,
    HLIST_DEL,
    INITIALIZE_LIST_HEAD,
    INSERT_HEAD_LIST,
    INSERT_TAIL_LIST,
    IS_LIST_EMPTY,
    LIST_DEL,
    LIST_DEL_INIT,
    REMOVE_ENTRY_LIST,
)
from .pattern import CppRef, KnownPattern, PatternParam, TypeRef
from .posix_macros import ALL_POSIX_MACRO_TEMPLATES, MAJOR
from .protobuf_hasbits import ALL_PROTOBUF_TEMPLATES
from .std_string_cstr import STD_STRING_CSTR
from .std_string_length import STD_STRING_EMPTY, STD_STRING_INDEX, STD_STRING_LENGTH
from .std_swap import STD_SWAP
from .std_vector_size import (
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_SHORT_SIZE,
    make_std_vector_size_template,
)
from .stl_containers import STD_VECTOR_INT_CAPACITY, STD_VECTOR_INT_EMPTY, STD_VECTOR_INT_INDEX
from .templates import KnownPatternTemplate, make_template
from .vector_math import ALL_VECTOR_MATH_TEMPLATES

if TYPE_CHECKING:
    from collections.abc import Iterable

ALL_KNOWN_PATTERN_TEMPLATES: list[KnownPatternTemplate] = []
TEMPLATE_BY_CALL_NAME: dict[str, KnownPatternTemplate] = {}


def register_pattern_template(template: KnownPatternTemplate) -> None:
    """Register a KnownPatternTemplate. Call names are unique across templates
    (the architecture / runtime conditionals live inside each template's
    ``build``)."""
    if template.call_name in TEMPLATE_BY_CALL_NAME:
        raise ValueError(f"a pattern template with call name {template.call_name!r} is already registered")
    ALL_KNOWN_PATTERN_TEMPLATES.append(template)
    TEMPLATE_BY_CALL_NAME[template.call_name] = template


# STL container accessors
register_pattern_template(STD_STRING_LENGTH)
register_pattern_template(STD_STRING_EMPTY)
register_pattern_template(STD_STRING_INDEX)
register_pattern_template(STD_STRING_CSTR)
register_pattern_template(STD_VECTOR_SHORT_SIZE)
register_pattern_template(STD_VECTOR_INT_SIZE)
register_pattern_template(STD_VECTOR_LONG_LONG_SIZE)
register_pattern_template(STD_VECTOR_INT_EMPTY)
register_pattern_template(STD_VECTOR_INT_CAPACITY)
register_pattern_template(STD_VECTOR_INT_INDEX)
register_pattern_template(STD_SWAP)
# C macros / kernel / library idioms
register_pattern_template(CONTAINING_RECORD_PATTERN)
for _t in ALL_LINKED_LIST_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_PROTOBUF_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_POSIX_MACRO_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_KERNEL_ERR_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_LIBM_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_VECTOR_MATH_TEMPLATES:
    register_pattern_template(_t)


def patterns_for(
    ctx: PatternContext,
    templates: Iterable[KnownPatternTemplate] | None = None,
    *,
    enabled_only: bool = False,
) -> list[KnownPattern]:
    """Instantiate the applicable templates for ``ctx`` into concrete
    KnownPatterns. ``templates`` defaults to the whole registry; with
    ``enabled_only`` only default-enabled templates are used."""
    if templates is None:
        templates = ALL_KNOWN_PATTERN_TEMPLATES
    out: list[KnownPattern] = []
    for t in templates:
        if enabled_only and not t.enabled_by_default:
            continue
        p = t.instantiate(ctx)
        if p is not None:
            out.append(p)
    return out


# convenience groupings (templates) for tests and callers
ALL_STL_TEMPLATES = [
    STD_STRING_LENGTH,
    STD_STRING_EMPTY,
    STD_STRING_INDEX,
    STD_VECTOR_SHORT_SIZE,
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_INT_EMPTY,
    STD_VECTOR_INT_CAPACITY,
    STD_VECTOR_INT_INDEX,
]


__all__ = [
    "ALL_KERNEL_ERR_TEMPLATES",
    "ALL_KNOWN_PATTERN_TEMPLATES",
    "ALL_LIBM_TEMPLATES",
    "ALL_LINKED_LIST_TEMPLATES",
    "ALL_POSIX_MACRO_TEMPLATES",
    "ALL_PROTOBUF_TEMPLATES",
    "ALL_STL_TEMPLATES",
    "ALL_VECTOR_MATH_TEMPLATES",
    "CONTAINING_RECORD_PATTERN",
    "HLIST_DEL",
    "INITIALIZE_LIST_HEAD",
    "INSERT_HEAD_LIST",
    "INSERT_TAIL_LIST",
    "IS_ERR",
    "IS_ERR_OR_NULL",
    "IS_LIST_EMPTY",
    "LIST_DEL",
    "LIST_DEL_INIT",
    "MAJOR",
    "REMOVE_ENTRY_LIST",
    "STD_STRING_CSTR",
    "STD_STRING_EMPTY",
    "STD_STRING_INDEX",
    "STD_STRING_LENGTH",
    "STD_SWAP",
    "STD_VECTOR_INT_CAPACITY",
    "STD_VECTOR_INT_EMPTY",
    "STD_VECTOR_INT_INDEX",
    "STD_VECTOR_INT_SIZE",
    "STD_VECTOR_LONG_LONG_SIZE",
    "STD_VECTOR_SHORT_SIZE",
    "TEMPLATE_BY_CALL_NAME",
    "CppRef",
    "KnownPattern",
    "KnownPatternFinder",
    "KnownPatternMatch",
    "KnownPatternTemplate",
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
    "PatternContext",
    "PatternGenerationError",
    "PatternGenerator",
    "PatternParam",
    "TypeRef",
    "UnsupportedOutlineError",
    "make_std_vector_size_template",
    "make_template",
    "patterns_for",
    "register_pattern_template",
]
