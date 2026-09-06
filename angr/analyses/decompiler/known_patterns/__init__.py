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
from .ctype_tables import ALL_CTYPE_TEMPLATES, CTYPE_PREDICATES
from .dsl import (
    PITE,
    PAny,
    PAssign,
    PBinOp,
    PBlockPat,
    PCall,
    PCallResult,
    PCallStmt,
    PChoice,
    PCondJump,
    PConst,
    PConv,
    PDefOf,
    PExtract,
    PField,
    PGraphPat,
    PLoad,
    PPhi,
    PStackField,
    PStmtSeq,
    PStore,
    PUnaryOp,
    PVVar,
)
from .finder import KnownPatternFinder, KnownPatternMatch, OutlineResult, UnsupportedOutlineError
from .gating import (
    KERNEL_TARGET,
    LINUX_KERNEL,
    WINDOWS_KERNEL_DRIVER,
    AllOf,
    AnyOf,
    CorroboratedBy,
    GateContext,
    PatternGate,
    TargetGate,
    all_of,
    any_of,
    corroborated_by,
)
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
from .std_string_dtor import ALL_STRING_DTOR_TEMPLATES, OPERATOR_DELETE, STD_STRING_DTOR
from .std_string_internals import ALL_STRING_INTERNALS_TEMPLATES, STD_STRING_SET_LENGTH
from .std_string_length import STD_STRING_EMPTY, STD_STRING_INDEX, STD_STRING_LENGTH
from .std_swap import STD_SWAP, STD_SWAP_TEMPLATES
from .std_vector_size import (
    STD_VECTOR_CAPACITY_TEMPLATES,
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_SHORT_SIZE,
    STD_VECTOR_STACK_TEMPLATES,
    STD_VECTOR_STRUCT_SIZE_TEMPLATES,
    exact_div_magic,
    make_std_vector_size_exactdiv_template,
    make_std_vector_size_template,
)
from .stl_accessors2 import ALL_STL2_TEMPLATES
from .stl_containers import STD_VECTOR_INDEX_TEMPLATES, STD_VECTOR_INT_EMPTY, STD_VECTOR_INT_INDEX
from .templates import KnownPatternTemplate, make_template
from .vector_claims import ALL_VECTOR_CLAIM_TEMPLATES
from .vector_math import ALL_VECTOR_MATH_TEMPLATES
from .wdk_shared_data import ALL_WDK_TEMPLATES

if TYPE_CHECKING:
    from collections.abc import Iterable

ALL_KNOWN_PATTERN_TEMPLATES: list[KnownPatternTemplate] = []
TEMPLATE_BY_CALL_NAME: dict[str, KnownPatternTemplate] = {}
TEMPLATE_BY_NAME: dict[str, KnownPatternTemplate] = {}

#: Value of the ``known_patterns`` decompilation option that force-enables every
#: registered template, opt-in ones included.
ALL_PATTERNS = "all"


class UnknownPatternError(ValueError):
    """Raised when a pattern selection names a template that is not registered."""


def register_pattern_template(template: KnownPatternTemplate) -> None:
    """Register a KnownPatternTemplate. Call names are unique across templates
    (the architecture / runtime conditionals live inside each template's
    ``build``)."""
    if template.call_name in TEMPLATE_BY_CALL_NAME:
        raise ValueError(f"a pattern template with call name {template.call_name!r} is already registered")
    ALL_KNOWN_PATTERN_TEMPLATES.append(template)
    TEMPLATE_BY_CALL_NAME[template.call_name] = template
    # a template's human name defaults to its call name; register the second spelling only when it differs and
    # does not shadow some other template's call name
    if template.name not in TEMPLATE_BY_CALL_NAME:
        TEMPLATE_BY_NAME[template.name] = template


# STL container accessors
register_pattern_template(STD_STRING_LENGTH)
register_pattern_template(STD_STRING_EMPTY)
register_pattern_template(STD_STRING_INDEX)
register_pattern_template(STD_STRING_CSTR)
register_pattern_template(STD_VECTOR_SHORT_SIZE)
register_pattern_template(STD_VECTOR_INT_SIZE)
register_pattern_template(STD_VECTOR_LONG_LONG_SIZE)
for _t in STD_VECTOR_STRUCT_SIZE_TEMPLATES:
    register_pattern_template(_t)
register_pattern_template(STD_VECTOR_INT_EMPTY)
for _t in STD_VECTOR_CAPACITY_TEMPLATES:
    register_pattern_template(_t)
for _t in STD_VECTOR_STACK_TEMPLATES:
    register_pattern_template(_t)
for _t in STD_VECTOR_INDEX_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_STL2_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_STRING_DTOR_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_STRING_INTERNALS_TEMPLATES:
    register_pattern_template(_t)
for _t in STD_SWAP_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_VECTOR_CLAIM_TEMPLATES:
    register_pattern_template(_t)
# C macros / kernel / library idioms
register_pattern_template(CONTAINING_RECORD_PATTERN)
for _t in ALL_LINKED_LIST_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_PROTOBUF_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_CTYPE_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_POSIX_MACRO_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_KERNEL_ERR_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_LIBM_TEMPLATES:
    register_pattern_template(_t)
for _t in ALL_WDK_TEMPLATES:
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


def resolve_pattern_selection(selection: str | Iterable[str] | None) -> list[KnownPatternTemplate]:
    """Resolve a user's force-enable selection into templates.

    ``selection`` is one of:

    * ``None`` / empty — nothing is force-enabled (returns an empty list);
    * ``"all"`` — every registered template, opt-in ones included;
    * an iterable of template ``name``s and/or ``call_name``s (a comma-separated
      string is accepted too, for the string-valued decompilation option).

    An unrecognized name raises :class:`UnknownPatternError` rather than
    silently selecting nothing.
    """
    if selection is None:
        return []
    if isinstance(selection, str):
        if selection.strip().lower() == ALL_PATTERNS:
            return list(ALL_KNOWN_PATTERN_TEMPLATES)
        names = [n.strip() for n in selection.split(",")]
    else:
        names = [str(n).strip() for n in selection]
    names = [n for n in names if n]
    if not names:
        return []
    if len(names) == 1 and names[0].lower() == ALL_PATTERNS:
        return list(ALL_KNOWN_PATTERN_TEMPLATES)

    out: list[KnownPatternTemplate] = []
    seen: set[int] = set()
    for name in names:
        template = TEMPLATE_BY_CALL_NAME.get(name) or TEMPLATE_BY_NAME.get(name)
        if template is None:
            raise UnknownPatternError(
                f"unknown known-pattern {name!r}. Valid names are the template call names "
                f"({', '.join(sorted(TEMPLATE_BY_CALL_NAME)[:3])}, ...) or their short names; pass "
                f'"all" to force-enable every pattern.'
            )
        if id(template) not in seen:
            seen.add(id(template))
            out.append(template)
    return out


def partition_templates(
    gate_ctx: GateContext,
    forced: Iterable[KnownPatternTemplate] = (),
    templates: Iterable[KnownPatternTemplate] | None = None,
) -> tuple[list[KnownPatternTemplate], list[KnownPatternTemplate]]:
    """Split templates into ``(enabled, deferred)`` for one target.

    ``enabled`` are the templates to match with right away: default-on ones,
    ones the caller force-enabled, and ones whose gate already opens on target
    evidence alone. ``deferred`` are the ones whose gate needs per-function
    evidence (see :class:`~.gating.CorroboratedBy`) and must be re-evaluated by
    the finder once the first matching stage has run.
    """
    if templates is None:
        templates = ALL_KNOWN_PATTERN_TEMPLATES
    forced_ids = {id(t) for t in forced}
    enabled: list[KnownPatternTemplate] = []
    deferred: list[KnownPatternTemplate] = []
    for t in templates:
        if t.enabled_by_default or id(t) in forced_ids or t.enabled_for(gate_ctx):
            enabled.append(t)
        elif t.gate is not None and t.gate.requires_evidence:
            deferred.append(t)
    return enabled, deferred


# convenience groupings (templates) for tests and callers
ALL_STL_TEMPLATES = [
    STD_STRING_LENGTH,
    STD_STRING_EMPTY,
    STD_STRING_INDEX,
    STD_VECTOR_SHORT_SIZE,
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_INT_EMPTY,
    STD_VECTOR_INT_INDEX,
    *STD_VECTOR_CAPACITY_TEMPLATES,
]


__all__ = [
    "ALL_CTYPE_TEMPLATES",
    "ALL_KERNEL_ERR_TEMPLATES",
    "ALL_KNOWN_PATTERN_TEMPLATES",
    "ALL_LIBM_TEMPLATES",
    "ALL_LINKED_LIST_TEMPLATES",
    "ALL_PATTERNS",
    "ALL_POSIX_MACRO_TEMPLATES",
    "ALL_PROTOBUF_TEMPLATES",
    "ALL_STL2_TEMPLATES",
    "ALL_STL_TEMPLATES",
    "ALL_STRING_DTOR_TEMPLATES",
    "ALL_STRING_INTERNALS_TEMPLATES",
    "ALL_VECTOR_CLAIM_TEMPLATES",
    "ALL_VECTOR_MATH_TEMPLATES",
    "ALL_WDK_TEMPLATES",
    "CONTAINING_RECORD_PATTERN",
    "CTYPE_PREDICATES",
    "HLIST_DEL",
    "INITIALIZE_LIST_HEAD",
    "INSERT_HEAD_LIST",
    "INSERT_TAIL_LIST",
    "IS_ERR",
    "IS_ERR_OR_NULL",
    "IS_LIST_EMPTY",
    "KERNEL_TARGET",
    "LINUX_KERNEL",
    "LIST_DEL",
    "LIST_DEL_INIT",
    "MAJOR",
    "OPERATOR_DELETE",
    "PITE",
    "REMOVE_ENTRY_LIST",
    "STD_STRING_CSTR",
    "STD_STRING_DTOR",
    "STD_STRING_EMPTY",
    "STD_STRING_INDEX",
    "STD_STRING_LENGTH",
    "STD_STRING_SET_LENGTH",
    "STD_SWAP",
    "STD_SWAP_TEMPLATES",
    "STD_VECTOR_CAPACITY_TEMPLATES",
    "STD_VECTOR_INDEX_TEMPLATES",
    "STD_VECTOR_INT_EMPTY",
    "STD_VECTOR_INT_INDEX",
    "STD_VECTOR_INT_SIZE",
    "STD_VECTOR_LONG_LONG_SIZE",
    "STD_VECTOR_SHORT_SIZE",
    "STD_VECTOR_STACK_TEMPLATES",
    "STD_VECTOR_STRUCT_SIZE_TEMPLATES",
    "TEMPLATE_BY_CALL_NAME",
    "TEMPLATE_BY_NAME",
    "WINDOWS_KERNEL_DRIVER",
    "AllOf",
    "AnyOf",
    "CorroboratedBy",
    "CppRef",
    "GateContext",
    "KnownPattern",
    "KnownPatternFinder",
    "KnownPatternMatch",
    "KnownPatternTemplate",
    "OutlineResult",
    "PAny",
    "PAssign",
    "PBinOp",
    "PBlockPat",
    "PCall",
    "PCallResult",
    "PCallStmt",
    "PChoice",
    "PCondJump",
    "PConst",
    "PConv",
    "PDefOf",
    "PExtract",
    "PField",
    "PGraphPat",
    "PLoad",
    "PPhi",
    "PStackField",
    "PStmtSeq",
    "PStore",
    "PUnaryOp",
    "PVVar",
    "PatternContext",
    "PatternGate",
    "PatternGenerationError",
    "PatternGenerator",
    "PatternParam",
    "TargetGate",
    "TypeRef",
    "UnknownPatternError",
    "UnsupportedOutlineError",
    "all_of",
    "any_of",
    "corroborated_by",
    "exact_div_magic",
    "make_std_vector_size_exactdiv_template",
    "make_std_vector_size_template",
    "make_template",
    "partition_templates",
    "patterns_for",
    "register_pattern_template",
    "resolve_pattern_selection",
]
