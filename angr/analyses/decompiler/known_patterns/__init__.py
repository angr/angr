"""Known code patterns: context-aware, declarative descriptions of library/macro
idioms that compilers inline, plus machinery (KnownPatternFinder) to find them
in Clinic AIL graphs and outline them back into calls.

Each idiom is defined once as a :class:`KnownPatternTemplate` that instantiates
itself into a concrete :class:`KnownPattern` for the target's
:class:`PatternContext` (architecture / platform / C++ runtime), so a single
definition covers 32- and 64-bit, libstdc++ and MSVC, etc.
"""

from __future__ import annotations

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
from .registry import (
    ALL_KNOWN_PATTERN_TEMPLATES,
    ALL_PATTERNS,
    TEMPLATE_BY_CALL_NAME,
    TEMPLATE_BY_NAME,
    UnknownPatternError,
    partition_templates,
    patterns_for,
    register_pattern_template,
    resolve_pattern_selection,
)
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
