"""Runtime-specific struct layout offsets for the STL container patterns.

Where a field offset is simply the n-th pointer word it is ``ctx.word(n)``
(scales with the architecture). Where a runtime differs non-trivially — the
MSVC std::string keeps its size behind a fixed 16-byte SSO buffer union while
libstdc++ keeps it one word past the data pointer — the conditional lives here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import MSVC

if TYPE_CHECKING:
    from .context import PatternContext


# --- std::string ------------------------------------------------------------
# libstdc++: { _M_p (1 word) , _M_string_length (1 word) , union }
# MSVC:      { _Bx (16-byte buf/pointer union) , _Mysize , _Myres }


def string_data_offset(ctx: PatternContext) -> int:
    """Offset of the character data pointer (_M_p / _Bx). 0 in both runtimes."""
    return 0


def string_size_offset(ctx: PatternContext) -> int:
    """Offset of the length field (_M_string_length / _Mysize)."""
    if ctx.cxx_runtime == MSVC:
        return 16  # behind the fixed 16-byte SSO buffer union
    return ctx.word(1)


# --- std::vector ------------------------------------------------------------
# both runtimes: { _M_start/_Myfirst , _M_finish/_Mylast , _M_end_of_storage/_Myend }
# three pointers.

_VECTOR_BEGIN, _VECTOR_END, _VECTOR_CAP = 0, 1, 2


def vector_begin_offset(ctx: PatternContext) -> int:
    return ctx.word(_VECTOR_BEGIN)


def vector_end_offset(ctx: PatternContext) -> int:
    return ctx.word(_VECTOR_END)


def vector_cap_offset(ctx: PatternContext) -> int:
    return ctx.word(_VECTOR_CAP)


# --- doubly-linked list -----------------------------------------------------
# LIST_ENTRY {Flink, Blink} / list_head {next, prev}: two pointers.


def list_next_offset(ctx: PatternContext) -> int:
    return ctx.word(0)


def list_prev_offset(ctx: PatternContext) -> int:
    return ctx.word(1)
