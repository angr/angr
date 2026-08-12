"""Inlined ``std::swap`` -- the three-move exchange of two memory locations.

Two statement orders occur, and both are common:

* as written, with the second value read inline::

      t = *a;  *a = *b;  *b = t;

* as scheduled, with both loads hoisted -- what any instruction scheduler
  produces, and what gcc emits for a struct assignment that swaps field by
  field::

      t1 = *a;  t2 = *b;  *a = t2;  *b = t1;

They cannot share a pattern object -- a statement sequence is one object -- so
each is its own template. The width is a parameter, currently pinned to the word
size for the reason given at ``_SWAP_WIDTHS``.

The addresses are :class:`~.dsl.PField` captures rather than bare variables
because swapping *fields* is the usual case (``std::swap(lhs.n, rhs.n)`` inside
a move assignment): the address arrives as ``obj + 8``, and the outliner
materializes the pointer for the call.

Calibrated against tests/x86_64/decompiler/known_patterns_multiblock (g++ -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL
from .dsl import PAssign, PField, PLoad, PStmtSeq, PStore, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

#: Widths a swapped value can have.
#:
#: Only the word size, and that is a performance decision, not a coverage one. A
#: statement-sequence pattern is tried at *every statement* of every block and
#: then scans forward, so each extra template multiplies a quadratic term -- and
#: the narrow widths are the ones that match most, since a three-statement byte
#: shuffle describes a great deal of code that is not a swap. With all four
#: widths in both statement orders (eight templates), the largest function of
#: fmt's format-impl-test went from seconds to minutes.
#:
#: The coverage that costs: `int` is 11% of the corpus' std::swap<T> records and
#: pointer-sized T 8%, so this covers the pointer/double half of the family and
#: misses the int half. Earning the narrow widths back needs the matcher to prune
#: statement patterns by their first statement's shape, the way expression
#: patterns are already pruned by anchor key -- not more templates.
_SWAP_WIDTHS = (8,)


def _ptr_type(ctx: PatternContext, size: int) -> str:
    return {1: "char *", 2: "short *", 4: "unsigned int *", 8: "unsigned long long *"}[size]


def _make_swap_template(size: int, scheduled: bool):
    """``std::swap`` of two ``size``-byte locations, in one of the two statement
    orders."""
    name = f"std_swap_{size}" + ("_scheduled" if scheduled else "")
    call_name = "std::swap" + (f" ({size}b{', scheduled' if scheduled else ''})" if size != 8 or scheduled else "")

    def build(ctx: PatternContext) -> KnownPattern | None:
        if size > ctx.word_size:
            return None
        a, b = PField("a", 0), PField("b", 0)
        if scheduled:
            stmts = (
                PAssign(PVVar("t1"), PLoad(a, size=size)),
                PAssign(PVVar("t2"), PLoad(b, size=size)),
                PStore(a, PVVar("t2"), size=size),
                PStore(b, PVVar("t1"), size=size),
            )
        else:
            stmts = (
                PAssign(PVVar("t"), PLoad(a, size=size)),
                PStore(a, PLoad(b, size=size), size=size),
                PStore(b, PVVar("t"), size=size),
            )
        return KnownPattern(
            name="std_swap",
            display_name="std::swap",
            call_name="std::swap",
            pattern=PStmtSeq(stmts),
            params=(
                PatternParam("a", type=_ptr_type(ctx, size)),
                PatternParam("b", type=_ptr_type(ctx, size)),
            ),
            returnty=None,  # void: the temporary dies inside the region
        )

    return make_template(call_name, build, arches=INTEL, languages=(CPP,), name=name)


STD_SWAP_TEMPLATES = [_make_swap_template(size, sched) for size in _SWAP_WIDTHS for sched in (False, True)]
#: the word-sized, as-written spelling -- the one the fixture tests
STD_SWAP = STD_SWAP_TEMPLATES[0]
