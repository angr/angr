"""Inlined ``std::swap`` -- the three-move exchange of two memory locations.

Three statement orders occur, and all three are common:

* as written, with the second value read inline::

      t = *a;  *a = *b;  *b = t;

* as scheduled, with both loads hoisted -- what any instruction scheduler
  produces, and what gcc emits for a struct assignment that swaps field by
  field::

      t1 = *a;  t2 = *b;  *a = t2;  *b = t1;

* the same, storing in the other order::

      t1 = *a;  t2 = *b;  *b = t1;  *a = t2;

  which is not the previous one with ``a`` and ``b`` renamed: that renaming also
  swaps the two *loads*, so the sequence differs either way round. gcc emits it
  for consecutive field swaps, where it lets the store to one field sit next to
  the load of the next.

They cannot share a pattern object -- a statement sequence is one object -- so
each is its own template. The width is a parameter; see ``_SWAP_WIDTHS``.

The addresses are :class:`~.dsl.PField` captures rather than bare variables
because swapping *fields* is the usual case (``std::swap(lhs.n, rhs.n)`` inside
a move assignment): the address arrives as ``obj + 8``, and the outliner
materializes the pointer for the call.

Calibrated against tests/x86_64/decompiler/known_patterns_multiblock (g++ -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL
from .dsl import PAssign, PChoice, PConv, PField, PLoad, PStmtSeq, PStore, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

#: Widths a swapped value can have.
#:
#: This was pinned to the word size for a while, on the grounds that a
#: statement-sequence pattern is tried at *every statement* of every block and
#: then scans forward, so each extra template multiplied a quadratic term. The
#: matcher now prunes statement patterns by their first statement's key -- which
#: for every template here is "an assignment whose source is a load of exactly
#: this width" -- so a template is only tried where its width already matches,
#: and the narrow widths cost what they are worth. `int` alone is 11% of the
#: corpus' std::swap<T> records.
_SWAP_WIDTHS = (1, 2, 4, 8)


def _ptr_type(ctx: PatternContext, size: int) -> str:
    return {1: "char *", 2: "short *", 4: "unsigned int *", 8: "unsigned long long *"}[size]


def _held(cap: str) -> PChoice:
    """The temporary on its way back out to memory.

    A sub-word swap keeps its value in a register, so the load is widened and
    the store narrows it again: the char case stores ``Conv(32->8, t)`` rather
    than ``t``. The load side needs no help -- structural matching already skips
    Convert wrappers -- but a bare PVVar does not, deliberately, so the store
    side has to say it accepts one.
    """
    return PChoice(PVVar(cap), PConv(PVVar(cap)))


#: The statement orders, as (name suffix, builder over (a, b, size)).
_AS_WRITTEN, _STORE_A_FIRST, _STORE_B_FIRST = "", "_scheduled", "_scheduled_rev"


def _make_swap_template(size: int, order: str):
    """``std::swap`` of two ``size``-byte locations, in one of the statement
    orders."""
    name = f"std_swap_{size}{order}"
    label = {_AS_WRITTEN: "", _STORE_A_FIRST: ", scheduled", _STORE_B_FIRST: ", scheduled rev"}[order]
    call_name = "std::swap" + (f" ({size}b{label})" if size != 8 or order else "")

    def build(ctx: PatternContext) -> KnownPattern | None:
        if size > ctx.word_size:
            return None
        a, b = PField("a", 0), PField("b", 0)
        if order == _STORE_A_FIRST:
            stmts = (
                PAssign(PVVar("t1"), PLoad(a, size=size)),
                PAssign(PVVar("t2"), PLoad(b, size=size)),
                PStore(a, _held("t2"), size=size),
                PStore(b, _held("t1"), size=size),
            )
        elif order == _STORE_B_FIRST:
            stmts = (
                PAssign(PVVar("t1"), PLoad(a, size=size)),
                PAssign(PVVar("t2"), PLoad(b, size=size)),
                PStore(b, _held("t1"), size=size),
                PStore(a, _held("t2"), size=size),
            )
        else:
            stmts = (
                PAssign(PVVar("t"), PLoad(a, size=size)),
                PStore(a, PLoad(b, size=size), size=size),
                PStore(b, _held("t"), size=size),
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


STD_SWAP_TEMPLATES = [
    _make_swap_template(size, order) for size in _SWAP_WIDTHS for order in (_AS_WRITTEN, _STORE_A_FIRST, _STORE_B_FIRST)
]
#: the word-sized, as-written spelling -- the one the fixture tests
STD_SWAP = STD_SWAP_TEMPLATES[0]
