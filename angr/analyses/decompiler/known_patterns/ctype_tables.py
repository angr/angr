"""The glibc ctype macros: isspace, isdigit, ... and tolower/toupper.

``<ctype.h>`` classifies a character by indexing a locale table, not by
comparing ranges::

    #define __isctype(c, type)  ((*__ctype_b_loc ())[(int) (c)] & (unsigned short int) type)

so ``isspace(c)`` compiles to a call to ``__ctype_b_loc``, a load of the table
pointer it returns, a 16-bit indexed load, and a mask. Every predicate is that
one shape with a different constant, which is why they are generated here rather
than written out.

Measured over the -O2 benchmark corpus, the eleven predicates account for 7,894
macro-oracle sites across **24 projects** -- wider project coverage than any
family KnownPatterns covers today -- with ``tolower`` and ``toupper`` adding
1,588 more.

The callee is what makes the whole family self-guarding: nothing else calls
``__ctype_b_loc``. :class:`~.dsl.PCallResult` binds the table to that call
without consuming it, which matters because the compiler hoists the call out of
loops and indexes the table from every predicate in the function.

**Two byte lanes.** glibc's ``_ISbit(n)`` is ``n < 8 ? (1 << n) << 8 : (1 << n) >> 8``,
so eight of the twelve masks live in the high byte of the table entry and four in
the low byte. gcc tests the high ones with ``test $0x20,%ah`` -- an 8-bit slice
at byte offset 1 -- rather than masking the full 16-bit word, so each predicate
needs both spellings.

Calibrated against tests/x86_64/decompiler/known_patterns_ctype (gcc 12.2.0 -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL, C
from .dsl import PAny, PBinOp, PCallResult, PChoice, PConst, PDefOf, PExtract, PLoad
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

#: glibc's ``__ctype_b_loc`` under every spelling a binary may know it by.
CTYPE_B_LOC = frozenset({"__ctype_b_loc", "___ctype_b_loc"})
CTYPE_TOLOWER_LOC = frozenset({"__ctype_tolower_loc", "___ctype_tolower_loc"})
CTYPE_TOUPPER_LOC = frozenset({"__ctype_toupper_loc", "___ctype_toupper_loc"})

#: ``(macro name, mask)``. The values are glibc's ``enum`` from <ctype.h>,
#: computed by ``_ISbit(n) = n < 8 ? (1 << n) << 8 : (1 << n) >> 8``.
CTYPE_PREDICATES: tuple[tuple[str, int], ...] = (
    ("isupper", 0x0100),
    ("islower", 0x0200),
    ("isalpha", 0x0400),
    ("isdigit", 0x0800),
    ("isxdigit", 0x1000),
    ("isspace", 0x2000),
    ("isprint", 0x4000),
    ("isgraph", 0x8000),
    ("isblank", 0x0001),
    ("iscntrl", 0x0002),
    ("ispunct", 0x0004),
    ("isalnum", 0x0008),
)


def _index_addr(names: frozenset[str], elem_size: int) -> PBinOp:
    """The address of ``(*__ctype_X_loc())[c]``.

    The scale is spelled as a multiply or a shift depending on how the compiler
    felt; ``lea (%rcx,%rbx,2)`` lifts to either.
    """
    scaled = PChoice(
        PBinOp("Mul", (PAny(name="c"), PConst(elem_size))),
        PBinOp("Shl", (PAny(name="c"), PConst(elem_size.bit_length() - 1))),
    )
    # the table pointer itself is loaded once and kept in a register across every
    # predicate in the function, so it too is reached through its definition
    table = PDefOf(PLoad(PCallResult(names)))
    return PBinOp("Add", (table, scaled))


def _indexed_load(names: frozenset[str], elem_size: int) -> PDefOf:
    """``(*__ctype_X_loc())[c]``, as written or as the register it was put in.

    Every predicate in a function reads the *same* table entry when it tests the
    same character, so the compiler loads it once; by the time patterns run the
    mask is applied to a register, not to a Load.
    """
    return PDefOf(PLoad(_index_addr(names, elem_size), size=elem_size))


def _build_predicate(macro: str, mask: int):
    def build(ctx: PatternContext) -> KnownPattern:
        entry = _indexed_load(CTYPE_B_LOC, 2)
        # The whole 16-bit entry masked with the mask as written. A low-byte
        # mask also arrives this way: the compiler narrows the entry to a byte,
        # and structural matching skips the Convert.
        alternatives = [PBinOp("And", (entry, PConst(mask)))]
        if mask >= 0x100:
            # gcc's `test $0x20,%ah`: an 8-bit slice at byte 1, masked with the
            # mask's high byte. Not a Convert -- a Convert takes the low end.
            alternatives.append(PBinOp("And", (PExtract(entry, bits=8, offset=1), PConst(mask >> 8))))
            # ...and the same byte reached as its own load rather than a slice
            alternatives.append(
                PBinOp(
                    "And",
                    (
                        PDefOf(PLoad(PBinOp("Add", (_index_addr(CTYPE_B_LOC, 2), PConst(1))), size=1)),
                        PConst(mask >> 8),
                    ),
                )
            )
        else:
            # A low mask is tested on the entry's low byte, and that arrives as
            # an Extract at offset 0 as often as it does as a Convert. The two
            # are not interchangeable for the matcher: structural matching skips
            # a Convert and does not skip an Extract.
            alternatives.append(PBinOp("And", (PExtract(entry, bits=8, offset=0), PConst(mask))))
        return KnownPattern(
            name=f"ctype_{macro}",
            display_name=macro,
            call_name=macro,
            pattern=PChoice(*alternatives),
            params=(PatternParam("c", type="int"),),
            returnty="int",
        )

    return make_template(macro, build, arches=INTEL, languages=(C, CPP), platforms=("linux",), name=f"ctype_{macro}")


def _build_case_map(macro: str, names: frozenset[str]):
    def build(ctx: PatternContext) -> KnownPattern:
        return KnownPattern(
            name=f"ctype_{macro}",
            display_name=macro,
            call_name=macro,
            # the case tables are `const int *`, so 4-byte entries and no mask
            pattern=_indexed_load(names, 4),
            params=(PatternParam("c", type="int"),),
            returnty="int",
        )

    return make_template(macro, build, arches=INTEL, languages=(C, CPP), platforms=("linux",), name=f"ctype_{macro}")


CTYPE_PREDICATE_TEMPLATES = [_build_predicate(macro, mask) for macro, mask in CTYPE_PREDICATES]
CTYPE_TOLOWER = _build_case_map("tolower", CTYPE_TOLOWER_LOC)
CTYPE_TOUPPER = _build_case_map("toupper", CTYPE_TOUPPER_LOC)

ALL_CTYPE_TEMPLATES = [*CTYPE_PREDICATE_TEMPLATES, CTYPE_TOLOWER, CTYPE_TOUPPER]
