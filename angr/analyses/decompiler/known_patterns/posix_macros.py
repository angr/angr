"""Single-expression glibc/POSIX macros that the preprocessor inlines into every
caller, so they survive into decompiled output as bare bit arithmetic.

``<sys/stat.h>`` file-type predicates all expand through one helper::

    #define __S_ISTYPE(mode, mask)  (((mode) & __S_IFMT) == (mask))

with ``__S_IFMT == 0170000`` and one of the seven ``__S_IFxxx`` values, so each
predicate is a two-node expression ``(mode & 0xf000) == <S_IFxxx>``. The mask is
the same in every libc and in the Windows CRT (``_S_IFMT``), and the pairing of
that mask with exactly one of the seven legal type values is self-guarding, so
these are enabled by default.

``<sys/wait.h>`` status decoders (glibc ``bits/waitstatus.h``)::

    #define __WTERMSIG(status)     ((status) & 0x7f)
    #define __WIFEXITED(status)    (__WTERMSIG(status) == 0)
    #define __WIFSIGNALED(status)  (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
    #define __WIFSTOPPED(status)   (((status) & 0xff) == 0x7f)
    #define __WEXITSTATUS(status)  (((status) & 0xff00) >> 8)

Only the first three leave enough residue to identify. gcc rewrites
``WIFSIGNALED`` into ``(signed char)((status & 0x7f) + 1) > 1`` (the ``>> 1`` and
the ``> 0`` fold together), which is what is matched here; the signed compare is
required, since the ``(signed char)`` cast is the whole point of the idiom.
``WIFSTOPPED`` narrows to a bare ``(char)status == 0x7f`` (the ``& 0xff`` is
absorbed by the byte-sized compare) and ``WTERMSIG`` is a bare ``status & 0x7f``;
both are common enough shapes to be opt-in. ``WEXITSTATUS`` / ``WSTOPSIG``
(identical macros in glibc) are not matchable at all on x86: gcc compiles
``(status & 0xff00) >> 8`` to a single ``movzbl %ah`` and the decompiler renders
it as a plain byte-sized virtual variable, leaving no shift or mask to match.

**``WIFSIGNALED`` does not match on x86-32, and should not be made to.** There
the ``(signed char)`` cast lifts to an ``Extract`` rather than a ``Convert``, and
gcc takes the *inverted* branch, so the AIL reads

    Extract(((status & 0x7f) + 1), 8bits@0) CmpLE 1<8>

The missing ``Extract`` node in the DSL is the smaller half of the problem: that
expression is ``!WIFSIGNALED(status)``, and a KnownPattern replaces the matched
expression by the value of its synthesized call, so there is no way to spell the
negation. A pattern matching this shape and emitting ``WIFSIGNALED(status)``
would silently swap the two arms of every wait-status branch on 32-bit -- the
"child was killed by signal N" arm would become the "exited normally" one. The
x86-32 sites (0 of 13 busybox functions) are therefore a deliberate gap until the
pattern model can express a negated result.

``<sys/sysmacros.h>`` ``major()`` is an ``extern __inline`` function that -O2
inlines; its glibc encoding scatters the major number over bits 8-19 and 32-63::

    __major  = ((__dev & 0x00000000000fff00u) >>  8);
    __major |= ((__dev & 0xfffff00000000000u) >> 32);

which gcc reassociates into ``((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000)``
on 64-bit targets, and into a funnel-shift pair on 32-bit ones (see
``_build_major32``). That constant quartet is unique enough to enable by default.
``minor()`` and ``makedev()`` compile to ``Insert``/``Extract`` AIL expressions
for which the pattern DSL has no node, so they are not defined here.

Every macro argument is matched as a virtual variable (optionally behind a
compiler-inserted narrowing Convert), never as a Load: an outlined call's
arguments must be the outlined region's live-in virtual variables, so a pattern
that captured, say, ``st->st_mode`` directly would match but could never be
outlined. Real callers that keep the mode in a local therefore match; callers
that read it straight out of a ``struct stat`` field at the point of use do not.

Calibrated against tests/x86_64/decompiler/known_patterns_glibc_macros (gcc
12.2 -O2; re-checked at -O1/-O3, and against glibc 2.36 headers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .dsl import PBinOp, PChoice, PConst, PConv, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from angr.ailment.expression import Expression

    from .context import PatternContext

# <sys/stat.h>: the file-type field mask and the seven legal type values
S_IFMT = 0o170000
_S_ISTYPES = (
    ("s_isreg", "S_ISREG", 0o100000),
    ("s_isdir", "S_ISDIR", 0o040000),
    ("s_ischr", "S_ISCHR", 0o020000),
    ("s_isblk", "S_ISBLK", 0o060000),
    ("s_isfifo", "S_ISFIFO", 0o010000),
    ("s_islnk", "S_ISLNK", 0o120000),
    ("s_issock", "S_ISSOCK", 0o140000),
)


def macro_operand(cap: str) -> PChoice:
    """A macro's scalar argument: a virtual variable, possibly narrowed by the
    compiler. PVVar does not see through Convert wrappers on its own, and
    binding the pre-narrowing vvar keeps the synthesized call argument
    correctly typed."""
    return PChoice(PVVar(cap), PConv(PVVar(cap)))


def _make_s_istype(name: str, macro: str, ifval: int):
    def build(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
        return KnownPattern(
            name=name,
            display_name=macro,
            call_name=macro,
            # ((mode) & S_IFMT) == S_IFxxx
            pattern=PBinOp("CmpEQ", (PBinOp("And", (macro_operand("mode"), PConst(S_IFMT))), PConst(ifval))),
            params=(PatternParam("mode", "unsigned int"),),
            returnty="int",
        )

    return build


def _build_wifexited(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
    # (status & 0x7f) == 0
    return KnownPattern(
        name="wifexited",
        display_name="WIFEXITED",
        call_name="WIFEXITED",
        pattern=PBinOp("CmpEQ", (PBinOp("And", (macro_operand("status"), PConst(0x7F))), PConst(0))),
        params=(PatternParam("status", "int"),),
        returnty="int",
    )


def _signed_cmp(bindings: dict[str, Expression]) -> bool:
    cmp_expr = bindings.get("cmp")
    return cmp_expr is not None and bool(getattr(cmp_expr, "signed", False))


def _build_wifsignaled(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
    # ((signed char) ((status & 0x7f) + 1) >> 1) > 0, folded by gcc into
    # (signed char) ((status & 0x7f) + 1) > 1
    return KnownPattern(
        name="wifsignaled",
        display_name="WIFSIGNALED",
        call_name="WIFSIGNALED",
        pattern=PBinOp(
            "CmpGT",
            (PBinOp("Add", (PBinOp("And", (macro_operand("status"), PConst(0x7F))), PConst(1))), PConst(1)),
            commutative=False,
            name="cmp",
        ),
        params=(PatternParam("status", "int"),),
        returnty="int",
        where=_signed_cmp,
    )


def _build_wifstopped(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
    # ((status) & 0xff) == 0x7f, which the compiler narrows to (char)status == 0x7f
    return KnownPattern(
        name="wifstopped",
        display_name="WIFSTOPPED",
        call_name="WIFSTOPPED",
        pattern=PBinOp("CmpEQ", (macro_operand("status"), PConst(0x7F, bits=8))),
        params=(PatternParam("status", "int"),),
        returnty="int",
        enabled_by_default=False,
    )


def _build_wtermsig(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
    # (status) & 0x7f
    return KnownPattern(
        name="wtermsig",
        display_name="WTERMSIG",
        call_name="WTERMSIG",
        pattern=PBinOp("And", (macro_operand("status"), PConst(0x7F))),
        params=(PatternParam("status", "int"),),
        returnty="int",
        enabled_by_default=False,
    )


def _build_major(ctx: PatternContext) -> KnownPattern | None:
    # ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000)
    if ctx.bits < 64:
        return _build_major32(ctx)
    return KnownPattern(
        name="gnu_dev_major",
        display_name="major",
        call_name="major",
        pattern=PBinOp(
            "Or",
            (
                PBinOp("And", (PBinOp("Shr", (PVVar("dev"), PConst(8)), commutative=False), PConst(0xFFF))),
                PBinOp("And", (PBinOp("Shr", (PVVar("dev"), PConst(32)), commutative=False), PConst(0xFFFFF000))),
            ),
        ),
        params=(PatternParam("dev", "unsigned long long"),),
        returnty="unsigned int",
    )


def _build_major32(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
    # glibc's dev_t is 64 bits on 32-bit targets too (__DEV_T_TYPE is __UQUAD_TYPE
    # for __WORDSIZE == 32), so the encoding is the same one -- but the value
    # lives in a register pair, and each half of major() reads a different half
    # of it:
    #
    #     (dev >> 8) & 0xfff       ->  shrd $8, %hi, %lo ; and $0xfff
    #     (dev >> 32) & 0xfffff000 ->  and $0xfffff000, %hi
    #
    # The funnel shift is what makes this recoverable: angr lifts `shrd` back
    # into a 64-bit shift of the concatenated pair, so the low half still names
    # *both* registers and the high half must name the same high register. That
    # repeated capture is the whole guard, and it is why the two halves cannot
    # be confused with unrelated masking.
    #
    # The synthesized call has to take two arguments, since the 64-bit value is
    # never materialized: they are ordered low-word-first, which is how a
    # `long long` argument is actually passed on i386.
    return KnownPattern(
        name="gnu_dev_major",
        display_name="major",
        call_name="major",
        pattern=PBinOp(
            "Or",
            (
                PBinOp(
                    "And",
                    (
                        PBinOp(
                            "Shr",
                            (PBinOp("Concat", (PVVar("dev_hi"), PVVar("dev_lo")), commutative=False), PConst(8)),
                            commutative=False,
                        ),
                        PConst(0xFFF),
                    ),
                ),
                PBinOp("And", (PVVar("dev_hi"), PConst(0xFFFFF000))),
            ),
        ),
        params=(PatternParam("dev_lo", "unsigned int"), PatternParam("dev_hi", "unsigned int")),
        returnty="unsigned int",
    )


# the S_IFMT encoding is not Unix-specific: the Windows CRT uses the same bit
# values (_S_IFMT 0xf000, _S_IFDIR 0x4000, _S_IFCHR 0x2000, _S_IFREG 0x8000), so
# these are left ungated. The mask/value pairing is self-guarding.
S_ISTYPE_TEMPLATES = [
    make_template(macro, _make_s_istype(name, macro, ifval), enabled_by_default=True, name=name)
    for name, macro, ifval in _S_ISTYPES
]

# the wait-status bit layout is POSIX/glibc-specific, so these are gated to the
# platform they were calibrated on
WIFEXITED = make_template(
    "WIFEXITED", _build_wifexited, platforms=("linux",), enabled_by_default=True, name="wifexited"
)
WIFSIGNALED = make_template(
    "WIFSIGNALED", _build_wifsignaled, platforms=("linux",), enabled_by_default=True, name="wifsignaled"
)
# opt-in: the compiler absorbs the & 0xff, leaving a bare byte compare against
# 0x7f that is indistinguishable from any other char test
WIFSTOPPED = make_template(
    "WIFSTOPPED", _build_wifstopped, platforms=("linux",), enabled_by_default=False, name="wifstopped"
)
# opt-in: a bare `x & 0x7f` is far too common to attribute to WTERMSIG, and it
# also nests inside WIFEXITED / WIFSIGNALED
WTERMSIG = make_template("WTERMSIG", _build_wtermsig, platforms=("linux",), enabled_by_default=False, name="wtermsig")

MAJOR = make_template("major", _build_major, platforms=("linux",), enabled_by_default=True, name="gnu_dev_major")

ALL_POSIX_MACRO_TEMPLATES = [*S_ISTYPE_TEMPLATES, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WTERMSIG, MAJOR]
