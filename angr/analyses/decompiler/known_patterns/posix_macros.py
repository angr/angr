"""Single-expression glibc/POSIX macros that the preprocessor inlines into every
caller, so they survive into decompiled output as bare bit arithmetic.

``<sys/stat.h>`` file-type predicates all expand through one helper::

    #define __S_ISTYPE(mode, mask)  (((mode) & __S_IFMT) == (mask))

with ``__S_IFMT == 0170000`` and one of the seven ``__S_IFxxx`` values, so each
predicate is a two-node expression ``(mode & 0xf000) == <S_IFxxx>``. The mask is
the same in every libc and in the Windows CRT (``_S_IFMT``), and the pairing of
that mask with exactly one of the seven legal type values is self-guarding, so
these are enabled by default.

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


# the S_IFMT encoding is not Unix-specific: the Windows CRT uses the same bit
# values (_S_IFMT 0xf000, _S_IFDIR 0x4000, _S_IFCHR 0x2000, _S_IFREG 0x8000), so
# these are left ungated. The mask/value pairing is self-guarding.
S_ISTYPE_TEMPLATES = [
    make_template(macro, _make_s_istype(name, macro, ifval), enabled_by_default=True, name=name)
    for name, macro, ifval in _S_ISTYPES
]

ALL_POSIX_MACRO_TEMPLATES = [*S_ISTYPE_TEMPLATES]
