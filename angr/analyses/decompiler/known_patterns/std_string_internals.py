"""libstdc++ std::string internals that are not accessors: the SSO test and the
two length-setting idioms.

``_M_set_length(n)`` is what every mutating operation ends with -- it stores the
new length and re-terminates the buffer::

    s->_M_string_length = n;
    s->_M_p[n] = '\\0';

768K DWARF inline sites across 242 binaries of the -O2 benchmark corpus, third
after the destructor and the SSO test. It is self-guarding because ``n`` appears
twice: once as the stored length and once as the offset added to the data
pointer, against a base the two field displacements already pin down.

``clear()`` is the same idiom with ``n == 0``, and is *not* the same pattern: with
no offset to add there is no second occurrence of ``n`` to unify on, so the shape
degrades to "zero a word at +8 and a byte through the pointer at +0". That is a
plausible reset of any pointer-and-count pair, so it is opt-in and corroborated.

``_M_is_local()`` is the SSO test on its own, ``_M_p == &_M_local_buf`` -- the
same comparison the destructor guards on and ``capacity()`` selects on. It is
opt-in for a different reason: wherever it appears as part of one of those, the
larger match wins and this one is redundant; what is left over is the handful of
places where the test stands alone.

Calibrated against tests/x86_64/decompiler/known_patterns_stl5 (g++ 12.2.0 -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL, LIBSTDCXX
from .dsl import PBinOp, PConst, PDefOf, PField, PLoad, PStmtSeq, PStore, PVVar
from .layouts import string_capacity_offset, string_data_offset, string_size_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_string_length import STD_BASIC_STRING, STRING_WITNESSED
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


def _data(ctx: PatternContext) -> PDefOf:
    """``_M_p``, as written or as the register the compiler put it in.

    Every idiom here reads the data pointer and something else, so the load is
    hoisted and neither use is a Load by the time patterns run.
    """
    return PDefOf(PLoad(PField("s", string_data_offset(ctx)), size=ctx.word_size))


def _build_set_length(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="std_string_set_length",
        display_name="std::string::_M_set_length",
        call_name="std::string::_M_set_length",
        # the compiler is free to schedule the two stores either way round
        pattern=PStmtSeq(
            (
                PStore(PField("s", string_size_offset(ctx)), PVVar("n"), size=ctx.word_size),
                PStore(PBinOp("Add", (_data(ctx), PVVar("n"))), PConst(0), size=1),
            ),
            ordered=False,
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)), PatternParam("n", type="unsigned long long")),
        returnty=None,
    )


def _build_clear(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="std_string_clear",
        display_name="std::string::clear",
        call_name="std::string::clear",
        pattern=PStmtSeq(
            (
                PStore(PField("s", string_size_offset(ctx)), PConst(0), size=ctx.word_size),
                PStore(_data(ctx), PConst(0), size=1),
            ),
            ordered=False,
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=None,
    )


def _build_is_local(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="std_string_is_local",
        display_name="std::string::_M_is_local",
        call_name="std::string::_M_is_local",
        pattern=PBinOp("CmpEQ", (_data(ctx), PField("s", string_capacity_offset(ctx)))),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty="int",
    )


STD_STRING_SET_LENGTH = make_template(
    "std::string::_M_set_length",
    _build_set_length,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_set_length",
)
STD_STRING_CLEAR = make_template(
    "std::string::clear",
    _build_clear,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    enabled_by_default=False,
    name="std_string_clear",
    gate=STRING_WITNESSED,
)
STD_STRING_IS_LOCAL = make_template(
    "std::string::_M_is_local",
    _build_is_local,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    enabled_by_default=False,
    name="std_string_is_local",
    gate=STRING_WITNESSED,
)

ALL_STRING_INTERNALS_TEMPLATES = [STD_STRING_SET_LENGTH, STD_STRING_CLEAR, STD_STRING_IS_LOCAL]
