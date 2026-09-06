"""Claims-only std::vector fingerprints: shapes that identify a vector beyond
doubt but are not worth a call of their own.

They exist for one reason. ``std::string::length`` is a bare word load at +8,
and so is ``std::vector::_M_finish``: 63% of ``length``'s false positives on the
benchmark corpus sit in functions with a vector at that very site. The generated
``size()``/``capacity()`` templates already claim a base wherever they match, but
they need a shift or a magic multiply to key on; two common vector shapes carry
neither, and are matched here purely so the base counts as a vector's
(see :attr:`~.pattern.KnownPattern.claims_only`):

* ``Load(v + 8) - Load(v)`` -- ``size()`` of a one-byte element type, which no
  size() template covers because there is nothing to divide by;
* ``Load(v + 8) ==/!= Load(v + 16)`` -- ``push_back``'s capacity check,
  ``_M_finish == _M_end_of_storage``, the shape behind the review's own example
  of a vector named as a string.

A string never subtracts its length from its data pointer, and compares its
length with its capacity only in ``size() == capacity()``, which is rare enough
inline to accept.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL
from .dsl import PBinOp, PChoice, PField, PLoad
from .layouts import vector_begin_offset, vector_cap_offset, vector_end_offset
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


def _field(off: int, ws: int) -> PLoad:
    return PLoad(PField("v", off), size=ws)


def _build_byte_size(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    return KnownPattern(
        name="std_vector_claim_byte_size",
        display_name="std::vector<T1>::size (claim)",
        call_name="std::vector<T1>::size (claim)",
        pattern=PBinOp("Sub", (_field(vector_end_offset(ctx), ws), _field(vector_begin_offset(ctx), ws))),
        params=(PatternParam("v"),),
        claims_only=True,
    )


def _build_capacity_check(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    end, cap = _field(vector_end_offset(ctx), ws), _field(vector_cap_offset(ctx), ws)
    return KnownPattern(
        name="std_vector_claim_capacity_check",
        display_name="std::vector<T>::push_back capacity check (claim)",
        call_name="std::vector<T>::push_back capacity check (claim)",
        pattern=PChoice(PBinOp("CmpEQ", (end, cap)), PBinOp("CmpNE", (end, cap))),
        params=(PatternParam("v"),),
        claims_only=True,
    )


STD_VECTOR_CLAIM_BYTE_SIZE = make_template(
    "std::vector<T1>::size (claim)", _build_byte_size, arches=INTEL, languages=(CPP,), name="std_vector_claim_byte_size"
)
STD_VECTOR_CLAIM_CAPACITY_CHECK = make_template(
    "std::vector<T>::push_back capacity check (claim)",
    _build_capacity_check,
    arches=INTEL,
    languages=(CPP,),
    name="std_vector_claim_capacity_check",
)

ALL_VECTOR_CLAIM_TEMPLATES = [STD_VECTOR_CLAIM_BYTE_SIZE, STD_VECTOR_CLAIM_CAPACITY_CHECK]
