"""protobuf has-bits accessors (protoc output for optional fields):

    has_field()  -> _has_bits_[w] & mask          (Load(m) And mask)
    set_has()    -> _has_bits_[w] |= mask          (Store(m, Load(m) Or mask))
    clear_has()  -> _has_bits_[w] &= ~mask         (Store(m, Load(m) And ~mask))

The ``_has_bits_`` word is a 32-bit int regardless of architecture, so the load
width is fixed at 4. Generic bitfield ops → opt-in; the mask is captured as an
extra call argument. Calibrated against
tests/x86_64/decompiler/known_patterns_protobuf (g++ -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .dsl import PBinOp, PConst, PLoad, PStore, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

_WORD = 4  # _has_bits_ is a 32-bit word


def _build_has_field(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="protobuf_has_field",
        display_name="_pb_has_field",
        call_name="_pb_has_field",
        pattern=PBinOp("And", (PLoad(PVVar("msg"), size=_WORD), PConst(name="mask"))),
        params=(PatternParam("msg"),),
        extra_args=("mask",),
        returnty="int",
    )


def _build_set_has_field(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="protobuf_set_has_field",
        display_name="_pb_set_has_field",
        call_name="_pb_set_has_field",
        pattern=PStore(PVVar("msg"), PBinOp("Or", (PLoad(PVVar("msg"), size=_WORD), PConst(name="mask"))), size=_WORD),
        params=(PatternParam("msg"),),
        extra_args=("mask",),
        returnty=None,
    )


def _build_clear_has_field(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="protobuf_clear_has_field",
        display_name="_pb_clear_has_field",
        call_name="_pb_clear_has_field",
        pattern=PStore(
            PVVar("msg"), PBinOp("And", (PLoad(PVVar("msg"), size=_WORD), PConst(name="notmask"))), size=_WORD
        ),
        params=(PatternParam("msg"),),
        extra_args=("notmask",),
        returnty=None,
    )


PROTOBUF_HAS_FIELD = make_template("_pb_has_field", _build_has_field, enabled_by_default=False)
PROTOBUF_SET_HAS_FIELD = make_template("_pb_set_has_field", _build_set_has_field, enabled_by_default=False)
PROTOBUF_CLEAR_HAS_FIELD = make_template("_pb_clear_has_field", _build_clear_has_field, enabled_by_default=False)

ALL_PROTOBUF_TEMPLATES = [PROTOBUF_HAS_FIELD, PROTOBUF_SET_HAS_FIELD, PROTOBUF_CLEAR_HAS_FIELD]
