"""protobuf has-bits accessors (the code protoc generates for optional fields).

For an optional field, protoc emits a ``_has_bits_`` word tested/set/cleared
with a per-field mask:

    has_field()   -> _has_bits_[w] & mask                 (Load(m) And mask)
    set_has()     -> _has_bits_[w] |= mask                (Store(m, Load(m) Or mask))
    clear_has()   -> _has_bits_[w] &= ~mask               (Store(m, Load(m) And ~mask))

These are generic bitfield operations, so the patterns are **opt-in**
(``enabled_by_default=False``) — they match any bitfield read/modify/write, not
only has-bits — and are meant for use when specifically analyzing protobuf-
generated code. The mask is captured as an extra call argument.

Calibrated against tests/x86_64/decompiler/known_patterns_protobuf
(g++ 12.2.0 -O2). The has-bits word here is at offset 0; a real field at a
non-zero word offset would appear as ``Load(m + off)``.
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PStore, PVVar
from .pattern import KnownPattern, PatternParam

_WORD = 4  # _has_bits_ is a 32-bit word


# has_field(m): _has_bits_ & mask
PROTOBUF_HAS_FIELD = KnownPattern(
    name="protobuf_has_field",
    display_name="_pb_has_field",
    call_name="_pb_has_field",
    pattern=PBinOp("And", (PLoad(PVVar("msg"), size=_WORD), PConst(name="mask"))),
    params=(PatternParam("msg"),),
    extra_args=("mask",),
    returnty="int",
    enabled_by_default=False,
)


# set_has_field(m): _has_bits_ |= mask
PROTOBUF_SET_HAS_FIELD = KnownPattern(
    name="protobuf_set_has_field",
    display_name="_pb_set_has_field",
    call_name="_pb_set_has_field",
    pattern=PStore(
        PVVar("msg"),
        PBinOp("Or", (PLoad(PVVar("msg"), size=_WORD), PConst(name="mask"))),
        size=_WORD,
    ),
    params=(PatternParam("msg"),),
    extra_args=("mask",),
    returnty=None,
    enabled_by_default=False,
)


# clear_has_field(m): _has_bits_ &= ~mask  (the stored constant is ~mask)
PROTOBUF_CLEAR_HAS_FIELD = KnownPattern(
    name="protobuf_clear_has_field",
    display_name="_pb_clear_has_field",
    call_name="_pb_clear_has_field",
    pattern=PStore(
        PVVar("msg"),
        PBinOp("And", (PLoad(PVVar("msg"), size=_WORD), PConst(name="notmask"))),
        size=_WORD,
    ),
    params=(PatternParam("msg"),),
    extra_args=("notmask",),
    returnty=None,
    enabled_by_default=False,
)


ALL_PROTOBUF_PATTERNS = [
    PROTOBUF_HAS_FIELD,
    PROTOBUF_SET_HAS_FIELD,
    PROTOBUF_CLEAR_HAS_FIELD,
]
