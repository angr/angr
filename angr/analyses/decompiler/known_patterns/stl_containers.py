"""C++ STL std::vector accessors beyond size(): empty / capacity / operator[].

The three-pointer vector layout is shared by libstdc++ and the MSVC STL, so a
single template per accessor — with word-scaled offsets and pointer-sized loads
from the :class:`PatternContext` — covers 32- and 64-bit on either runtime.

Calibrated against the known_patterns_stl binaries (libstdc++ ELF, MSVC x64/x86).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL, size_t_typename
from .dsl import PBinOp, PConst, PLoad, PVVar
from .layouts import vector_begin_offset, vector_cap_offset, vector_end_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_vector_size import STD_VECTOR_INT
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

_ELT_SIZE = 4  # int


def _vfield(cap: str, off: int, size: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


def _build_vector_empty(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    return KnownPattern(
        name="std_vector_int_empty",
        display_name="std::vector<int>::empty",
        call_name="std::vector<int>::empty",
        pattern=PBinOp("CmpEQ", (_vfield("v", vector_end_offset(ctx), ws), _vfield("v", vector_begin_offset(ctx), ws))),
        params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
        returnty="int",
    )


def _build_vector_capacity(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    return KnownPattern(
        name="std_vector_int_capacity",
        display_name="std::vector<int>::capacity",
        call_name="std::vector<int>::capacity",
        pattern=PBinOp(
            frozenset({"Sar", "Shr"}),
            (
                PBinOp("Sub", (_vfield("v", vector_cap_offset(ctx), ws), _vfield("v", vector_begin_offset(ctx), ws))),
                PConst(2),
            ),
        ),
        params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
        returnty=size_t_typename(ctx.bits),
    )


def _build_vector_index(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    return KnownPattern(
        name="std_vector_int_index",
        display_name="std::vector<int>::operator[]",
        call_name="std::vector<int>::operator[]",
        pattern=PLoad(
            PBinOp("Add", (_vfield("v", vector_begin_offset(ctx), ws), PBinOp("Mul", (PVVar("i"), PConst(_ELT_SIZE))))),
            size=_ELT_SIZE,
        ),
        params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)), PatternParam("i")),
        returnty="int",
    )


STD_VECTOR_INT_EMPTY = make_template("std::vector<int>::empty", _build_vector_empty, arches=INTEL, languages=(CPP,))
STD_VECTOR_INT_CAPACITY = make_template(
    "std::vector<int>::capacity", _build_vector_capacity, arches=INTEL, languages=(CPP,)
)
# opt-in: overlaps plain int-array indexing
STD_VECTOR_INT_INDEX = make_template(
    "std::vector<int>::operator[]", _build_vector_index, arches=INTEL, languages=(CPP,), enabled_by_default=False
)
