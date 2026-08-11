"""Inlined std::vector<T>::size().

libstdc++ and the MSVC STL both lay out std::vector as three pointers
(_M_start/_M_finish/_M_end_of_storage), so ``size() == (_M_finish - _M_start)
/ sizeof(T)``:

    (Load(v + word(1)) - Load(v)) >> log2(sizeof(T))

One template per common element size (short/int/long long); the field offsets
and load width come from the :class:`PatternContext` (word-scaled), so a single
definition covers 32- and 64-bit. ``sizeof(T) == 1`` is not covered (no shift →
a bare pointer difference, too generic).

Calibrated against the known_patterns_stl binaries (libstdc++ ELF, MSVC x64/x86).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.procedures.definitions.types_stl import EXACTDIV_ELEMENT_SIZES

from .context import CPP, INTEL, size_t_typename
from .dsl import PBinOp, PConst, PLoad, PVVar
from .layouts import vector_begin_offset, vector_end_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

STD_VECTOR_UNIQUE_NAME_TMPL = "class std::vector<{elt}, class std::allocator<{elt}>>"
STD_VECTOR_INT = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt="int")


def _vfield(cap: str, off: int, size: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


def make_std_vector_size_template(elt_name: str, log2_elt_size: int):
    """A ``std::vector<elt_name>::size`` template (``sizeof(elt) == 1 <<
    log2_elt_size``)."""
    assert log2_elt_size > 0, "sizeof(T) == 1 has no shift and is too generic to match"
    slug = elt_name.replace(" ", "_")
    unique_name = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name)
    call_name = f"std::vector<{elt_name}>::size"

    def build(ctx: PatternContext) -> KnownPattern:
        ws = ctx.word_size
        return KnownPattern(
            name=f"std_vector_{slug}_size",
            display_name=call_name,
            call_name=call_name,
            pattern=PBinOp(
                frozenset({"Sar", "Shr"}),
                (
                    PBinOp(
                        "Sub", (_vfield("v", vector_end_offset(ctx), ws), _vfield("v", vector_begin_offset(ctx), ws))
                    ),
                    PConst(log2_elt_size),
                ),
            ),
            params=(PatternParam("v", type=CppRef(unique_name)),),
            returnty=size_t_typename(ctx.bits),
        )

    return make_template(call_name, build, arches=INTEL, languages=(CPP,), name=f"std_vector_{slug}_size")


STD_VECTOR_SHORT_SIZE = make_std_vector_size_template("short", 1)
STD_VECTOR_INT_SIZE = make_std_vector_size_template("int", 2)
STD_VECTOR_LONG_LONG_SIZE = make_std_vector_size_template("long long", 3)
# std::vector<T>::size() for non-power-of-two sizeof(T)
#
# `(_M_finish - _M_start) / sizeof(T)` is an *exact* division: the compiler
# knows the byte difference is a whole multiple of sizeof(T), so instead of the
# usual mulhi-and-shift it emits
#
#     (diff >> ctz(sizeof(T))) * modinv(sizeof(T) >> ctz(sizeof(T)), 2**bits)
#
# -- a right shift by the number of trailing zeros of sizeof(T) followed by a
# plain low-half multiply by the modular inverse of its odd part. Both operands
# are fully determined by sizeof(T), so one template per element size can be
# generated. Verified on g++ 12.2.0 at -O1/-Os/-O2/-O3 for sizeof(T) in
# {3,6,12,20,24,40,48,56,72,80}.
#
# Without these, such a vector is *mis*-identified: the inner `diff >> 2` alone
# matches std::vector<int>::size, leaving a bare magic multiply in the output,
# and a 48-byte element vector was even typed std::string * with its size read
# rendered as std::string::length.


def exact_div_magic(elt_size: int, bits: int) -> tuple[int, int]:
    """``(shift, magic)`` of the exact-division-by-``elt_size`` idiom."""
    shift = (elt_size & -elt_size).bit_length() - 1
    return shift, pow(elt_size >> shift, -1, 1 << bits)


def make_std_vector_size_exactdiv_template(elt_name: str, elt_size: int):
    """A ``std::vector<elt_name>::size`` template for a non-power-of-two
    ``sizeof(elt_name)`` (the magic-multiply form)."""
    assert elt_size & (elt_size - 1), "power-of-two sizeof(T): use make_std_vector_size_template"
    slug = elt_name.replace(" ", "_")
    unique_name = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name)
    call_name = f"std::vector<{elt_name}>::size"

    def build(ctx: PatternContext) -> KnownPattern:
        ws = ctx.word_size
        shift, magic = exact_div_magic(elt_size, ctx.bits)
        diff = PBinOp("Sub", (_vfield("v", vector_end_offset(ctx), ws), _vfield("v", vector_begin_offset(ctx), ws)))
        scaled = diff if shift == 0 else PBinOp(frozenset({"Sar", "Shr"}), (diff, PConst(shift)))
        return KnownPattern(
            name=f"std_vector_{slug}_size",
            display_name=call_name,
            call_name=call_name,
            pattern=PBinOp("Mul", (scaled, PConst(magic))),
            params=(PatternParam("v", type=CppRef(unique_name)),),
            returnty=size_t_typename(ctx.bits),
        )

    return make_template(call_name, build, arches=INTEL, languages=(CPP,), name=f"std_vector_{slug}_size")


# Every non-power-of-two element size with a registered opaque T<N> class. The
# list is deliberately wide rather than a handful of common sizes: sizeof(T) is
# whatever the program's record happens to be (112 for CryptoPP::ECPPoint, say),
# and a size that is not covered leaves the raw magic multiply in the output --
# precisely the shape this pattern exists to remove.
STD_VECTOR_EXACTDIV_SIZES = EXACTDIV_ELEMENT_SIZES
STD_VECTOR_STRUCT_SIZE_TEMPLATES = [
    make_std_vector_size_exactdiv_template(f"T{n}", n) for n in STD_VECTOR_EXACTDIV_SIZES
]
