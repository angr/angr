"""Inlined std::vector<T>::size() and capacity().

libstdc++ and the MSVC STL both lay out std::vector as three pointers
(_M_start/_M_finish/_M_end_of_storage), so both accessors are one pointer
difference divided by sizeof(T):

    size()     == (_M_finish         - _M_start) / sizeof(T)
    capacity() == (_M_end_of_storage - _M_start) / sizeof(T)

i.e. the same shape reading a different minuend field. The field offsets and load
width come from the :class:`PatternContext` (word-scaled), so one definition
covers 32- and 64-bit.

``sizeof(T)`` is not recoverable from anything but the divisor, so there is one
template per element size. Three ranges of sizeof(T) need three spellings:

* a power of two up to 8 -- a bare shift, and there is a named C++ type of that
  width (short/int/long long);
* a power of two above 8 -- still a bare shift, but no named type, so the element
  is the opaque ``T<N>`` class (``sizeof(std::string) == 32``, and
  ``std::vector<std::string>`` is the corpus' most common element type);
* not a power of two -- the exact-division magic-multiply idiom below.

``sizeof(T) == 1`` is not covered for size()/capacity(): with no shift the idiom
is a bare pointer difference, too generic to name.

Calibrated against the known_patterns_stl binaries (libstdc++ ELF, MSVC x64/x86).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.procedures.definitions.types_stl import EXACTDIV_ELEMENT_SIZES, SHIFT_ELEMENT_SIZES

from .context import CPP, INTEL, size_t_typename
from .dsl import PBinOp, PConst, PField, PLoad
from .layouts import vector_begin_offset, vector_cap_offset, vector_end_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from collections.abc import Callable

    from .context import PatternContext

STD_VECTOR_UNIQUE_NAME_TMPL = "class std::vector<{elt}, class std::allocator<{elt}>>"
STD_VECTOR_INT = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt="int")


def _vfield(cap: str, off: int, size: int) -> PLoad:
    # PField, not PVVar+PConst: size() reads _M_start *and* _M_finish, so the two
    # displacements constrain each other and the vector no longer has to sit at
    # the address held in a register. A vector that is a member of another object
    # -- ``this->tokens.size()``, most vectors in real code -- lifts to
    # Load(this + 56) / Load(this + 64) and could not bind ``v`` at all before.
    return PLoad(PField(cap, off), size=size)


def _byte_diff(ctx: PatternContext, minuend_offset: int) -> PBinOp:
    """``Load(v + minuend) - Load(v + _M_start)`` -- the byte extent."""
    ws = ctx.word_size
    return PBinOp("Sub", (_vfield("v", minuend_offset, ws), _vfield("v", vector_begin_offset(ctx), ws)))


# The two accessors, as (name, the offset of the field the difference is taken
# from). capacity() is deliberately generated over the same element sizes as
# size(): it had only the int template, and the benchmark corpus contains **zero**
# 4-byte-element capacity sites, so it could not fire at all.
_ACCESSORS: tuple[tuple[str, Callable[[PatternContext], int]], ...] = (
    ("size", vector_end_offset),
    ("capacity", vector_cap_offset),
)


def exact_div_magic(elt_size: int, bits: int) -> tuple[int, int]:
    """``(shift, magic)`` of the exact-division-by-``elt_size`` idiom."""
    shift = (elt_size & -elt_size).bit_length() - 1
    return shift, pow(elt_size >> shift, -1, 1 << bits)


def _make_vector_div_template(accessor: str, minuend: Callable[[PatternContext], int], elt_name: str, elt_size: int):
    """A ``std::vector<elt_name>::<accessor>`` template.

    Power-of-two ``elt_size`` divides with a bare shift; anything else is the
    exact-division idiom: ``(_M_finish - _M_start) / sizeof(T)`` is an *exact*
    division -- the compiler knows the byte difference is a whole multiple of
    sizeof(T) -- so instead of the usual mulhi-and-shift it emits

        (diff >> ctz(sizeof(T))) * modinv(sizeof(T) >> ctz(sizeof(T)), 2**bits)

    a right shift by the number of trailing zeros of sizeof(T) followed by a plain
    low-half multiply by the modular inverse of its odd part. Both operands are
    fully determined by sizeof(T), so one template per element size can be
    generated. Verified on g++ 12.2.0 at -O1/-Os/-O2/-O3 for sizeof(T) in
    {3,6,12,20,24,40,48,56,72,80}.

    Without them such a vector is *mis*-identified: the inner ``diff >> 2`` alone
    matches std::vector<int>::size, leaving a bare magic multiply in the output,
    and a 48-byte element vector was even typed ``std::string *`` with its size
    read rendered as std::string::length.
    """
    assert elt_size > 1, "sizeof(T) == 1 has no shift and is too generic to match"
    slug = elt_name.replace(" ", "_")
    unique_name = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name)
    call_name = f"std::vector<{elt_name}>::{accessor}"
    name = f"std_vector_{slug}_{accessor}"
    is_pow2 = not (elt_size & (elt_size - 1))

    def build(ctx: PatternContext) -> KnownPattern:
        diff = _byte_diff(ctx, minuend(ctx))
        if is_pow2:
            pattern = PBinOp(frozenset({"Sar", "Shr"}), (diff, PConst(elt_size.bit_length() - 1)))
        else:
            shift = exact_div_magic(elt_size, ctx.bits)[0]
            scaled = diff if shift == 0 else PBinOp(frozenset({"Sar", "Shr"}), (diff, PConst(shift)))
            # The multiply is as wide as the *result the caller wanted*, not as
            # wide as the pointer difference: clang narrows to 32 bits whenever
            # size() feeds an int, emitting `Mul(Conv(64->32, diff >> k), inv32)`
            # with the 32-bit modular inverse. Accepting only the word-width
            # magic is most of why this family scored 21% on gcc and 2.8% on
            # clang. (The Convert itself needs no pattern node -- structural
            # matching skips Convert wrappers.)
            magics = {exact_div_magic(elt_size, b)[1] for b in {ctx.bits, 32}}
            pattern = PBinOp("Mul", (scaled, PConst(pred=magics.__contains__)))
        return KnownPattern(
            name=name,
            display_name=call_name,
            call_name=call_name,
            pattern=pattern,
            params=(PatternParam("v", type=CppRef(unique_name)),),
            returnty=size_t_typename(ctx.bits),
        )

    return make_template(call_name, build, arches=INTEL, languages=(CPP,), name=name)


def make_std_vector_size_template(elt_name: str, log2_elt_size: int):
    """A power-of-two ``std::vector<elt_name>::size`` template."""
    return _make_vector_div_template("size", vector_end_offset, elt_name, 1 << log2_elt_size)


def make_std_vector_size_exactdiv_template(elt_name: str, elt_size: int):
    """A non-power-of-two ``std::vector<elt_name>::size`` template."""
    assert elt_size & (elt_size - 1), "power-of-two sizeof(T): use make_std_vector_size_template"
    return _make_vector_div_template("size", vector_end_offset, elt_name, elt_size)


# element sizes with a named C++ type
_NAMED_ELEMENTS: tuple[tuple[str, int], ...] = (("short", 2), ("int", 4), ("long long", 8))

STD_VECTOR_SHORT_SIZE = _make_vector_div_template("size", vector_end_offset, "short", 2)
STD_VECTOR_INT_SIZE = _make_vector_div_template("size", vector_end_offset, "int", 4)
STD_VECTOR_LONG_LONG_SIZE = _make_vector_div_template("size", vector_end_offset, "long long", 8)

#: Every opaque element size, power-of-two and not. The list is deliberately wide
#: rather than a handful of common sizes: sizeof(T) is whatever the program's
#: record happens to be (112 for CryptoPP::ECPPoint, say), and a size that is not
#: covered leaves the raw magic multiply in the output -- precisely the shape this
#: pattern exists to remove.
STD_VECTOR_EXACTDIV_SIZES = EXACTDIV_ELEMENT_SIZES
STD_VECTOR_OPAQUE_SIZES = tuple(sorted(EXACTDIV_ELEMENT_SIZES + SHIFT_ELEMENT_SIZES))

STD_VECTOR_STRUCT_SIZE_TEMPLATES = [
    _make_vector_div_template("size", vector_end_offset, f"T{n}", n) for n in STD_VECTOR_OPAQUE_SIZES
]

# capacity(): the same expression against _M_end_of_storage, over the same
# element sizes. Not opt-in -- like size() it reads two of the three vector
# pointers at a fixed distance, which is self-guarding.
STD_VECTOR_CAPACITY_TEMPLATES = [
    _make_vector_div_template("capacity", vector_cap_offset, elt_name, elt_size)
    for elt_name, elt_size in _NAMED_ELEMENTS
] + [_make_vector_div_template("capacity", vector_cap_offset, f"T{n}", n) for n in STD_VECTOR_OPAQUE_SIZES]
