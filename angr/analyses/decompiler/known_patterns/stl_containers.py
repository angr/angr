"""C++ STL std::vector accessors beyond size()/capacity(): empty / operator[].

The three-pointer vector layout is shared by libstdc++ and the MSVC STL, so a
single template per accessor — with word-scaled offsets and pointer-sized loads
from the :class:`PatternContext` — covers 32- and 64-bit on either runtime.

``capacity()`` lives in :mod:`.std_vector_size` with ``size()``: the two are one
expression against different fields, and both need a template per element size.

Calibrated against the known_patterns_stl binaries (libstdc++ ELF, MSVC x64/x86).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL
from .dsl import PBinOp, PChoice, PConst, PField, PLoad, PVVar
from .gating import corroborated_by_pattern
from .layouts import vector_begin_offset, vector_end_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_vector_size import STD_VECTOR_UNIQUE_NAME_TMPL
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext
    from .dsl import PatternExpr


def _vfield(cap: str, off: int, size: int) -> PLoad:
    # PField: empty() reads two of the three vector pointers, so their
    # displacements constrain each other and the container is free to be a field
    # of another object (see std_vector_size._vfield).
    return PLoad(PField(cap, off), size=size)


def _vfield_bare(cap: str, off: int, size: int) -> PLoad:
    """The single-field form. operator[] reads only _M_start, so there is no
    second displacement to constrain a floating base -- ``Load(PField(v, 0) + i*4)``
    would match every indexed load in the binary."""
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


def _build_vector_empty(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    return KnownPattern(
        name="std_vector_int_empty",
        display_name="std::vector<int>::empty",
        call_name="std::vector<int>::empty",
        pattern=PBinOp("CmpEQ", (_vfield("v", vector_end_offset(ctx), ws), _vfield("v", vector_begin_offset(ctx), ws))),
        params=(PatternParam("v", type=CppRef(STD_VECTOR_UNIQUE_NAME_TMPL.format(elt="int"))),),
        returnty="int",
    )


def make_std_vector_index_template(elt_name: str, elt_size: int, returnty: str):
    """A ``std::vector<elt_name>::operator[]`` template: ``*(_M_start + i * sizeof(T))``.

    One per element size. Only the 4-byte (int) template existed, which covers 5%
    of the corpus' DWARF sites for this accessor: 78% of them are 8-byte elements
    (``unsigned long long`` alone is 30%, pointers another 14%).

    The scale is matched as ``Mul`` *or* ``Shl``: a power-of-two element size lifts
    from `lea (%rax,%rdx,8)` either way depending on how the index reached the
    address, and pinning one spelling silently halves the coverage.
    """
    slug = elt_name.replace(" ", "_")
    unique_name = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name)
    call_name = f"std::vector<{elt_name}>::operator[]"
    name = f"std_vector_{slug}_index"
    log2 = elt_size.bit_length() - 1 if not (elt_size & (elt_size - 1)) else None

    def build(ctx: PatternContext) -> KnownPattern:
        scaled: PatternExpr = PVVar("i")
        if elt_size != 1:
            alts = [PBinOp("Mul", (PVVar("i"), PConst(elt_size)))]
            if log2 is not None:
                alts.append(PBinOp("Shl", (PVVar("i"), PConst(log2))))
            scaled = PChoice(*alts) if len(alts) > 1 else alts[0]
        return KnownPattern(
            name=name,
            display_name=call_name,
            call_name=call_name,
            pattern=PLoad(
                PBinOp("Add", (_vfield_bare("v", vector_begin_offset(ctx), ctx.word_size), scaled)),
                size=elt_size,
            ),
            params=(PatternParam("v", type=CppRef(unique_name)), PatternParam("i")),
            returnty=returnty,
        )

    # opt-in: an indexed load off a pointer field describes every array in every
    # program; only the container's identity makes it operator[].
    return make_template(call_name, build, arches=INTEL, languages=(CPP,), enabled_by_default=False, name=name)


# Opt-in, gated on a size()/capacity() match for the same kind of object.
#
# `Load(v + 8) == Load(v)` is two adjacent pointer fields compared for equality,
# which describes an enormous amount of code that is not a container. Measured
# over the benchmark corpus it fired on 164 functions the oracle knows nothing
# about against 4 it does -- 2.4% precision -- and letting the base float (PField)
# is what took it there: the same family was 22% precise when the container had
# to sit at a register's value. Recall bought that way is not worth having.
#
# The witness is any std::vector<T>::size or ::capacity match in the same
# function: those read two fields at a *fixed distance* and divide by a known
# element size, which is self-guarding in a way that an equality test is not.
STD_VECTOR_INT_EMPTY = make_template(
    "std::vector<int>::empty",
    _build_vector_empty,
    arches=INTEL,
    languages=(CPP,),
    enabled_by_default=False,
    gate=corroborated_by_pattern(r"std_vector_.*_(size|capacity)$"),
)
STD_VECTOR_INDEX_TEMPLATES = [
    make_std_vector_index_template("char", 1, "char"),
    make_std_vector_index_template("short", 2, "short"),
    make_std_vector_index_template("int", 4, "int"),
    make_std_vector_index_template("long long", 8, "long long"),
]
STD_VECTOR_INT_INDEX = STD_VECTOR_INDEX_TEMPLATES[2]
