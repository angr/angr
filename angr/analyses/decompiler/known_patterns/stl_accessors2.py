"""C++ STL accessors, round two: std::string capacity/back/front and
std::vector<T>::back().

``std::string::capacity()`` is the only control-flow idiom here. libstdc++ lays
std::string out as ``{ _M_p , _M_string_length , union { _M_local_buf[16] |
_M_allocated_capacity } }``, so ``capacity()`` is the SSO select::

    _M_p == &_M_local_buf ? 15 : _M_allocated_capacity

i.e. a diamond. Unlike the MSVC ``c_str()`` triangle (see
:mod:`.std_string_cstr`), *both* arms of this diamond assign a value, so
ITERegionConverter — which runs at AFTER_GLOBAL_SIMPLIFICATION, before the
KnownPatternOutliner at BEFORE_VARIABLE_RECOVERY — has already folded the region
into a single ``x = c ? a : b`` assignment by the time patterns are matched.
The idiom is therefore a :class:`~.dsl.PITE` expression pattern, not a
PGraphPat. (When gcc's tail duplication copies the join into both arms instead
of merging them, no ITE and no single-exit region exists and the idiom is not
matched; that is deliberate — there is nothing to outline.)

The comparison ``Load(s) == s + 16`` — a loaded pointer tested against the
object's own address plus the union offset — is what makes the pattern
self-guarding; the SSO threshold 15 is fixed for ``char`` strings, and the union
offset is word-scaled, so one definition covers 32- and 64-bit.

``back()``/``front()`` are plain expression idioms: ``*(_M_p + size - 1)`` and
``*_M_p``. ``std::vector<T>::back()`` is ``*(_M_finish - sizeof(T))``.

Calibrated against tests/x86_64/decompiler/known_patterns_stl2 (g++ 12.2.0 -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL, LIBSTDCXX, size_t_typename
from .dsl import (
    PITE,
    PAssign,
    PBinOp,
    PBlockPat,
    PChoice,
    PCondJump,
    PConst,
    PField,
    PGraphPat,
    PLoad,
    PStackField,
    PStmtSeq,
    PVVar,
)
from .layouts import string_capacity_offset, string_data_offset, string_size_offset, vector_end_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_string_length import STD_BASIC_STRING, STRING_WITNESSED
from .std_vector_size import STD_VECTOR_UNIQUE_NAME_TMPL
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

# libstdc++ char SSO: sizeof(_M_local_buf)/sizeof(char) - 1
_SSO_LOCAL_CAPACITY = 15


def _field(cap: str, off: int, size: int) -> PLoad:
    """A field read of a container identified by *two* of its fields, so the
    object may sit at a non-zero offset inside another one (see
    :class:`~.dsl.PField`). capacity() reads _M_p and the local buffer; back()
    reads _M_p and _M_string_length."""
    return PLoad(PField(cap, off), size=size)


def _field_bare(cap: str, off: int, size: int) -> PLoad:
    """The single-field form, for accessors with no second displacement to
    constrain a floating base (front(), vector::back())."""
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


# --- std::string ------------------------------------------------------------


def _build_string_capacity(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    local_buf = PField("s", string_capacity_offset(ctx))
    data_is_local = _field("s", string_data_offset(ctx), ws)
    heap_cap = _field("s", string_capacity_offset(ctx), ws)
    local_cap = PConst(_SSO_LOCAL_CAPACITY)
    return KnownPattern(
        name="std_string_capacity",
        display_name="std::string::capacity",
        call_name="std::string::capacity",
        # both branch polarities: the compiler is free to emit either
        pattern=PChoice(
            PITE(PBinOp("CmpEQ", (data_is_local, local_buf)), local_cap, heap_cap),
            PITE(PBinOp("CmpNE", (data_is_local, local_buf)), heap_cap, local_cap),
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=size_t_typename(ctx.bits),
    )


def _build_string_capacity_branch(ctx: PatternContext) -> KnownPattern:
    """The same SSO select as a *triangle* rather than a diamond.

    clang does not materialize a value in both arms. It seeds the register with
    the local capacity and overwrites it only on the heap path::

        mov  $0xf,%ecx           ; lc = 15
        cmp  %r15,%rax           ; _M_p == &_M_local_buf ?
        je   skip
        mov  0x40(%rsi),%rcx     ; h = _M_allocated_capacity
      skip:

    One arm is empty, so ITERegionConverter leaves it alone and no ITE ever
    forms -- which is why :func:`_build_string_capacity` scored 0% on every clang
    arm of the benchmark corpus while managing ~25% on gcc. The two spellings
    cannot share a pattern object: one is an expression, the other a region.
    """
    ws = ctx.word_size
    local_buf = PField("s", string_capacity_offset(ctx))
    data = _field("s", string_data_offset(ctx), ws)
    heap_cap = _field("s", string_capacity_offset(ctx), ws)
    return KnownPattern(
        name="std_string_capacity",
        display_name="std::string::capacity",
        call_name="std::string::capacity",
        pattern=PGraphPat(
            blocks={
                # lc = 15; if (_M_p == &_M_local_buf) fall through, else load the
                # allocated capacity. Both polarities: the edge set is what the
                # region match is keyed on, not which successor is the taken one.
                "entry": PBlockPat(
                    "entry",
                    PStmtSeq(
                        (
                            PAssign(PVVar("lc"), PConst(_SSO_LOCAL_CAPACITY)),
                            PCondJump(
                                PChoice(
                                    PBinOp("CmpEQ", (data, local_buf)),
                                    PBinOp("CmpNE", (data, local_buf)),
                                )
                            ),
                        )
                    ),
                ),
                "heap": PBlockPat("heap", PStmtSeq((PAssign(PVVar("h"), heap_cap),))),
            },
            edges=[("entry", "heap"), ("entry", "merge"), ("heap", "merge")],
            entry="entry",
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=size_t_typename(ctx.bits),
    )


def _build_string_capacity_stack(ctx: PatternContext) -> KnownPattern:
    """The SSO select on a std::string that lives on the stack.

    A local string is not an object by the time patterns run: variable recovery
    has split it into one virtual variable per slot, so there is no ``Load(s)``
    and no ``s + 16``. What survives is the *shape* -- the data slot compared
    against the address of the slot sixteen bytes along, selecting between 15 and
    that slot's value -- and that is what :class:`~.dsl.PStackField` matches, on
    stack offsets instead of displacements.

    Stack objects are 18-56% of this accessor's sites across the benchmark
    corpus, so this is not an edge case; see kp-eval/stack_share.py.
    """
    cap_off = string_capacity_offset(ctx)
    data = PStackField("s", string_data_offset(ctx))
    local_buf = PStackField("s", cap_off, as_address=True)
    heap_cap = PStackField("s", cap_off)
    local_cap = PConst(_SSO_LOCAL_CAPACITY)
    return KnownPattern(
        name="std_string_capacity",
        display_name="std::string::capacity",
        call_name="std::string::capacity",
        pattern=PChoice(
            PITE(PBinOp("CmpEQ", (data, local_buf)), local_cap, heap_cap),
            PITE(PBinOp("CmpNE", (data, local_buf)), heap_cap, local_cap),
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=size_t_typename(ctx.bits),
    )


def _build_string_back(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    data = _field("s", string_data_offset(ctx), ws)
    length = _field("s", string_size_offset(ctx), ws)
    return KnownPattern(
        name="std_string_back",
        display_name="std::string::back",
        call_name="std::string::back",
        pattern=PLoad(PBinOp("Sub", (PBinOp("Add", (data, length)), PConst(1))), size=1),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty="char",
    )


def _build_string_front(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="std_string_front",
        display_name="std::string::front",
        call_name="std::string::front",
        pattern=PLoad(_field_bare("s", string_data_offset(ctx), ctx.word_size), size=1),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty="char",
    )


# libstdc++ only: MSVC keeps the capacity in a plain _Myres field (no select),
# and its back()/front() go through the SSO buffer union.
STD_STRING_CAPACITY = make_template(
    "std::string::capacity",
    _build_string_capacity,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_capacity",
)
# The triangle spelling is a second template rather than another arm of the
# first: a PGraphPat is a region, a PITE is an expression, and one KnownPattern
# holds one pattern object. Both emit the same call name and the same pattern
# name, so they are one family to everything downstream.
STD_STRING_CAPACITY_BRANCH = make_template(
    "std::string::capacity (triangle)",
    _build_string_capacity_branch,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_capacity_branch",
)
STD_STRING_CAPACITY_STACK = make_template(
    "std::string::capacity (stack)",
    _build_string_capacity_stack,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_capacity_stack",
)
STD_STRING_BACK = make_template(
    "std::string::back",
    _build_string_back,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_back",
)
# opt-in: `**(char **)p` is one of the most common shapes in any C++ binary. Gated on corroboration: in a function
# where length() or capacity() already pinned the object down as a std::string, the double dereference is front().
STD_STRING_FRONT = make_template(
    "std::string::front",
    _build_string_front,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    enabled_by_default=False,
    name="std_string_front",
    gate=STRING_WITNESSED,
)


# --- std::vector<T>::back() -------------------------------------------------


def make_std_vector_back_template(elt_name: str, elt_size: int, returnty: str):
    """A ``std::vector<elt_name>::back`` template: ``*(_M_finish - sizeof(T))``."""
    slug = elt_name.replace(" ", "_")
    unique_name = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name)
    call_name = f"std::vector<{elt_name}>::back"

    def build(ctx: PatternContext) -> KnownPattern:
        end = _field_bare("v", vector_end_offset(ctx), ctx.word_size)
        return KnownPattern(
            name=f"std_vector_{slug}_back",
            display_name=call_name,
            call_name=call_name,
            pattern=PLoad(PBinOp("Sub", (end, PConst(elt_size))), size=elt_size),
            params=(PatternParam("v", type=CppRef(unique_name)),),
            returnty=returnty,
        )

    return make_template(
        call_name, build, arches=INTEL, languages=(CPP,), enabled_by_default=False, name=f"std_vector_{slug}_back"
    )


# opt-in: `*(p->field_1 - N)` with N == the load width also describes a
# header-behind-the-pointer read (allocators, refcounted buffers).
#
# Element sizes 1/2/4/8. char and bool together are 20% of the corpus' DWARF
# sites for this accessor -- more than the 8-byte elements -- but `*(p - 1)` is
# also the most generic of the four, which is another reason the whole family
# stays opt-in. The remaining 60% are class elements, where back() returns a
# reference: the machine code is an address computation with no element load at
# all, so no template can express them.
STD_VECTOR_CHAR_BACK = make_std_vector_back_template("char", 1, "char")
STD_VECTOR_INT_BACK = make_std_vector_back_template("int", 4, "int")
STD_VECTOR_LONG_LONG_BACK = make_std_vector_back_template("long long", 8, "long long")
STD_VECTOR_SHORT_BACK = make_std_vector_back_template("short", 2, "short")


ALL_STL2_TEMPLATES = [
    STD_STRING_CAPACITY,
    STD_STRING_CAPACITY_BRANCH,
    STD_STRING_CAPACITY_STACK,
    STD_STRING_BACK,
    STD_STRING_FRONT,
    STD_VECTOR_CHAR_BACK,
    STD_VECTOR_SHORT_BACK,
    STD_VECTOR_INT_BACK,
    STD_VECTOR_LONG_LONG_BACK,
]
