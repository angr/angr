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
from .dsl import PITE, PBinOp, PChoice, PConst, PLoad, PVVar
from .layouts import string_capacity_offset, string_data_offset, string_size_offset, vector_end_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_string_length import STD_BASIC_STRING
from .std_vector_size import STD_VECTOR_UNIQUE_NAME_TMPL
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

# libstdc++ char SSO: sizeof(_M_local_buf)/sizeof(char) - 1
_SSO_LOCAL_CAPACITY = 15


def _field(cap: str, off: int, size: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


# --- std::string ------------------------------------------------------------


def _build_string_capacity(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    local_buf = PBinOp("Add", (PVVar("s"), PConst(string_capacity_offset(ctx))))
    data_is_local = PLoad(PVVar("s"), size=ws)
    heap_cap = PLoad(local_buf, size=ws)
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
        pattern=PLoad(_field("s", string_data_offset(ctx), ctx.word_size), size=1),
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
STD_STRING_BACK = make_template(
    "std::string::back",
    _build_string_back,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_back",
)
# opt-in: `**(char **)p` is one of the most common shapes in any C++ binary
STD_STRING_FRONT = make_template(
    "std::string::front",
    _build_string_front,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    enabled_by_default=False,
    name="std_string_front",
)


# --- std::vector<T>::back() -------------------------------------------------


def make_std_vector_back_template(elt_name: str, elt_size: int, returnty: str):
    """A ``std::vector<elt_name>::back`` template: ``*(_M_finish - sizeof(T))``."""
    slug = elt_name.replace(" ", "_")
    unique_name = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name)
    call_name = f"std::vector<{elt_name}>::back"

    def build(ctx: PatternContext) -> KnownPattern:
        end = _field("v", vector_end_offset(ctx), ctx.word_size)
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
STD_VECTOR_INT_BACK = make_std_vector_back_template("int", 4, "int")
STD_VECTOR_LONG_LONG_BACK = make_std_vector_back_template("long long", 8, "long long")
STD_VECTOR_SHORT_BACK = make_std_vector_back_template("short", 2, "short")


ALL_STL2_TEMPLATES = [
    STD_STRING_CAPACITY,
    STD_STRING_BACK,
    STD_STRING_FRONT,
    STD_VECTOR_SHORT_BACK,
    STD_VECTOR_INT_BACK,
    STD_VECTOR_LONG_LONG_BACK,
]
