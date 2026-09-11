"""The inlined ``std::string`` destructor.

``~basic_string()`` is one line of source and, at -O2, five lines of machine
code that the compiler emits at every scope exit of every local string and in
every destructor of every class holding one. It is by a wide margin the most
common inlined idiom in C++ binaries: the DWARF inline records of the -O2
benchmark corpus put ``~basic_string`` / ``_M_dispose`` / ``_M_destroy`` at 5.9M
sites across 245 binaries, an order of magnitude above any accessor.

libstdc++ frees the buffer only when the string is not using its small-string
buffer, which is exactly the SSO test ``capacity()`` also uses::

    if (_M_p != &_M_local_buf)
        operator delete(_M_p, _M_allocated_capacity + 1);

a triangle whose taken arm is a single call. Four things have to agree for a
match -- the same object address in the compare and in both loads, the local
buffer's offset appearing both as an address and as a field, the ``+ 1``, and
the callee being ``operator delete`` -- which is what makes this pattern
self-guarding enough to be on by default. The ``+ 1`` is the NUL terminator:
libstdc++ allocated ``capacity + 1`` bytes and hands the same number back to the
sized ``operator delete``.

Sized deallocation is a C++14 feature and a compiler switch, so the one-argument
``operator delete(void *)`` spelling gets its own template; the two cannot share
one pattern object because a statement pattern has no PChoice.

Calibrated against tests/x86_64/decompiler/known_patterns_stl5 (g++ 12.2.0 -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL, LIBSTDCXX
from .dsl import (
    PBinOp,
    PBlockPat,
    PCall,
    PCallStmt,
    PChoice,
    PCondJump,
    PConst,
    PDefOf,
    PField,
    PGraphPat,
    PLoad,
    PStackField,
    PStmtSeq,
)
from .layouts import string_capacity_offset, string_data_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_string_length import STD_BASIC_STRING
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


#: Every spelling of ``operator delete`` a compiler emits for this idiom. The
#: mangled names are exact; the demangled ones are accepted too because
#: :class:`~.dsl.PCall` matches against both and a stripped-but-imported callee
#: may only be known by one of them.
OPERATOR_DELETE = frozenset(
    {
        # Itanium ABI (libstdc++, libc++)
        "_ZdlPv",  # operator delete(void *)
        "_ZdlPvm",  # operator delete(void *, size_t)  -- LP64
        "_ZdlPvj",  # operator delete(void *, size_t)  -- ILP32
        "_ZdlPvSt11align_val_t",
        "_ZdlPvmSt11align_val_t",
        "_ZdlPvjSt11align_val_t",
        "operator delete(void*)",
        "operator delete(void*, unsigned long)",
        "operator delete(void*, unsigned int)",
        # MSVC
        "??3@YAXPEAX@Z",  # operator delete(void *)         -- x64
        "??3@YAXPAX@Z",  # operator delete(void *)          -- x86
        "??3@YAXPEAX_K@Z",  # operator delete(void *, size_t) -- x64
        "??3@YAXPAXI@Z",  # operator delete(void *, size_t)  -- x86
    }
)

_DTOR_CALL_NAME = "std::string::~string"


def _dtor_graph(guard, free_stmt) -> PGraphPat:
    """The triangle: a guarded block whose single statement is the free."""
    return PGraphPat(
        blocks={
            # The condition's polarity is not constrained: which successor is the
            # taken one is a codegen choice, and the edge set is what the region
            # match is keyed on.
            "entry": PBlockPat("entry", PStmtSeq((PCondJump(guard),))),
            "free": PBlockPat("free", PStmtSeq((free_stmt,), allow_gaps=False)),
        },
        edges=[("entry", "free"), ("entry", "join"), ("free", "join")],
        entry="entry",
    )


def _build_dtor(ctx: PatternContext, sized: bool) -> KnownPattern:
    ws = ctx.word_size
    # _M_p is read twice -- once by the compare, once as the pointer to free --
    # so the compiler loads it into a register and neither use is a Load by the
    # time patterns run. PDefOf reads that register's definition, read-only.
    data = PDefOf(PLoad(PField("s", string_data_offset(ctx)), size=ws))
    local_buf = PField("s", string_capacity_offset(ctx))
    heap_cap = PLoad(PField("s", string_capacity_offset(ctx)), size=ws)
    args = (data, PBinOp("Add", (heap_cap, PConst(1)))) if sized else (data,)
    return KnownPattern(
        name="std_string_dtor" if sized else "std_string_dtor_unsized",
        display_name=_DTOR_CALL_NAME,
        call_name=_DTOR_CALL_NAME,
        pattern=_dtor_graph(
            PChoice(
                PBinOp("CmpEQ", (data, local_buf)),
                PBinOp("CmpNE", (data, local_buf)),
            ),
            PCallStmt(PCall(OPERATOR_DELETE, args=args)),
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=None,
    )


def _build_dtor_stack(ctx: PatternContext, sized: bool) -> KnownPattern:
    """The same triangle on a string that lives in stack slots.

    A local string is not an object by the time patterns run: variable recovery
    has split it into one virtual variable per slot, so there is no ``Load(s)``
    and no ``s + 16`` to unify on. What survives is the shape -- the data slot
    compared against the address of the slot two words along, and freed -- which
    is what :class:`~.dsl.PStackField` matches. This is the spelling a local
    ``std::string`` takes, and locals are what most destructors destroy.
    """
    cap_off = string_capacity_offset(ctx)
    data = PDefOf(PStackField("s", string_data_offset(ctx)))
    local_buf = PStackField("s", cap_off, as_address=True)
    heap_cap = PStackField("s", cap_off)
    args = (data, PBinOp("Add", (heap_cap, PConst(1)))) if sized else (data,)
    return KnownPattern(
        name="std_string_dtor",
        display_name=_DTOR_CALL_NAME,
        call_name=_DTOR_CALL_NAME,
        pattern=_dtor_graph(
            PChoice(
                PBinOp("CmpEQ", (data, local_buf)),
                PBinOp("CmpNE", (data, local_buf)),
            ),
            PCallStmt(PCall(OPERATOR_DELETE, args=args)),
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=None,
    )


# The registry key must be unique across templates; the *emitted* call keeps the
# plain name so all four spellings of the destructor are one family everywhere
# downstream (see std_vector_size.STD_VECTOR_STACK_TEMPLATES for the same trick).
STD_STRING_DTOR = make_template(
    _DTOR_CALL_NAME,
    lambda ctx: _build_dtor(ctx, sized=True),
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_dtor",
)
STD_STRING_DTOR_UNSIZED = make_template(
    _DTOR_CALL_NAME + " (unsized)",
    lambda ctx: _build_dtor(ctx, sized=False),
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_dtor_unsized",
)
STD_STRING_DTOR_STACK = make_template(
    _DTOR_CALL_NAME + " (stack)",
    lambda ctx: _build_dtor_stack(ctx, sized=True),
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_dtor_stack",
)
STD_STRING_DTOR_STACK_UNSIZED = make_template(
    _DTOR_CALL_NAME + " (stack, unsized)",
    lambda ctx: _build_dtor_stack(ctx, sized=False),
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    name="std_string_dtor_stack_unsized",
)

ALL_STRING_DTOR_TEMPLATES = [
    STD_STRING_DTOR,
    STD_STRING_DTOR_UNSIZED,
    STD_STRING_DTOR_STACK,
    STD_STRING_DTOR_STACK_UNSIZED,
]
