"""Inlined MSVC ``std::string::c_str()`` / ``data()`` — the small-string
optimization (SSO) select.

The MSVC STL stores the character buffer in a 16-byte union ``_Bx`` at offset 0
(either an inline ``_Buf[16]`` or, for long strings, a heap ``_Ptr``), the size
at offset 16, and the capacity ``_Myres`` one word further on. ``c_str()``
returns the inline buffer address when the string is short and the heap pointer
when it is long, i.e.::

    result = &s->_Bx;                 // == s   (the buffer address)
    if (s->_Myres >= 16)              // capacity past the SSO threshold?
        result = s->_Bx._Ptr;        // == *(void**)s  (the heap pointer)

which the compiler lowers to a control-flow diamond. In clean SSA it is::

    entry:  if (Load(s + cap_off) < 16) goto merge else goto heap
    heap:   h = Load(s)
    merge:  result = Phi(h [heap], s [entry])          // Phi(*s, s)

so it is a :class:`PGraphPat` (entry + heap; the phi merge is the frontier)
rather than an expression idiom. This matches the SSA form *before* de-phi — the
form the KnownPatternOutliner pass sees when it runs at BEFORE_VARIABLE_RECOVERY
— so the idiom is recognized and outlined during decompilation. (SSA
destruction later inserts ``res = s`` / ``h2 = h`` copies that would obscure this
shape; matching the clean form avoids depending on them and needs no cross-copy
unification.) The offsets are word-scaled (cap_off is 24 on x64, 20 on x86); the
16-byte SSO threshold is fixed for ``char`` strings.

libstdc++ ``c_str()`` is a bare ``_M_p`` load (no SSO branch) and is not matched
here. Opt-in — a control-flow select is genericish. Calibrated against
tests/x86_64/windows/known_patterns_msvc_string_cstr.exe (MSVC 19 /O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import INTEL
from .dsl import PAssign, PBinOp, PBlockPat, PCondJump, PConst, PGraphPat, PLoad, PStmtSeq, PVVar
from .layouts import string_data_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .std_string_length import STD_BASIC_STRING
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

# MSVC ``char`` SSO buffer capacity: a string with _Myres past this is heap-allocated.
_SSO_BUF_SIZE = 16


def _build_string_cstr(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    # MSVC std::string: _Bx (16-byte SSO union) at 0, _Mysize at 16, _Myres one
    # word further on. The capacity offset is intrinsic to this MSVC-only idiom,
    # so compute it directly rather than via the runtime-branching layout helper
    # (a statically-linked, stripped MSVC binary evades C++-runtime detection —
    # hence this template gates on platform, not on the detected runtime).
    cap_off = _SSO_BUF_SIZE + ws
    data_off = string_data_offset(ctx)
    heap_ptr = PLoad(PVVar("s") if data_off == 0 else PBinOp("Add", (PVVar("s"), PConst(data_off))), size=ws)
    cap_load = PLoad(PBinOp("Add", (PVVar("s"), PConst(cap_off))), size=ws)
    return KnownPattern(
        name="msvc_string_c_str",
        display_name="std::string::c_str",
        call_name="std::string::c_str",
        pattern=PGraphPat(
            blocks={
                # if (s->_Myres < 16) fall through to the merge, else take the heap branch
                "entry": PBlockPat("entry", PStmtSeq((PCondJump(PBinOp("CmpLT", (cap_load, PConst(_SSO_BUF_SIZE)))),))),
                # h = *(void**)s   (the heap pointer)
                "heap": PBlockPat("heap", PStmtSeq((PAssign(PVVar("h"), heap_ptr),))),
            },
            edges=[("entry", "heap"), ("entry", "merge"), ("heap", "merge")],
            entry="entry",
        ),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty="char *",
    )


# opt-in: a control-flow select is genericish. MSVC-only in practice (libstdc++
# c_str is a bare _M_p load with no SSO branch, so no diamond to match), but
# gated on platform=windows rather than the detected C++ runtime: stripped,
# statically-linked MSVC binaries carry no msvcp dependency or mangled symbols,
# so runtime detection returns None even though the idiom is present. The
# structural pattern (the +cap capacity test, the +0 pointer load, the phi
# merge) is self-guarding against non-MSVC layouts.
STD_STRING_CSTR = make_template(
    "std::string::c_str",
    _build_string_cstr,
    arches=INTEL,
    platforms=("windows",),
    enabled_by_default=True,
    name="msvc_string_c_str",
)
