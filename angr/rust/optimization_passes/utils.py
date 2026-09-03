# Compatibility shim: the AIL rewriting helpers live in angr.analyses.decompiler.optimization_passes.rewriter_utils now.
from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.rewriter_utils import (
    CallRewriter,
    SideEffectStatementRewriter,
    extract_callee,
    extract_str,
    extract_str_from_addr,
    replace_argument_pairs,
)

__all__ = [
    "CallRewriter",
    "SideEffectStatementRewriter",
    "extract_callee",
    "extract_str",
    "extract_str_from_addr",
    "replace_argument_pairs",
]
