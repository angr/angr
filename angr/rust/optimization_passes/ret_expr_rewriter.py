# Compatibility shim: the pass lives in angr.analyses.decompiler.optimization_passes now.
from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.ret_expr_rewriter import RetExprRewriter

__all__ = ["RetExprRewriter"]
