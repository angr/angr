# Compatibility shim: the pass lives in angr.analyses.decompiler.optimization_passes now.
from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.combo_register_rewriter import ComboRegisterRewriter

__all__ = ["ComboRegisterRewriter"]
