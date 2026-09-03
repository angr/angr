from __future__ import annotations

from angr.analyses.decompiler.optimization_passes.combo_register_rewriter import ComboRegisterRewriter
from angr.analyses.decompiler.optimization_passes.ret_expr_rewriter import RetExprRewriter


class GoRetExprRewriter(RetExprRewriter):
    """Give calls to functions with several results a combo-register return expression."""

    NAME = "Rewrite return expressions of calls to Go functions with several results"

    def _check(self):
        return self.project.is_go_binary, None


class GoComboRegisterRewriter(ComboRegisterRewriter):
    """Fold register pairs that make up one combo-register parameter back into that parameter."""

    NAME = "Rewrite combo-register parameter references"

    def _check(self):
        return self.project.is_go_binary, None
