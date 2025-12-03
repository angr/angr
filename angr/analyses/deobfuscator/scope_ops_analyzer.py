from __future__ import annotations
from typing import TYPE_CHECKING

import logging

from collections import Counter
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker
from angr.analyses.analysis import Analysis

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CFunction

_l = logging.getLogger(name=__name__)


class ScopeOpsWalker(CStructuredCodeWalker):
    """
    ScopeOpsWalker walks a C construct (typically a C function) and extracts counts of all operations in each scope.
    Its intended use is to reason about the intent of different parts of functions (e.g., crypto implementations).
    """

    def __init__(self):
        self.current_addr = None
        self.found_ops = {}

    def handle(self, obj):
        if type(obj).__name__ in [
            "CFunction",
            "CWhileLoop",
            "CDoWhileLoop",
            "CSwitchCase",
            "CIfBreak",
            "CForLoop",
            "CIfElse",
        ]:
            old_addr = self.current_addr
            self.current_addr = obj.tags.get("ins_addr", getattr(obj, "addr", None))
            self.found_ops.setdefault(self.current_addr, Counter())
            super().handle(obj)
            self.current_addr = old_addr
            return self.found_ops
        return super().handle(obj)

    def handle_CBinaryOp(self, obj):
        self.found_ops[self.current_addr][obj.op] += 1
        return self.found_ops

    def handle_CUnaryOp(self, obj):
        self.found_ops[self.current_addr][obj.op] += 1
        return self.found_ops


class ScopeOpsAnalyzer(Analysis):
    """
    An analysis that extracts and analyzes operations used by different scopes of a function.
    """

    def __init__(self, cfunc: CFunction):
        self._cfunc = cfunc
        self.scope_ops = ScopeOpsWalker().handle(cfunc)

    def filter_scopes(self, wanted_ops: set, min_count):
        return [
            a for a, s in self.scope_ops.items() if sum(self.scope_ops[a][v] for v in s if v in wanted_ops) >= min_count
        ]

    def crypto_scopes(self, min_count=20):
        return self.filter_scopes({"Xor", "Ror", "Rol", "Shl", "Shr"}, min_count)
