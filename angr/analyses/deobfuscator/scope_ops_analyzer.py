from __future__ import annotations

import logging

from collections import Counter
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker
from angr.analyses.decompiler import Decompiler
from angr import Analysis

_l = logging.getLogger(name=__name__)

class ScopeOpsWalker(CStructuredCodeWalker):
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
            self.current_addr = obj.tags["ins_addr"] if "ins_addr" in obj.tags else obj.addr
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

    def __init__(self, decomp: Decompiler):
        if not decomp.codegen:
            _l.warning("ScopeOpsAnalyzer called with an unsuccessful decompilation %s", decomp)
            self.scope_ops = { }
            return
        self.scope_ops = ScopeOpsWalker().handle(decomp.codegen.cfunc)

    def filter_scopes(self, wanted_ops: set, min_count):
        return [
            a for a, s in self.scope_ops.items() if sum(self.scope_ops[a][v] for v in s if v in wanted_ops) >= min_count
        ]

    def crypto_scopes(self, min_count=20):
        return self.filter_scopes({"Xor", "Ror", "Rol", "Shl", "Shr"}, min_count)
