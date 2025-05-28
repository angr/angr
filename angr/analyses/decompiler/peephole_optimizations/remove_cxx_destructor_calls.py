# pylint:disable=arguments-differ
from __future__ import annotations

from angr.ailment.expression import Const
from angr.ailment.statement import Call

from .base import PeepholeOptimizationStmtBase


class RemoveCxxDestructorCalls(PeepholeOptimizationStmtBase):
    """
    Rewrite C++ operator function calls into operations.
    """

    __slots__ = ()

    NAME = "Remove C++ destructor function calls"
    stmt_classes = (Call,)

    def optimize(self, stmt: Call, **kwargs) -> tuple | None:  # type:ignore
        # are we calling a function that we deem as a C++ destructor?
        assert self.project is not None

        if isinstance(stmt.target, Const):
            func_addr = stmt.target.value
            if not self.project.kb.functions.contains_addr(func_addr):
                return None
            func = self.project.kb.functions[func_addr]
            if "::~" in func.demangled_name and stmt.args is not None:
                # yes it is!
                return ()
        return None
