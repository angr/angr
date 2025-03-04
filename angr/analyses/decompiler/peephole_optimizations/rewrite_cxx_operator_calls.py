# pylint:disable=arguments-differ
from __future__ import annotations

from archinfo import Endness
from ailment.constant import UNDETERMINED_SIZE
from ailment.expression import Const, VirtualVariable, BinaryOp, UnaryOp, Load
from ailment.statement import Call, Assignment

from angr.sim_type import SimTypeReference
from angr.knowledge_plugins.key_definitions import atoms
from .base import PeepholeOptimizationStmtBase


class RewriteCxxOperatorCalls(PeepholeOptimizationStmtBase):
    """
    Rewrite C++ operator function calls into operations.
    """

    __slots__ = ()

    NAME = "Rewrite C++ operator function calls into operations"
    stmt_classes = (Call,)

    def optimize(self, stmt: Call, block=None, **kwargs):
        # are we calling a function that we deem as an overridden operator function?
        if isinstance(stmt.target, Const):
            func_addr = stmt.target.value
            if not self.project.kb.functions.contains_addr(func_addr):
                return None
            func = self.project.kb.functions[func_addr]
            # TODO: Be less frugal
            if "operator=" in func.demangled_name and stmt.args is not None:
                return self._optimize_operator_equal(stmt)
            if "operator+" in func.demangled_name and stmt.args is not None:
                return self._optimize_operator_add(stmt)

        return None

    def _optimize_operator_equal(self, stmt: Call) -> Assignment | None:
        if stmt.args and len(stmt.args) == 2 and isinstance(stmt.args[0], UnaryOp) and stmt.args[0].op == "Reference":
            dst = stmt.args[0].operand
            if isinstance(dst, VirtualVariable):
                self.preserve_vvar_ids.add(dst.varid)
                atom = atoms.VirtualVariable(dst.varid, dst.size, dst.category, dst.oident)
                self.type_hints.append((atom, "std::string"))  # FIXME: Other types of variables?
            type = None
            if stmt.prototype is not None:
                dst_ty = stmt.prototype.returnty
                if isinstance(dst_ty, SimTypeReference):
                    dst_ty = dst_ty.refs
                type = {"dst": dst_ty, "src": stmt.prototype.args[1]}
            return Assignment(stmt.idx, stmt.args[0].operand, stmt.args[1], type=type, **stmt.tags)
        return None

    def _optimize_operator_add(self, stmt: Call) -> Assignment | None:
        if (
            stmt.args
            and len(stmt.args) == 3
            and isinstance(stmt.args[1], UnaryOp)
            and isinstance(stmt.args[1].operand, VirtualVariable)
            and isinstance(stmt.args[2], Const)
            and isinstance(stmt.ret_expr, VirtualVariable)
        ):
            arg2 = Load(None, stmt.args[2], UNDETERMINED_SIZE, Endness.BE, **stmt.tags)
            addition = BinaryOp(None, "Add", [stmt.args[1].operand, arg2], **stmt.tags)
            return Assignment(stmt.idx, stmt.ret_expr, addition, **stmt.tags)
        return None
