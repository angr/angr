# pylint:disable=arguments-differ,too-many-boolean-expressions,no-self-use
from __future__ import annotations

from archinfo import Endness

from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import BinaryOp, Call, Const, Load, UnaryOp, VirtualVariable
from angr.ailment.statement import SideEffectStatement, WeakAssignment
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.knowledge_plugins.key_definitions import atoms
from angr.sim_type import SimCppClass, SimTypeReference

from .base import PeepholeOptimizationStmtBase


class RewriteCxxOperatorCalls(PeepholeOptimizationStmtBase):
    """
    Rewrite C++ operator function calls into operations.
    """

    __slots__ = ()

    NAME = "Rewrite C++ operator function calls into operations"
    stmt_classes = (SideEffectStatement, WeakAssignment)

    def optimize(self, stmt: SideEffectStatement | WeakAssignment, block=None, **kwargs):  # type: ignore
        assert self.project is not None

        if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
            call_expr = stmt.expr
        elif isinstance(stmt, WeakAssignment) and isinstance(stmt.src, Call):
            call_expr = stmt.src
        else:
            return None

        # are we calling a function that we deem as an overridden operator function?
        if isinstance(call_expr.target, Const):
            func_addr = call_expr.target.value
            if not self.project.kb.functions.contains_addr(func_addr):
                return None
            func = self.project.kb.functions[func_addr]
            if (
                "operator=" in func.demangled_name
                and isinstance(stmt, SideEffectStatement)
                and call_expr.args is not None
            ):
                return self._optimize_operator_equal(stmt)
            if "operator+" in func.demangled_name and call_expr.args is not None:
                if isinstance(stmt, SideEffectStatement):
                    return self._optimize_operator_add_call(stmt)
                assert isinstance(stmt, WeakAssignment)
                return self._optimize_operator_add_assignment(stmt)
            # TODO: Support other types of C++ operator functions

        return None

    def _optimize_operator_equal(self, stmt: SideEffectStatement) -> WeakAssignment | None:
        if (
            stmt.expr.args
            and len(stmt.expr.args) == 2
            and isinstance(stmt.expr.args[0], UnaryOp)
            and stmt.expr.args[0].op == "Reference"
        ):
            prototype = variable_map_of(self.manager).prototype(stmt.expr)
            dst = stmt.expr.args[0].operand
            if isinstance(dst, VirtualVariable):
                self.preserve_vvar_ids.add(dst.varid)
                atom = atoms.VirtualVariable(dst.varid, dst.size, dst.category, dst.oident)
                if prototype is not None and isinstance(prototype.returnty, SimTypeReference):
                    type_hint = self._type_hint_from_typeref(prototype.returnty)
                    if type_hint is not None:
                        self.type_hints.append((atom, type_hint))
            arg1 = (
                Load(self.manager.next_atom(), stmt.expr.args[1], UNDETERMINED_SIZE, Endness.BE, **stmt.tags)
                if isinstance(stmt.expr.args[1], Const)
                else stmt.expr.args[1]
            )
            type_ = None
            if prototype is not None:
                dst_ty = prototype.returnty
                if isinstance(dst_ty, SimTypeReference):
                    dst_ty = dst_ty.refs
                type_ = {"dst": dst_ty, "src": prototype.args[1]}
            return WeakAssignment(stmt.idx, stmt.expr.args[0].operand, arg1, type=type_, **stmt.tags)  # type: ignore
        return None

    def _optimize_operator_add_call(self, stmt: SideEffectStatement) -> WeakAssignment | None:
        if (
            isinstance(stmt.expr, Call)
            and stmt.expr.args
            and len(stmt.expr.args) == 3
            and isinstance(stmt.expr.args[1], UnaryOp)
            and stmt.expr.args[1].op == "Reference"
            and isinstance(stmt.expr.args[1].operand, VirtualVariable)
            and isinstance(stmt.expr.args[2], Const)
            and isinstance(stmt.ret_expr, VirtualVariable)
        ):
            arg2 = Load(self.manager.next_atom(), stmt.expr.args[2], UNDETERMINED_SIZE, Endness.BE, **stmt.tags)
            addition = BinaryOp(self.manager.next_atom(), "Add", [stmt.expr.args[1].operand, arg2], **stmt.tags)
            type_ = None
            prototype = variable_map_of(self.manager).prototype(stmt.expr)
            if prototype is not None:
                dst_ty = prototype.returnty
                if isinstance(dst_ty, SimTypeReference):
                    dst_ty = dst_ty.refs
                type_ = {"dst": dst_ty, "src": prototype.args[1]}
            return WeakAssignment(stmt.idx, stmt.ret_expr, addition, type=type_, **stmt.tags)
        return None

    def _optimize_operator_add_assignment(self, stmt: WeakAssignment) -> WeakAssignment | None:
        if (
            isinstance(stmt.src, Call)
            and stmt.src.args
            and len(stmt.src.args) == 3
            and isinstance(stmt.src.args[1], UnaryOp)
            and stmt.src.args[1].op == "Reference"
            and isinstance(stmt.src.args[1].operand, VirtualVariable)
            and isinstance(stmt.src.args[2], Const)
            and isinstance(stmt.dst, VirtualVariable)
        ):
            arg2 = Load(self.manager.next_atom(), stmt.src.args[2], UNDETERMINED_SIZE, Endness.BE, **stmt.tags)
            addition = BinaryOp(self.manager.next_atom(), "Add", [stmt.src.args[1].operand, arg2], **stmt.tags)
            type_ = None
            prototype = variable_map_of(self.manager).prototype(stmt.src)
            if prototype is not None:
                dst_ty = prototype.returnty
                if isinstance(dst_ty, SimTypeReference):
                    dst_ty = dst_ty.refs
                type_ = {"dst": dst_ty, "src": prototype.args[1]}
            stmt_tags = stmt.tags.copy()
            stmt_tags["type"] = type_
            return WeakAssignment(stmt.idx, stmt.dst, addition, **stmt_tags)
        return None

    @staticmethod
    def _type_hint_from_typeref(typeref: SimTypeReference) -> str | None:
        if isinstance(typeref.refs, SimCppClass) and typeref.refs.unique_name:
            return typeref.refs.unique_name
        return None
