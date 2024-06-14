from __future__ import annotations
from typing import Any

from ailment.statement import Statement, Assignment
from ailment.expression import Expression, Register, VirtualVariable, Load, Const

from angr.engines.light import SimEngineLight, SimEngineLightAILMixin
from .rewriting_state import RewritingState


class SimEngineSSARewriting(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    """
    This engine rewrites every block to insert phi variables and replaces every used variable with their versioned
    copies at each use location.
    """

    state: RewritingState

    def __init__(
        self,
        arch,
        sp_tracker=None,
        bp_as_gpr: bool = False,
        def_to_vvid: dict[Any, int] = None,
        udef_to_phiid: dict[tuple, set[int]] = None,
        phiid_to_loc: dict[int, tuple[int, int | None]] = None,
    ):
        super().__init__()

        self.arch = arch
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.def_to_vvid = def_to_vvid
        self.udef_to_phiid = udef_to_phiid
        self.phiid_to_loc = phiid_to_loc

    #
    # Handlers
    #

    def _handle_Stmt(self, stmt: Statement):
        new_stmt = super()._handle_Stmt(stmt)
        if new_stmt is not None:
            self.state.append_statement(new_stmt)
        else:
            self.state.append_statement(stmt)

    def _handle_Assignment(self, stmt: Assignment) -> Assignment | None:
        new_src = self._expr(stmt.src)
        new_dst = self._replace_def_expr(stmt.dst)

        if new_dst is not None:
            if isinstance(stmt.dst, Register):
                # TODO: Support partial registers
                self.state.registers[stmt.dst.reg_offset] = new_dst.varid
            else:
                raise NotImplementedError()

        if new_dst is not None or new_src is not None:
            return Assignment(
                stmt.idx,
                stmt.dst if new_dst is None else new_dst,
                stmt.src if new_src is None else new_src,
                **stmt.tags,
            )
        return None

    def _handle_Register(self, expr: Register) -> VirtualVariable | None:
        new_expr = self._replace_use_reg(expr)
        return new_expr

    def _handle_Load(self, expr: Load) -> Load | None:
        new_addr = self._expr(expr.addr)
        if new_addr is not None:
            return Load(expr.idx, new_addr, expr.size, expr.endness, guard=expr.guard, alt=expr.alt, **expr.tags)
        return None

    def _handle_Const(self, expr: Const) -> None:
        return None

    #
    # Expression replacement
    #

    def _replace_def_expr(self, expr: Expression) -> VirtualVariable | None:
        if isinstance(expr, Register):
            # get the virtual variable ID
            vvid = self.get_vvid_by_def(expr)
            return VirtualVariable(expr.idx, vvid, expr.bits, **expr.tags)
        return None

    def _replace_use_reg(self, reg_expr: Register) -> VirtualVariable | None:
        if reg_expr.reg_offset in self.state.registers:
            vvid = self.state.registers[reg_expr.reg_offset]
            return VirtualVariable(reg_expr.idx, vvid, reg_expr.bits, **reg_expr.tags)
        return None

    #
    # Utils
    #

    def get_vvid_by_def(self, expr: Expression) -> int | None:
        return self.def_to_vvid.get(expr, None)
