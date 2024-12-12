# pylint:disable=no-self-use,unused-argument
from __future__ import annotations

from angr.engines.light import SimEngineNostmtVEX


class IRSBRegisterCollector(SimEngineNostmtVEX[None, None, None]):
    """
    Scan the VEX IRSB to collect all registers that are read.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.reg_reads: set[tuple[int, int]] = set()

    def _top(self, bits):
        return None

    def _is_top(self, expr):
        return True

    def _handle_expr_Get(self, expr):
        self.reg_reads.add((expr.offset, expr.result_size(self.tyenv)))

    def _handle_stmt_WrTmp(self, stmt):
        self._expr(stmt.data)

    def _handle_conversion(self, from_size, to_size, signed, operand):
        return None

    def _process_block_end(self, stmt_result, whitelist):
        return None

    def _handle_expr_VECRET(self, expr):
        return None

    def _handle_expr_GSPTR(self, expr):
        return None

    def _handle_expr_RdTmp(self, expr):
        return None

    def _handle_expr_GetI(self, expr):
        return None

    def _handle_expr_Load(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_Const(self, expr):
        return None
