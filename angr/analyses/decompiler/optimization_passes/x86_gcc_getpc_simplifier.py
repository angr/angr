from __future__ import annotations
from typing import Any
import logging

import ailment

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class X86GccGetPcSimplifier(OptimizationPass):
    """
    Simplifies __x86.get_pc_thunk calls.
    """

    ARCHES = ["X86"]
    PLATFORMS = ["linux"]
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Simplify getpc()"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        getpc_calls = self._find_getpc_calls()

        return bool(getpc_calls), {
            "getpc_calls": getpc_calls,
        }

    def _analyze(self, cache=None):
        getpc_calls = None

        if cache is not None:
            getpc_calls = cache.get("getpc_calls", None)

        if getpc_calls is None:
            getpc_calls = self._find_getpc_calls()

        if not getpc_calls:
            return

        # update each block
        for block_key, stmt_idx, getpc_reg, getpc_reg_value in getpc_calls:
            pcreg_offset = self.project.arch.registers[getpc_reg][0]

            old_block = self.blocks_by_addr_and_idx[block_key]
            block = old_block.copy()
            old_stmt = block.statements[stmt_idx]
            block.statements[stmt_idx] = ailment.Stmt.Assignment(
                old_stmt.idx,
                ailment.Expr.Register(None, None, pcreg_offset, 32, reg_name=getpc_reg),
                ailment.Expr.Const(None, None, getpc_reg_value, 32),
                **old_stmt.tags,
            )
            # remove the statement that pushes return address onto the stack
            if stmt_idx > 0 and isinstance(block.statements[stmt_idx - 1], ailment.Stmt.Store):
                block.statements = block.statements[: stmt_idx - 1] + block.statements[stmt_idx:]
            self._update_block(old_block, block)

    def _find_getpc_calls(self) -> list[tuple[Any, int, str, int]]:
        """
        Find all blocks that are calling __x86.get_pc_thunk functions.

        :return:    A list of tuples. Each tuple is in the form of (block_key, statement ID, pc-storing register,
                    value of the pc-storing register).
        """

        results = []
        for key, block in self._blocks_by_addr_and_idx.items():
            if (
                block.statements
                and isinstance(block.statements[-1], ailment.Stmt.Call)
                and isinstance(block.statements[-1].target, ailment.Expr.Const)
            ):
                call_func_addr = block.statements[-1].target.value
                try:
                    call_func = self.kb.functions.get_by_addr(call_func_addr)
                except KeyError:
                    continue
                if "get_pc" in call_func.info:
                    results.append(
                        (key, len(block.statements) - 1, call_func.info["get_pc"], block.addr + block.original_size),
                    )
        return results
