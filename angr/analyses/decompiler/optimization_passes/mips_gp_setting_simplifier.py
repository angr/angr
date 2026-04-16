from __future__ import annotations

import logging

from angr import ailment
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class MipsGpSettingSimplifier(OptimizationPass):
    """
    Removes $gp-setting statements at the beginning of MIPS functions.
    """

    ARCHES = ["MIPS32", "MIPS64"]
    PLATFORMS = ["linux"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove MIPS $gp-setting statements"
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        gp_stmt = self._find_gp_setting_stmt()
        if gp_stmt is None:
            return False, {}
        return True, {"gp_stmt": gp_stmt}

    def _analyze(self, cache=None):
        gp_stmt = None
        if cache is not None:
            gp_stmt = cache.get("gp_stmt", None)
        if gp_stmt is None:
            gp_stmt = self._find_gp_setting_stmt()
        if gp_stmt is None:
            return

        block, stmt_idx = gp_stmt
        block_copy = block.copy()
        block_copy.statements.pop(stmt_idx)
        self._update_block(block, block_copy)

    def _find_gp_setting_stmt(self) -> tuple[ailment.Block, int] | None:
        """
        Find the AIL statement that sets the $gp value in the entry block.

        Two patterns are recognized:

        1. Fully constant-propagated: the source is a Const equal to the function's known GP value.
           ``vvar{stack} = Const(gp_value)``

        2. PIC-style computation: the source is a BinaryOp adding/subtracting a constant offset
           to/from the t9 register (which holds the function address on entry in PIC MIPS code).
           ``vvar{stack} = Add(Const(offset), vvar{t9})``

        :return:    A tuple of (block, statement_idx) or None if not found.
        """
        gp_value = self._func.info.get("gp")
        if gp_value is None:
            return None

        first_block = self._get_block(self._func.addr)
        if first_block is None:
            return None

        t9_offset = self.project.arch.registers["t9"][0]

        for idx, stmt in enumerate(first_block.statements):
            if not (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.was_stack
            ):
                continue

            src = stmt.src

            # Pattern 1: direct constant assignment
            if isinstance(src, ailment.Expr.Const) and src.value == gp_value:
                return first_block, idx

            # Pattern 2: t9 + offset (PIC-style GP computation)
            if isinstance(src, ailment.Expr.BinaryOp) and src.op == "Add" and len(src.operands) == 2:
                op0, op1 = src.operands
                # Either order: Const + VVar{t9} or VVar{t9} + Const
                const_op = None
                vvar_op = None
                for op in (op0, op1):
                    if isinstance(op, ailment.Expr.Const):
                        const_op = op
                    elif isinstance(op, ailment.Expr.VirtualVariable) and op.was_reg and op.reg_offset == t9_offset:
                        vvar_op = op
                if const_op is not None and vvar_op is not None and self._func.addr + const_op.value == gp_value:
                    # Verify the offset matches: func_addr + offset == gp_value
                    return first_block, idx

        return None
