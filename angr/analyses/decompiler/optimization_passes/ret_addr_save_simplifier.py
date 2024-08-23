from __future__ import annotations
from typing import Any
import logging

import ailment

from ....calling_conventions import SimRegArg, default_cc, DEFAULT_CC
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class RetAddrSaveSimplifier(OptimizationPass):
    """
    Removes code in function prologues and epilogues for saving and restoring return address registers (ra, lr, etc.),
    generally seen in non-leaf functions.
    """

    ARCHES = ["MIPS32", "MIPS64"]
    PLATFORMS = ["linux"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify return address storage"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        if self.project.arch.name not in DEFAULT_CC:
            return False, {}

        cc = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )(self.project.arch)
        if not isinstance(cc.return_addr, SimRegArg):
            return False, {}

        save_stmt = self._find_retaddr_save_stmt()

        # Note that restoring statements may not exist since they can be effectively removed by other optimization
        restore_stmts = self._find_retaddr_restore_stmt()

        if save_stmt is None:
            return False, {}

        save_dst = save_stmt[2]
        if restore_stmts is not None:
            restore_srcs = [tpl[2] for tpl in restore_stmts]

            if all(src == save_dst for src in restore_srcs):
                return True, {
                    "save_stmt": save_stmt,
                    "restore_stmts": restore_stmts,
                }

        return True, {
            "save_stmt": save_stmt,
            "restore_stmts": [],
        }

    def _analyze(self, cache=None):
        save_stmt = None
        restore_stmts = None

        if cache is not None:
            save_stmt = cache.get("save_stmt", None)
            restore_stmts = cache.get("restore_stmts", None)

        if save_stmt is None:
            save_stmt = self._find_retaddr_save_stmt()
        if restore_stmts is None:
            restore_stmts = self._find_retaddr_restore_stmt()

        if save_stmt is None:
            return

        # update the first block
        block, stmt_idx, _ = save_stmt
        block_copy = block.copy()
        block_copy.statements.pop(stmt_idx)
        self._update_block(block, block_copy)

        # update all endpoint blocks
        if restore_stmts:
            for block, stmt_idx, _ in restore_stmts:
                block_copy = block.copy()
                block_copy.statements.pop(stmt_idx)
                self._update_block(block, block_copy)

    def _find_retaddr_save_stmt(self) -> tuple[Any, int, ailment.Expr.StackBaseOffset] | None:
        """
        Find the AIL statement that saves the return address to a stack slot.

        :return:    A tuple of (block_addr, statement_idx, save_dst) or None if not found.
        """

        first_block = self._get_block(self._func.addr)
        if first_block is None:
            return None

        cc = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )(self.project.arch)
        retaddr = cc.return_addr
        assert isinstance(retaddr, SimRegArg)
        retaddr_reg = self.project.arch.registers[retaddr.reg_name][0]

        for idx, stmt in enumerate(first_block.statements):
            if (
                isinstance(stmt, ailment.Stmt.Store)
                and isinstance(stmt.addr, ailment.Expr.StackBaseOffset)
                and isinstance(stmt.data, ailment.Expr.Register)
                and stmt.data.reg_offset == retaddr_reg
                and stmt.addr.offset < 0
            ):
                return first_block, idx, stmt.addr
            if (
                isinstance(stmt, ailment.Stmt.Store)
                and isinstance(stmt.addr, ailment.Expr.StackBaseOffset)
                and isinstance(stmt.data, ailment.Expr.StackBaseOffset)
                and stmt.data.offset == 0
                and stmt.addr.offset < 0
            ):
                return first_block, idx, stmt.addr

        # Not found
        return None

    def _find_retaddr_restore_stmt(self) -> list[tuple[Any, int, ailment.Expr.StackBaseOffset]] | None:
        """
        Find the AIL statement that restores the return address from a stack slot.

        :return:    A list of tuples, where each tuple is like (block_addr, statement_idx, load_src), or None if not
                    found.
        """

        endpoints = self._func.endpoints
        callouts_and_jumpouts = {n.addr for n in self._func.callout_sites + self._func.jumpout_sites}

        retaddr_restore_stmts = []

        cc = default_cc(
            self.project.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )(self.project.arch)
        retaddr = cc.return_addr
        assert isinstance(retaddr, SimRegArg)
        retaddr_reg = self.project.arch.registers[retaddr.reg_name][0]

        for endpoint in endpoints:
            for endpoint_block in self._get_blocks(endpoint.addr):
                for idx, stmt in enumerate(endpoint_block.statements):
                    if (
                        isinstance(stmt, ailment.Stmt.Assignment)
                        and isinstance(stmt.dst, ailment.Expr.Register)
                        and stmt.dst.reg_offset == retaddr_reg
                        and isinstance(stmt.src, ailment.Expr.Load)
                        and isinstance(stmt.src.addr, ailment.Expr.StackBaseOffset)
                    ):
                        retaddr_restore_stmts.append((endpoint_block, idx, stmt.src.addr))
                        break
                else:
                    if endpoint.addr not in callouts_and_jumpouts:
                        _l.debug("Could not find retaddr restoring statement in function %#x.", endpoint.addr)
                        return None
                    _l.debug(
                        "No retaddr restoring statement is found at callout/jumpout site %#x. Might be expected.",
                        endpoint.addr,
                    )

        return retaddr_restore_stmts
