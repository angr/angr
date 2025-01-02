from __future__ import annotations
import logging

import pyvex

from .resolver import IndirectJumpResolver

_l = logging.getLogger(name=__name__)


class MemoryLoadResolver(IndirectJumpResolver):
    """
    Resolve an indirect jump that looks like the following::

    .text:
                    call    off_3314A8

    .data:
    off_3314A8      dd offset sub_1E426F

    This indirect jump resolver may not be the best solution for all cases (e.g., when the .data section can be
    intentionally altered by the binary itself).
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return jumpkind in {"Ijk_Boring", "Ijk_Call"}

    def resolve(  # pylint:disable=unused-argument
        self,
        cfg,
        addr: int,
        func_addr: int,
        block: pyvex.IRSB,
        jumpkind: str,
        func_graph_complete: bool = True,
        **kwargs,
    ):
        """
        :param cfg:         CFG with specified function
        :param addr:        Address of indirect jump
        :param func_addr:   Address of function of indirect jump
        :param block:       Block of indirect jump (Block object)
        :param jumpkind:    VEX jumpkind (Ijk_Boring or Ijk_Call)
        :return:            Bool tuple with replacement address
        """
        vex_block = block
        if isinstance(vex_block.next, pyvex.expr.RdTmp):
            tmp_stmt_idx, tmp_ins_addr = self._find_tmp_write_stmt_and_ins(vex_block, vex_block.next.tmp)
            if tmp_stmt_idx is None or tmp_ins_addr is None:
                return False, []

            stmt = vex_block.statements[tmp_stmt_idx]
            assert isinstance(stmt, pyvex.IRStmt.WrTmp)
            if (
                isinstance(stmt.data, pyvex.IRExpr.Load)
                and isinstance(stmt.data.addr, pyvex.IRExpr.Const)
                and stmt.data.result_size(vex_block.tyenv) == self.project.arch.bits
            ):
                load_addr = stmt.data.addr.con.value
                try:
                    value = self.project.loader.memory.unpack_word(load_addr, size=self.project.arch.bytes)
                    if isinstance(value, int) and self._is_target_valid(cfg, value):
                        return True, [value]
                except KeyError:
                    return False, []

        return False, []

    @staticmethod
    def _find_tmp_write_stmt_and_ins(vex_block, tmp: int) -> tuple[int | None, int | None]:
        stmt_idx = None
        for idx, stmt in enumerate(reversed(vex_block.statements)):
            if isinstance(stmt, pyvex.IRStmt.IMark) and stmt_idx is not None:
                ins_addr = stmt.addr + stmt.delta
                return stmt_idx, ins_addr
            if isinstance(stmt, pyvex.IRStmt.WrTmp) and stmt.tmp == tmp:
                stmt_idx = len(vex_block.statements) - idx - 1
        return None, None
