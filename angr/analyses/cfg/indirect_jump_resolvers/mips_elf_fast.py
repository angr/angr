# pylint:disable=too-many-boolean-expressions,global-statement,too-many-positional-arguments
from __future__ import annotations
from typing import TYPE_CHECKING
import logging
from enum import Enum

import archinfo
import pyvex


from angr.blade import Blade
from angr.utils.constants import DEFAULT_STATEMENT
from .resolver import IndirectJumpResolver

if TYPE_CHECKING:
    from angr.block import Block


l = logging.getLogger(name=__name__)

PROFILING = False
HITS_CASE_1, HITS_CASE_2, MISSES = 0, 0, 0


def enable_profiling():
    global PROFILING, HITS_CASE_1, HITS_CASE_2, MISSES

    PROFILING = True
    HITS_CASE_1 = 0
    HITS_CASE_2 = 0
    MISSES = 0


def disable_profiling():
    global PROFILING
    PROFILING = False


class Case2Result(Enum):
    """
    Describes the result of resolving case 2 function calls.
    """

    SUCCESS = 0
    FAILURE = 1
    RESUME = 2


class MipsElfFastResolver(IndirectJumpResolver):
    """
    A timeless indirect jump resolver for R9-based indirect function calls in MIPS ELFs.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return isinstance(self.project.arch, (archinfo.ArchMIPS32, archinfo.ArchMIPS64))

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):
        """
        Wrapper for _resolve that slowly increments the max_depth used by Blade for finding sources
        until we can resolve the addr or we reach the default max_depth

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :param str jumpkind: The jumpkind.
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """
        global MISSES

        resolved, resolved_targets = self._resolve(cfg, addr, func_addr, block, jumpkind, max_level=2)
        if resolved:
            return resolved, resolved_targets

        if PROFILING:
            MISSES += 1
        return False, []

    def _resolve(self, cfg, addr, func_addr, block, jumpkind, max_level):  # pylint:disable=unused-argument
        """
        Resolves the indirect jump in MIPS ELF binaries where all external function calls are indexed using gp.

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :param str jumpkind: The jumpkind.
        :param int max_level: maximum level for Blade to resolve when looking for sources
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """

        global HITS_CASE_1, HITS_CASE_2

        func = cfg.kb.functions.function(addr=func_addr)
        b = Blade(
            cfg.graph,
            addr,
            -1,
            cfg=cfg,
            project=self.project,
            ignore_sp=True,
            ignore_bp=True,
            ignored_regs=("gp",),
            cross_insn_opt=False,
            stop_at_calls=True,
            max_level=max_level,
            include_imarks=False,
        )

        gp_value = func.info.get("gp", None)

        # see if gp is used on this slice at all
        gp_used = self._is_gp_used_on_slice(self.project, b)
        if gp_used and gp_value is None:
            # this might a special case: gp is only used once in this function, and it can be initialized right
            # before its use site.
            # however, it should have been determined in CFGFast
            # cannot determine the value of gp. quit
            l.warning("Failed to determine value of register gp for function %#x.", func.addr)
            return False, []

        # we support two cases:
        # Case 1. t9 is set in the current block, and jalr $t9 at the end of the same block.
        # Case 2. t9 is set in both predecessor blocks, and jalr $t9 at the end of the current block.

        block_addrs = {block_addr for block_addr, _ in b.slice}
        if len(block_addrs) == 2 and addr in block_addrs:
            first_block_addr = next(iter(block_addrs - {addr}))
            r, target = self._resolve_case_2(first_block_addr, block, func_addr, gp_value, cfg)
            if r == Case2Result.SUCCESS:
                if PROFILING:
                    HITS_CASE_2 += 1
                return True, [target]
            if r == Case2Result.FAILURE:
                return False, []
            # otherwise, we need to resume the analysis

        target = self._resolve_case_1(addr, block, func_addr, gp_value, cfg)
        if target is not None:
            if PROFILING:
                HITS_CASE_1 += 1
            return True, [target]

        # no luck
        return False, []

    def _resolve_case_1(self, addr: int, block: pyvex.IRSB, func_addr: int, gp_value: int, cfg) -> int | None:
        # lift the block again with the correct setting

        inital_regs = [(self.project.arch.registers["t9"][0], self.project.arch.registers["t9"][1], func_addr)]
        if gp_value is not None:
            inital_regs.append((self.project.arch.registers["gp"][0], self.project.arch.registers["gp"][1], gp_value))

        first_irsb = self.project.factory.block(
            addr,
            size=block.size,
            collect_data_refs=False,
            const_prop=True,
            cross_insn_opt=False,
            load_from_ro_regions=True,
            initial_regs=inital_regs,
        ).vex_nostmt

        if not isinstance(first_irsb.next, pyvex.IRExpr.RdTmp):
            return None
        target_tmp = first_irsb.next.tmp
        if first_irsb.const_vals is None:
            return None

        # find the value of the next tmp
        for cv in first_irsb.const_vals:
            if cv.tmp == target_tmp:
                target = cv.value
                if self._is_target_valid(cfg, target):
                    return target
                break

        return None

    def _resolve_case_2(
        self, first_block_addr: int, second_block: pyvex.IRSB, func_addr: int, gp_value: int, cfg
    ) -> tuple[Case2Result, int | None]:
        jump_target_reg = self._get_jump_target_reg(second_block)
        if jump_target_reg is None:
            return Case2Result.FAILURE, None
        last_reg_setting_tmp = self._get_last_reg_setting_tmp(second_block, jump_target_reg)
        if last_reg_setting_tmp is not None:
            # the register (t9) is set in this block - we can resolve the jump target using only the current block
            return Case2Result.RESUME, None

        inital_regs = [(self.project.arch.registers["t9"][0], self.project.arch.registers["t9"][1], func_addr)]
        if gp_value is not None:
            inital_regs.append((self.project.arch.registers["gp"][0], self.project.arch.registers["gp"][1], gp_value))

        # lift the first block again with the correct setting
        first_irsb = self.project.factory.block(
            first_block_addr,
            cross_insn_opt=False,
            collect_data_refs=False,
            const_prop=True,
            load_from_ro_regions=True,
            initial_regs=inital_regs,
        ).vex_nostmt

        last_reg_setting_tmp = self._get_last_reg_setting_tmp(first_irsb, jump_target_reg)
        if last_reg_setting_tmp is None:
            return Case2Result.FAILURE, None

        # find the value of the next tmp
        if first_irsb.const_vals is None:
            return Case2Result.FAILURE, None
        for cv in first_irsb.const_vals:
            if cv.tmp == last_reg_setting_tmp:
                target = cv.value
                if self._is_target_valid(cfg, target):
                    return Case2Result.SUCCESS, target
                break

        return Case2Result.FAILURE, None

    @staticmethod
    def _get_jump_target_reg(block: pyvex.IRSB) -> int | None:
        if block.jumpkind != "Ijk_Call":
            return None
        if not isinstance(block.next, pyvex.IRExpr.RdTmp):
            return None
        next_tmp = block.next.tmp

        for stmt in reversed(block.statements):
            if (
                isinstance(stmt, pyvex.IRStmt.Put)
                and isinstance(stmt.data, pyvex.IRExpr.RdTmp)
                and stmt.data.tmp == next_tmp
            ):
                return stmt.offset
            if (
                isinstance(stmt, pyvex.IRStmt.WrTmp)
                and stmt.tmp == next_tmp
                and isinstance(stmt.data, pyvex.IRExpr.Get)
            ):
                return stmt.data.offset

        return None

    @staticmethod
    def _get_last_reg_setting_tmp(block: pyvex.IRSB, target_reg: int) -> int | None:
        for stmt in reversed(block.statements):
            if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == target_reg:
                if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    return stmt.data.tmp
                return None

        return None

    @staticmethod
    def _is_gp_used_on_slice(project, b: Blade) -> bool:
        gp_offset = project.arch.registers["gp"][0]
        blocks_on_slice: dict[int, Block] = {}
        for block_addr, block_stmt_idx in b.slice.nodes():
            if block_addr not in blocks_on_slice:
                blocks_on_slice[block_addr] = project.factory.block(block_addr, cross_insn_opt=False)
            block = blocks_on_slice[block_addr]
            if block_stmt_idx == DEFAULT_STATEMENT:
                if isinstance(block.vex.next, pyvex.IRExpr.Get) and block.vex.next.offset == gp_offset:
                    gp_used = True
                    break
            else:
                stmt = block.vex.statements[block_stmt_idx]
                if (
                    isinstance(stmt, pyvex.IRStmt.WrTmp)
                    and isinstance(stmt.data, pyvex.IRExpr.Get)
                    and stmt.data.offset == gp_offset
                ):
                    gp_used = True
                    break
        else:
            gp_used = False

        return gp_used
