from __future__ import annotations
from collections import defaultdict
from typing import Any

import archinfo
from ailment import Expression, Block
from ailment.expression import VirtualVariable, Const, Phi, Tmp, Load, Register, StackBaseOffset, DirtyExpression
from ailment.statement import Statement, Assignment, Call
from ailment.block_walker import AILBlockWalkerBase

from angr.knowledge_plugins.key_definitions import atoms
from angr.code_location import CodeLocation
from .vvar_uses_collector import VVarUsesCollector
from .tmp_uses_collector import TmpUsesCollector


def get_reg_offset_base_and_size(
    reg_offset: int, arch: archinfo.Arch, size: int | None = None, resilient: bool = True
) -> tuple[int, int] | None:
    """
    Translate a given register offset into the offset of its full register and obtain the size of the full register.

    :param reg_offset:  The offset of the register to translate.
    :param arch:        The corresponding Arch object.
    :param size:        Size of the register to translate. Optional.
    :param resilient:   When set to True, this function will return the provided offset and size for registers that the
                        arch does not know about.
    :return:            A tuple of translated offset and the size of the full register.
    """

    base_reg_and_size = arch.get_base_register(reg_offset, size=size)
    if resilient and base_reg_and_size is None:
        return reg_offset, size
    return base_reg_and_size


def get_reg_offset_base(
    reg_offset: int, arch: archinfo.Arch, size: int | None = None, resilient: bool = True
) -> int | None:
    """
    Translate a given register offset into the offset of its full register.

    :param reg_offset:  The offset of the register to translate.
    :param arch:        The corresponding Arch object.
    :param size:        Size of the register to translate. Optional.
    :param resilient:   When set to True, this function will return the provided offset and size for registers that the
                        arch does not know about.
    :return:            The translated offset of the full register.
    """

    base_reg_and_size = arch.get_base_register(reg_offset, size=size)
    if base_reg_and_size is None:
        return reg_offset if resilient else None
    return base_reg_and_size[0]


def get_vvar_deflocs(
    blocks, phi_vvars: dict[VirtualVariable, set[VirtualVariable]] | None = None
) -> dict[VirtualVariable, CodeLocation]:
    vvar_to_loc: dict[VirtualVariable, CodeLocation] = {}

    for block in blocks:
        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                vvar_to_loc[stmt.dst] = CodeLocation(block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx)
                if phi_vvars is not None and isinstance(stmt.src, Phi):
                    phi_vvars[stmt.dst] = {vvar_ for src, vvar_ in stmt.src.src_and_vvars}
            elif isinstance(stmt, Call):
                if isinstance(stmt.ret_expr, VirtualVariable):
                    vvar_to_loc[stmt.ret_expr] = CodeLocation(
                        block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx
                    )
                if isinstance(stmt.fp_ret_expr, VirtualVariable):
                    vvar_to_loc[stmt.fp_ret_expr] = CodeLocation(
                        block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx
                    )

    return vvar_to_loc


def get_vvar_uselocs(blocks) -> dict[int, set[tuple[VirtualVariable, CodeLocation]]]:
    vvar_to_loc: dict[int, set[tuple[VirtualVariable, CodeLocation]]] = defaultdict(set)

    for block in blocks:
        collector = VVarUsesCollector()
        collector.walk(block)
        for vvar_idx, vvar_and_uselocs in collector.vvar_and_uselocs.items():
            if vvar_idx not in vvar_to_loc:
                vvar_to_loc[vvar_idx] = vvar_and_uselocs
            else:
                vvar_to_loc[vvar_idx] |= vvar_and_uselocs

    return vvar_to_loc


def get_tmp_deflocs(blocks) -> dict[CodeLocation, dict[atoms.Tmp, int]]:
    tmp_to_loc: dict[CodeLocation, dict[atoms.Tmp, int]] = defaultdict(dict)

    for block in blocks:
        codeloc = CodeLocation(block.addr, None, block_idx=block.idx)
        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp):
                tmp_to_loc[codeloc][atoms.Tmp(stmt.dst.tmp_idx, stmt.dst.bits)] = stmt_idx

    return tmp_to_loc


def get_tmp_uselocs(blocks) -> dict[CodeLocation, dict[atoms.Tmp, set[tuple[Tmp, int]]]]:
    tmp_to_loc: dict[CodeLocation, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)

    for block in blocks:
        collector = TmpUsesCollector()
        collector.walk(block)
        block_loc = CodeLocation(block.addr, None, block_idx=block.idx)
        for (tmp_idx, tmp_bits), tmp_and_stmtids in collector.tmp_and_uselocs.items():
            if tmp_idx not in tmp_to_loc[block_loc]:
                tmp_to_loc[block_loc][atoms.Tmp(tmp_idx, tmp_bits)] = tmp_and_stmtids
            else:
                tmp_to_loc[block_loc][atoms.Tmp(tmp_idx, tmp_bits)] |= tmp_and_stmtids

    return tmp_to_loc


def is_const_assignment(stmt: Statement) -> tuple[bool, Const | None]:
    if isinstance(stmt, Assignment) and isinstance(stmt.src, (Const, StackBaseOffset)):
        return True, stmt.src
    return False, None


class AILBlacklistExprTypeWalker(AILBlockWalkerBase):
    """
    Walks an AIL expression or statement and determines if it does not contain certain types of expressions.
    """

    def __init__(self, blacklist_expr_types: tuple[type, ...]):
        super().__init__()
        self.blacklist_expr_types = blacklist_expr_types
        self.has_blacklisted_exprs = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, self.blacklist_expr_types):
            self.has_blacklisted_exprs = True
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def is_const_and_vvar_assignment(stmt: Statement) -> bool:
    if isinstance(stmt, Assignment):
        walker = AILBlacklistExprTypeWalker((Tmp, Load, Register, Phi, Call, DirtyExpression))
        walker.walk_expression(stmt.src)
        return not walker.has_blacklisted_exprs
    return False


def is_const_vvar_tmp_assignment(stmt: Statement) -> bool:
    if isinstance(stmt, Assignment):
        walker = AILBlacklistExprTypeWalker((Load, Register, Phi, Call, DirtyExpression))
        walker.walk_expression(stmt.src)
        return not walker.has_blacklisted_exprs
    return False


def is_const_vvar_load_assignment(stmt: Statement) -> bool:
    if isinstance(stmt, Assignment):
        walker = AILBlacklistExprTypeWalker((Tmp, Register, Phi, Call, DirtyExpression))
        walker.walk_expression(stmt.src)
        return not walker.has_blacklisted_exprs
    return False


def is_const_vvar_load_dirty_assignment(stmt: Statement) -> bool:
    if isinstance(stmt, Assignment):
        walker = AILBlacklistExprTypeWalker((Tmp, Register, Phi, Call))
        walker.walk_expression(stmt.src)
        return not walker.has_blacklisted_exprs
    return False


def is_phi_assignment(stmt: Statement) -> tuple[bool, Phi | None]:
    if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
        return True, stmt.src
    return False, None


__all__ = (
    "VVarUsesCollector",
    "get_vvar_deflocs",
    "get_vvar_uselocs",
    "is_const_assignment",
    "is_phi_assignment",
    "is_const_and_vvar_assignment",
    "is_const_vvar_load_assignment",
    "is_const_vvar_load_dirty_assignment",
    "get_tmp_uselocs",
    "get_tmp_deflocs",
)
