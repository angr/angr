from __future__ import annotations
from collections import defaultdict
from typing import Any

from ailment import Expression, Block
from ailment.expression import VirtualVariable, Const, Phi, Tmp, Load, Register, StackBaseOffset
from ailment.statement import Statement, Assignment
from ailment.block_walker import AILBlockWalkerBase

from angr.knowledge_plugins.key_definitions import atoms
from angr.code_location import CodeLocation
from .vvar_uses_collector import VVarUsesCollector
from .tmp_uses_collector import TmpUsesCollector


def get_vvar_deflocs(blocks) -> dict[VirtualVariable, CodeLocation]:
    vvar_to_loc: dict[VirtualVariable, CodeLocation] = {}

    for block in blocks:
        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                vvar_to_loc[stmt.dst] = CodeLocation(block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx)

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


class ConstAndVVarWalker(AILBlockWalkerBase):
    def __init__(self):
        super().__init__()
        self.all_const_and_vvar_expr = True

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, (Tmp, Load, Register)):
            self.all_const_and_vvar_expr = False
            return
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def is_const_and_vvar_assignment(stmt: Statement) -> bool:
    if isinstance(stmt, Assignment):
        walker = ConstAndVVarWalker()
        walker.walk_expression(stmt.src)
        return walker.all_const_and_vvar_expr
    return False


class ConstVVarAndLoadWalker(AILBlockWalkerBase):
    def __init__(self):
        super().__init__()
        self.all_const_vvar_load_expr = True

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, (Tmp, Register)):
            self.all_const_vvar_load_expr = False
            return
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def is_const_vvar_load_assignment(stmt: Statement) -> bool:
    if isinstance(stmt, Assignment):
        walker = ConstVVarAndLoadWalker()
        walker.walk_expression(stmt.src)
        return walker.all_const_vvar_load_expr
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
    "get_tmp_uselocs",
    "get_tmp_deflocs",
)
