from __future__ import annotations
from collections import defaultdict
from collections.abc import Callable
from typing import Any, Literal, overload

import networkx

import archinfo
from angr.ailment import Expression, Block
from angr.ailment.expression import (
    VirtualVariable,
    Const,
    Phi,
    Tmp,
    Load,
    Register,
    StackBaseOffset,
    DirtyExpression,
    ITE,
)
from angr.ailment.statement import Statement, Assignment, Call, Store, CAS
from angr.ailment.block_walker import AILBlockWalkerBase

from angr.knowledge_plugins.key_definitions import atoms
from angr.code_location import CodeLocation
from .vvar_uses_collector import VVarUsesCollector
from .tmp_uses_collector import TmpUsesCollector


DEPHI_VVAR_REG_OFFSET = 4096


@overload
def get_reg_offset_base_and_size(
    reg_offset: int, arch: archinfo.Arch, size: int | None = None, resilient: Literal[True] = True
) -> tuple[int, int]: ...
@overload
def get_reg_offset_base_and_size(
    reg_offset: int, arch: archinfo.Arch, size: int | None = None, resilient: Literal[False] = False
) -> tuple[int, int] | None: ...


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


@overload
def get_reg_offset_base(
    reg_offset: int, arch: archinfo.Arch, size: int | None = None, resilient: Literal[True] = True
) -> int: ...
@overload
def get_reg_offset_base(
    reg_offset: int, arch: archinfo.Arch, size: int | None = None, resilient: Literal[False] = False
) -> int | None: ...


def get_reg_offset_base(reg_offset, arch, size=None, resilient=True):
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
    blocks, phi_vvars: dict[int, set[int]] | None = None
) -> dict[int, tuple[VirtualVariable, CodeLocation]]:
    vvar_to_loc: dict[int, tuple[VirtualVariable, CodeLocation]] = {}
    for block in blocks:
        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                vvar_to_loc[stmt.dst.varid] = stmt.dst, CodeLocation(
                    block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx
                )
                if phi_vvars is not None and isinstance(stmt.src, Phi):
                    phi_vvars[stmt.dst.varid] = {
                        vvar_.varid for src, vvar_ in stmt.src.src_and_vvars if vvar_ is not None
                    }
            elif isinstance(stmt, Call):
                if isinstance(stmt.ret_expr, VirtualVariable):
                    vvar_to_loc[stmt.ret_expr.varid] = stmt.ret_expr, CodeLocation(
                        block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx
                    )
                if isinstance(stmt.fp_ret_expr, VirtualVariable):
                    vvar_to_loc[stmt.fp_ret_expr.varid] = stmt.fp_ret_expr, CodeLocation(
                        block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx
                    )

    return vvar_to_loc


def get_vvar_uselocs(blocks) -> dict[int, list[tuple[VirtualVariable, CodeLocation]]]:
    vvar_to_loc: dict[int, list[tuple[VirtualVariable, CodeLocation]]] = defaultdict(list)
    for block in blocks:
        collector = VVarUsesCollector()
        collector.walk(block)
        for vvar_idx, vvar_and_uselocs in collector.vvar_and_uselocs.items():
            if vvar_idx not in vvar_to_loc:
                vvar_to_loc[vvar_idx] = list(vvar_and_uselocs)
            else:
                vvar_to_loc[vvar_idx] += vvar_and_uselocs
    return vvar_to_loc


def get_tmp_deflocs(blocks) -> dict[CodeLocation, dict[atoms.Tmp, int]]:
    tmp_to_loc: dict[CodeLocation, dict[atoms.Tmp, int]] = defaultdict(dict)

    for block in blocks:
        codeloc = CodeLocation(block.addr, None, block_idx=block.idx)
        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp):
                tmp_to_loc[codeloc][atoms.Tmp(stmt.dst.tmp_idx, stmt.dst.bits)] = stmt_idx
            if isinstance(stmt, CAS):
                if isinstance(stmt.old_lo, Tmp):
                    tmp_to_loc[codeloc][atoms.Tmp(stmt.old_lo.tmp_idx, stmt.old_lo.bits)] = stmt_idx
                if stmt.old_hi is not None and isinstance(stmt.old_hi, Tmp):
                    tmp_to_loc[codeloc][atoms.Tmp(stmt.old_hi.tmp_idx, stmt.old_hi.bits)] = stmt_idx

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

    def __init__(self, blacklist_expr_types: tuple[type, ...], skip_if_contains_vvar: int | None = None):
        super().__init__()
        self.blacklist_expr_types = blacklist_expr_types
        self.has_blacklisted_exprs = False
        self.skip_if_contains_vvar = skip_if_contains_vvar

        self._has_specified_vvar = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, self.blacklist_expr_types):
            if self.skip_if_contains_vvar is None:
                self.has_blacklisted_exprs = True
                return None
            # otherwise we do a more complicated check
            self._has_specified_vvar = False  # we do not support nested blacklisted expr types
            has_blacklisted_exprs = True
            r = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
            if self._has_specified_vvar is False:
                # we have seen the vvar that we are looking for! ignore this match
                self.has_blacklisted_exprs = has_blacklisted_exprs
                return None
            self._has_specified_vvar = False
            return r

        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if self.skip_if_contains_vvar is not None and expr.varid == self.skip_if_contains_vvar:
            self._has_specified_vvar = True
        return super()._handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block)


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


def is_phi_assignment(stmt: Statement) -> bool:
    return isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)


def has_load_expr(stmt: Statement, skip_if_contains_vvar: int | None = None) -> bool:
    walker = AILBlacklistExprTypeWalker((Load,), skip_if_contains_vvar=skip_if_contains_vvar)
    walker.walk_statement(stmt)
    return walker.has_blacklisted_exprs


def phi_assignment_get_src(stmt: Statement) -> Phi | None:
    if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
        return stmt.src
    return None


def is_dephi_vvar(vvar: VirtualVariable) -> bool:
    return vvar.varid == DEPHI_VVAR_REG_OFFSET


def has_ite_expr(expr: Expression) -> bool:
    walker = AILBlacklistExprTypeWalker((ITE,))
    walker.walk_expression(expr)
    return walker.has_blacklisted_exprs


def has_ite_stmt(stmt: Statement) -> bool:
    walker = AILBlacklistExprTypeWalker((ITE,))
    walker.walk_statement(stmt)
    return walker.has_blacklisted_exprs


def has_tmp_expr(expr: Expression) -> bool:
    walker = AILBlacklistExprTypeWalker((Tmp,))
    walker.walk_expression(expr)
    return walker.has_blacklisted_exprs


def check_in_between_stmts(
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: CodeLocation,
    useloc: CodeLocation,
    predicate: Callable,
):
    assert defloc.block_addr is not None
    assert defloc.stmt_idx is not None
    assert useloc.block_addr is not None
    assert useloc.stmt_idx is not None
    assert graph is not None

    use_block = blocks[(useloc.block_addr, useloc.block_idx)]
    def_block = blocks[(defloc.block_addr, defloc.block_idx)]

    # traverse the graph, go from use_block until we reach def_block, and look for Store statements
    seen = {use_block}
    queue = [use_block]
    while queue:
        block = queue.pop(0)

        starting_stmt_idx, ending_stmt_idx = 0, len(block.statements)
        if block is def_block:
            starting_stmt_idx = defloc.stmt_idx + 1
        if block is use_block:
            ending_stmt_idx = useloc.stmt_idx

        for i in range(starting_stmt_idx, ending_stmt_idx):
            if predicate(block.statements[i]):
                return True

        if block is def_block:
            continue

        for pred in graph.predecessors(block):
            if pred not in seen:
                seen.add(pred)
                queue.append(pred)

    return False


def has_store_stmt_in_between_stmts(
    graph: networkx.DiGraph, blocks: dict[tuple[int, int | None], Block], defloc: CodeLocation, useloc: CodeLocation
) -> bool:
    return check_in_between_stmts(graph, blocks, defloc, useloc, lambda stmt: isinstance(stmt, Store))


def has_call_in_between_stmts(
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: CodeLocation,
    useloc: CodeLocation,
    skip_if_contains_vvar: int | None = None,
) -> bool:

    def _contains_call(stmt: Statement) -> bool:
        if isinstance(stmt, Call):
            return True
        # walk the statement and check if there is a call expression
        walker = AILBlacklistExprTypeWalker((Call,), skip_if_contains_vvar=skip_if_contains_vvar)
        walker.walk_statement(stmt)
        return walker.has_blacklisted_exprs

    return check_in_between_stmts(graph, blocks, defloc, useloc, _contains_call)


def has_load_expr_in_between_stmts(
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: CodeLocation,
    useloc: CodeLocation,
    skip_if_contains_vvar: int | None = None,
) -> bool:
    return check_in_between_stmts(
        graph, blocks, defloc, useloc, lambda stmt: has_load_expr(stmt, skip_if_contains_vvar=skip_if_contains_vvar)
    )


def is_vvar_eliminatable(vvar: VirtualVariable, def_stmt: Statement | None) -> bool:
    if vvar.was_tmp or vvar.was_reg or vvar.was_parameter:
        return True
    if (  # noqa: SIM103
        vvar.was_stack
        and isinstance(def_stmt, Assignment)
        and isinstance(def_stmt.src, VirtualVariable)
        and def_stmt.src.was_stack
        and def_stmt.src.stack_offset == vvar.stack_offset
    ):
        # special case: the following block
        #   ## Block 401e98
        #   00 | 0x401e98 | LABEL_401e98:
        #   01 | 0x401e98 | vvar_227{stack -12} = 𝜙@32b [((4202088, None), vvar_277{stack -12}), ((4202076, None),
        #                   vvar_278{stack -12})]
        #   02 | 0x401ea0 | return Conv(32->64, vvar_227{stack -12});
        # might be simplified to the following block after return duplication
        #   ## Block 401e98.1
        #   00 | 0x401e98 | LABEL_401e98__1:
        #   01 | 0x401e98 | vvar_279{stack -12} = vvar_277{stack -12}
        #   02 | 0x401ea0 | return Conv(32->64, vvar_279{stack -12});
        # in this case, vvar_279 is eliminatable.
        return True
    return False


__all__ = (
    "VVarUsesCollector",
    "check_in_between_stmts",
    "get_tmp_deflocs",
    "get_tmp_uselocs",
    "get_vvar_deflocs",
    "get_vvar_uselocs",
    "has_call_in_between_stmts",
    "has_ite_expr",
    "has_load_expr_in_between_stmts",
    "has_store_stmt_in_between_stmts",
    "is_const_and_vvar_assignment",
    "is_const_assignment",
    "is_const_vvar_load_assignment",
    "is_const_vvar_load_dirty_assignment",
    "is_phi_assignment",
    "is_vvar_eliminatable",
    "phi_assignment_get_src",
)
