from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any, Literal, overload

import archinfo
import networkx

from angr.ailment import Address, Block, Expression
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Extract,
    Insert,
    Load,
    MultiStatementExpression,
    Phi,
    Reinterpret,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import CAS, Assignment, SideEffectStatement, Statement, Store
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions import atoms
from angr.rustylib.ailment import ExpressionKind as _EK  # pylint:disable=import-error
from angr.rustylib.ailment import Statement as _RustStatement  # pylint:disable=import-error,no-name-in-module
from angr.rustylib.ailment import StatementKind as _SK  # pylint:disable=import-error

from .combined_uses_collector import VVarAndTmpUsesCollector
from .tmp_uses_collector import TmpUsesCollector
from .vvar_extra_defs_collector import FindExtraDefs
from .vvar_uses_collector import VVarUsesCollector

# Module-level kind constants -- bound once at import so the hot SSA
# loops do an int compare against a local instead of an attribute
# lookup on the pyclass per iteration.
_SK_ASSIGNMENT = _SK.Assignment
_SK_SIDE_EFFECT_STATEMENT = _SK.SideEffectStatement
_SK_CAS = _SK.CAS
_EK_VIRTUAL_VARIABLE = _EK.VirtualVariable
_EK_TMP = _EK.Tmp
_EK_PHI = _EK.Phi

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
) -> tuple[int, int | None] | None:
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
        base_reg_and_size = arch.get_base_register(reg_offset, size=None)
        if base_reg_and_size is None:
            # give up
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
    blocks, phi_vvars: dict[int, set[int | None]] | None = None, check_extra_defs: bool = True
) -> dict[int, tuple[VirtualVariable, AILCodeLocation]]:
    vvar_to_loc: dict[int, tuple[VirtualVariable, AILCodeLocation]] = {}
    walker = FindExtraDefs()
    walker.found = vvar_to_loc
    for block in blocks:
        for stmt_idx, stmt in enumerate(block.statements):
            # Dispatch on ``stmt.kind`` directly (~20 ns) instead
            # of ``isinstance(stmt, MarkerCls)`` (~150 ns via the marker
            # metaclass). The pure-Python ``IncompleteSwitchCaseHeadStatement``
            # subclass declares its own class-level ``kind`` attribute
            # (``"IncompleteSwitchCaseHead"``) so this read always works.
            kind = stmt.kind
            if kind == _SK_ASSIGNMENT:
                dst = stmt.dst
                if dst.kind == _EK_VIRTUAL_VARIABLE:
                    vvar_to_loc[dst.varid] = (
                        dst,
                        AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr")),
                    )
                    if phi_vvars is not None and stmt.src.kind == _EK_PHI:
                        phi_vvars[dst.varid] = {
                            vvar_.varid if vvar_ is not None else None for src, vvar_ in stmt.src.src_and_vvars
                        }
            elif kind == _SK_SIDE_EFFECT_STATEMENT:
                ret = stmt.ret_expr
                if ret is not None and ret.kind == _EK_VIRTUAL_VARIABLE:
                    vvar_to_loc[ret.varid] = (
                        ret,
                        AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr")),
                    )
                fp_ret = stmt.fp_ret_expr
                if fp_ret is not None and fp_ret.kind == _EK_VIRTUAL_VARIABLE:
                    vvar_to_loc[fp_ret.varid] = (
                        fp_ret,
                        AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr")),
                    )

            if extra_defs := stmt.tags.get("extra_defs", None):
                walker.walk_statement(stmt, block, stmt_idx)
                # When scanning only a subset of blocks (e.g. incremental updates), an extra-def varid may be defined
                # in a block that is not part of the subset, so this consistency check is skipped there.
                assert not check_extra_defs or all(varid in vvar_to_loc for varid in extra_defs), (
                    "extra_def tag was dropped"
                )

    return vvar_to_loc


def get_vvar_uselocs(blocks) -> dict[int, list[tuple[VirtualVariable, AILCodeLocation]]]:
    collector = VVarUsesCollector()
    for block in blocks:
        collector.walk(block)
    return collector.vvar_and_uselocs


def get_tmp_deflocs(blocks: Iterable[Block]) -> dict[Address, dict[atoms.Tmp, int]]:
    tmp_to_loc: dict[Address, dict[atoms.Tmp, int]] = defaultdict(dict)

    for block in blocks:
        codeloc = (block.addr, block.idx)
        for stmt_idx, stmt in enumerate(block.statements):
            # See ``get_vvar_deflocs`` for the .kind vs isinstance() rationale.
            kind = stmt.kind
            if kind == _SK_ASSIGNMENT:
                dst = stmt.dst
                if dst.kind == _EK_TMP:
                    tmp_to_loc[codeloc][atoms.Tmp(dst.tmp_idx, dst.bits)] = stmt_idx
            elif kind == _SK_CAS:
                old_lo = stmt.old_lo
                if old_lo.kind == _EK_TMP:
                    tmp_to_loc[codeloc][atoms.Tmp(old_lo.tmp_idx, old_lo.bits)] = stmt_idx
                old_hi = stmt.old_hi
                if old_hi is not None and old_hi.kind == _EK_TMP:
                    tmp_to_loc[codeloc][atoms.Tmp(old_hi.tmp_idx, old_hi.bits)] = stmt_idx

    return tmp_to_loc


def get_tmp_uselocs(blocks: Iterable[Block]) -> dict[Address, dict[atoms.Tmp, set[tuple[Tmp, int]]]]:
    tmp_to_loc: dict[Address, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)
    collector = TmpUsesCollector()
    for block in blocks:
        collector.reset()
        collector.walk(block)
        block_loc = (block.addr, block.idx)
        for (tmp_idx, tmp_bits), tmp_and_stmtids in collector.tmp_and_uselocs.items():
            if tmp_idx not in tmp_to_loc[block_loc]:
                tmp_to_loc[block_loc][atoms.Tmp(tmp_idx, tmp_bits)] = tmp_and_stmtids
            else:
                tmp_to_loc[block_loc][atoms.Tmp(tmp_idx, tmp_bits)] |= tmp_and_stmtids

    return tmp_to_loc


def get_uses_defs(
    blocks,
    phi_vvars: dict[int, set[int | None]] | None = None,
    check_extra_defs: bool = True,
) -> tuple[
    dict[int, tuple[VirtualVariable, AILCodeLocation]],
    dict[int, list[tuple[VirtualVariable, AILCodeLocation]]],
    dict[Address, dict[atoms.Tmp, int]],
    dict[Address, dict[atoms.Tmp, set[tuple[Tmp, int]]]],
]:
    """Combined ``get_{vvar,tmp}_{def,use}locs``.

    Return: ``(vvar_deflocs, vvar_uselocs, tmp_deflocs, tmp_uselocs)`` matching the original four-function shapes.
    """
    vvar_deflocs: dict[int, tuple[VirtualVariable, AILCodeLocation]] = {}
    tmp_deflocs: dict[Address, dict[atoms.Tmp, int]] = defaultdict(dict)
    tmp_uselocs: dict[Address, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)

    extra_defs_walker = FindExtraDefs()
    extra_defs_walker.found = vvar_deflocs

    collector = VVarAndTmpUsesCollector()

    for block in blocks:
        block_loc = (block.addr, block.idx)
        block_addr = block.addr
        block_idx = block.idx

        # tmp uses are per-block; vvar uses accumulate across blocks.
        collector.reset_tmp_uses_only()

        for stmt_idx, stmt in enumerate(block.statements):
            stmt_ins_addr = stmt.tags.get("ins_addr")
            if isinstance(stmt, Assignment):
                dst = stmt.dst
                if isinstance(dst, VirtualVariable):
                    vvar_deflocs[dst.varid] = (
                        dst,
                        AILCodeLocation(block_addr, block_idx, stmt_idx, stmt_ins_addr),
                    )
                    if phi_vvars is not None and isinstance(stmt.src, Phi):
                        phi_vvars[dst.varid] = {
                            vvar_.varid if vvar_ is not None else None for src, vvar_ in stmt.src.src_and_vvars
                        }
                elif isinstance(dst, Tmp):
                    tmp_deflocs[block_loc][atoms.Tmp(dst.tmp_idx, dst.bits)] = stmt_idx
            elif isinstance(stmt, SideEffectStatement):
                if isinstance(stmt.ret_expr, VirtualVariable):
                    vvar_deflocs[stmt.ret_expr.varid] = (
                        stmt.ret_expr,
                        AILCodeLocation(block_addr, block_idx, stmt_idx, stmt_ins_addr),
                    )
                if isinstance(stmt.fp_ret_expr, VirtualVariable):
                    vvar_deflocs[stmt.fp_ret_expr.varid] = (
                        stmt.fp_ret_expr,
                        AILCodeLocation(block_addr, block_idx, stmt_idx, stmt_ins_addr),
                    )
            elif isinstance(stmt, CAS):
                if isinstance(stmt.old_lo, Tmp):
                    tmp_deflocs[block_loc][atoms.Tmp(stmt.old_lo.tmp_idx, stmt.old_lo.bits)] = stmt_idx
                if stmt.old_hi is not None and isinstance(stmt.old_hi, Tmp):
                    tmp_deflocs[block_loc][atoms.Tmp(stmt.old_hi.tmp_idx, stmt.old_hi.bits)] = stmt_idx

            if extra_defs := stmt.tags.get("extra_defs", None):
                extra_defs_walker.walk_statement(stmt, block, stmt_idx)
                assert not check_extra_defs or all(varid in vvar_deflocs for varid in extra_defs), (
                    "extra_def tag was dropped"
                )

        collector.walk(block)

        # Extract this block's tmp uses into the block-keyed map.
        block_tmp_map = tmp_uselocs[block_loc]
        for (tmp_idx, tmp_bits), tmp_and_stmtids in collector.tmp_and_uselocs.items():
            key = atoms.Tmp(tmp_idx, tmp_bits)
            existing = block_tmp_map.get(key)
            if existing is None:
                block_tmp_map[key] = tmp_and_stmtids
            else:
                existing |= tmp_and_stmtids

    return vvar_deflocs, collector.vvar_and_uselocs, tmp_deflocs, tmp_uselocs


def is_const_assignment(stmt: Statement, only_consts: bool = False) -> tuple[bool, Const | StackBaseOffset | None]:
    if isinstance(stmt, Assignment) and (
        isinstance(stmt.src, Const) or (not only_consts and isinstance(stmt.src, StackBaseOffset))
    ):
        return True, stmt.src
    return False, None


class AILBlacklistExprTypeWalker(AILBlockViewer):
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
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if self.skip_if_contains_vvar is not None and expr.varid == self.skip_if_contains_vvar:
            self._has_specified_vvar = True
        return super()._handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block)


class AILWhitelistExprTypeWalker(AILBlockViewer):
    """
    Walks an AIL expression or statement and determines if it is built *only* out of a whitelisted set of expression
    types. ``has_nonwhitelisted_exprs`` is set to True as soon as any expression whose type is not in the whitelist is
    encountered.

    Note that the whitelist must include the operator/container types that the walker recurses through (e.g. BinaryOp,
    UnaryOp), otherwise those nodes would be flagged as non-whitelisted.
    """

    def __init__(self, whitelist_expr_types: tuple[type, ...]):
        super().__init__()
        self.whitelist_expr_types = whitelist_expr_types
        self.has_nonwhitelisted_exprs = False

    def reset(self) -> None:
        self.has_nonwhitelisted_exprs = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if not isinstance(expr, self.whitelist_expr_types):
            self.has_nonwhitelisted_exprs = True
            # the result is already determined; no need to recurse into this subtree
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


_CONST_VVAR_OPERATORS: tuple[type, ...] = (
    BinaryOp,
    UnaryOp,
    ITE,
    Extract,
    Insert,
    MultiStatementExpression,
    StackBaseOffset,
    Convert,
    Reinterpret,
)
CONST_VVAR_WHITELIST = (Const, VirtualVariable, *_CONST_VVAR_OPERATORS)
CONST_VVAR_TMP_WHITELIST = (*CONST_VVAR_WHITELIST, Tmp)
CONST_VVAR_LOAD_WHITELIST = (*CONST_VVAR_WHITELIST, Load)
CONST_VVAR_LOAD_DIRTY_WHITELIST = (*CONST_VVAR_WHITELIST, Load, DirtyExpression)


def _check_whitelisted_assignment_src(
    stmt: Statement, whitelist: tuple[type, ...], walker_cached: AILWhitelistExprTypeWalker | None
) -> bool:
    if isinstance(stmt, Assignment):
        if walker_cached is None:
            walker = AILWhitelistExprTypeWalker(whitelist)
        else:
            walker = walker_cached
            walker.reset()
        walker.walk_expression(stmt.src)
        return not walker.has_nonwhitelisted_exprs
    return False


def is_const_and_vvar_assignment(stmt: Statement, walker_cached: AILWhitelistExprTypeWalker | None = None) -> bool:
    return _check_whitelisted_assignment_src(stmt, CONST_VVAR_WHITELIST, walker_cached)


def is_const_vvar_tmp_assignment(stmt: Statement, walker_cached: AILWhitelistExprTypeWalker | None = None) -> bool:
    return _check_whitelisted_assignment_src(stmt, CONST_VVAR_TMP_WHITELIST, walker_cached)


def is_const_vvar_load_assignment(stmt: Statement, walker_cached: AILWhitelistExprTypeWalker | None = None) -> bool:
    return _check_whitelisted_assignment_src(stmt, CONST_VVAR_LOAD_WHITELIST, walker_cached)


def is_const_vvar_load_dirty_assignment(
    stmt: Statement, walker_cached: AILWhitelistExprTypeWalker | None = None
) -> bool:
    return _check_whitelisted_assignment_src(stmt, CONST_VVAR_LOAD_DIRTY_WHITELIST, walker_cached)


def is_phi_assignment(stmt: Statement) -> bool:
    # Native projection -- one FFI call, no dst/src wrapper cloning. The
    # native getter additionally requires ``dst`` to be a VirtualVariable,
    # which every phi assignment in SSA form satisfies.
    return isinstance(stmt, _RustStatement) and stmt.is_phi_assignment


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


class AILReferenceFinder(AILBlockViewer):
    """
    Walks an AIL expression or statement and finds if it contains references to certain expressions.
    """

    def __init__(self, vvar_id: int):
        super().__init__()
        self.vvar_id = vvar_id
        self.has_references_to_vvar = False

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.varid == self.vvar_id:
            self.has_references_to_vvar = True
            return None
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


def has_reference_to_vvar(stmt: Statement, vvar_id: int) -> bool:
    walker = AILReferenceFinder(vvar_id)
    walker.walk_statement(stmt)
    return walker.has_references_to_vvar


def stmt_is_simple_call(stmt: Statement) -> Call | None:
    if isinstance(stmt, SideEffectStatement):
        return stmt.expr if isinstance(stmt.expr, Call) else None
    if not isinstance(stmt, Assignment):
        return None
    src = stmt.src
    while True:
        if isinstance(src, Call):
            return src
        if isinstance(src, Convert):
            src = src.operand
        elif isinstance(src, Extract):
            src = src.base
        elif isinstance(src, Insert):
            src = src.value
        else:
            return None


def check_in_between_stmts(
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: AILCodeLocation,
    useloc: AILCodeLocation,
    predicate: Callable,
):
    use_block = blocks[(useloc.addr, useloc.block_idx)]
    def_block = blocks[(defloc.addr, defloc.block_idx)]

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
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: AILCodeLocation,
    useloc: AILCodeLocation,
) -> bool:
    return check_in_between_stmts(graph, blocks, defloc, useloc, lambda stmt: isinstance(stmt, Store))


def has_call_in_between_stmts(
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: AILCodeLocation,
    useloc: AILCodeLocation,
    skip_if_contains_vvar: int | None = None,
) -> bool:
    def _contains_call(stmt: Statement) -> bool:
        if isinstance(stmt, SideEffectStatement):
            return True
        # walk the statement and check if there is a call expression
        walker = AILBlacklistExprTypeWalker((Call,), skip_if_contains_vvar=skip_if_contains_vvar)
        walker.walk_statement(stmt)
        return walker.has_blacklisted_exprs

    return check_in_between_stmts(graph, blocks, defloc, useloc, _contains_call)


def has_load_expr_in_between_stmts(
    graph: networkx.DiGraph,
    blocks: dict[tuple[int, int | None], Block],
    defloc: AILCodeLocation,
    useloc: AILCodeLocation,
    skip_if_contains_vvar: int | None = None,
) -> bool:
    return check_in_between_stmts(
        graph, blocks, defloc, useloc, lambda stmt: has_load_expr(stmt, skip_if_contains_vvar=skip_if_contains_vvar)
    )


def is_vvar_propagatable(vvar: VirtualVariable, def_stmt: Statement, stack_arg_offsets: set[int] | None) -> bool:
    if isinstance(def_stmt, Assignment) and isinstance(def_stmt.src, Insert):
        # do not create huge insert chains
        return False
    if (
        isinstance(def_stmt, Assignment)
        and isinstance(def_stmt.dst, VirtualVariable)
        and def_stmt.dst.varid != vvar.varid
    ):
        # the definition statement is not directly assigning to the vvar; this is probably because the vvar happens to
        # be defined together in def_stmt.src, e.g., `vvar_781 = Reference(vvar_780)` where vvar_780 is first seen at
        # this statement. we cannot propagate vvar_780.
        return False
    if vvar.was_tmp or vvar.was_reg or vvar.was_parameter:
        return True
    if vvar.was_stack and isinstance(def_stmt, Assignment):
        if (
            stack_arg_offsets is not None
            and vvar.stack_offset in stack_arg_offsets
            and not isinstance(def_stmt.src, Phi)
        ):
            return True
        if (
            isinstance(def_stmt.src, VirtualVariable)
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
    "CONST_VVAR_LOAD_DIRTY_WHITELIST",
    "CONST_VVAR_LOAD_WHITELIST",
    "CONST_VVAR_TMP_WHITELIST",
    "CONST_VVAR_WHITELIST",
    "AILWhitelistExprTypeWalker",
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
