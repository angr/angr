# pylint:disable=too-many-boolean-expressions,consider-using-enumerate
from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections.abc import Iterable
from collections import defaultdict
from enum import Enum
import logging

import networkx

from angr.ailment import AILBlockWalker
from angr.ailment.block import Block
from angr.ailment.statement import Statement, Assignment, Store, Call, ConditionalJump, DirtyStatement, WeakAssignment
from angr.ailment.expression import (
    Register,
    Convert,
    Load,
    StackBaseOffset,
    Expression,
    DirtyExpression,
    VEXCCallExpression,
    Tmp,
    Const,
    BinaryOp,
    VirtualVariable,
    UnaryOp,
)

from angr.analyses.s_propagator import SPropagatorAnalysis
from angr.analyses.s_reaching_definitions import SRDAModel
from angr.utils.ail import is_phi_assignment, HasExprWalker
from angr.utils.ssa import (
    has_call_in_between_stmts,
    has_store_stmt_in_between_stmts,
    has_load_expr_in_between_stmts,
    is_vvar_eliminatable,
)
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.sim_variable import SimStackVariable, SimMemoryVariable, SimVariable
from angr.knowledge_plugins.propagations.states import Equivalence
from angr.knowledge_plugins.key_definitions import atoms
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.errors import AngrRuntimeError
from angr.analyses import Analysis, AnalysesHub
from angr.utils.timing import timethis
from .ailgraph_walker import AILGraphWalker
from .expression_narrower import ExprNarrowingInfo, NarrowingInfoExtractor, ExpressionNarrower
from .block_simplifier import BlockSimplifier
from .ccall_rewriters import CCALL_REWRITERS
from .counters.expression_counters import SingleExpressionCounter

if TYPE_CHECKING:
    from angr.ailment.manager import Manager


_l = logging.getLogger(__name__)


class HasCallNotification(Exception):
    """
    Notifies the existence of a call statement.
    """


class HasVVarNotification(Exception):
    """
    Notifies the existence of a VirtualVariable.
    """


class HasRefVVarNotification(Exception):
    """
    Notifies the existence of a reference to a VirtualVariable.
    """


class AILBlockTempCollector(AILBlockWalker):
    """
    Collects any temporaries used in a block.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.temps = set()
        self.expr_handlers[Tmp] = self._handle_Tmp

    # pylint:disable=unused-argument
    def _handle_Tmp(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement, block) -> None:
        if isinstance(expr, Tmp):
            self.temps.add(expr)


class DefEqRelation(Enum):
    """
    Describes the location relationship between a virtual variable definition and the equivalence statement.
    """

    UNKNOWN = 0
    DEF_IS_FUNCARG = 1
    DEF_EQ_SAME_BLOCK = 2
    DEF_IN_EQ_PRED_BLOCK = 3


class PartialConstantExprRewriter(AILBlockWalker):
    """
    Rewrites expressions whose high bits are definitely zero to constants (if possible) or mask them with masks
    properly.
    """

    def __init__(self, varid: int, zero_high_bits: int):
        super().__init__(update_block=False)
        self.varid = varid
        self.zero_high_bits = zero_high_bits

    def _handle_BinaryOp(  # type:ignore
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if (
            expr.op == "And"
            and isinstance(expr.operands[0], VirtualVariable)
            and expr.operands[0].varid == self.varid
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].is_int
        ):
            vvar = expr.operands[0]
            mask_expr = expr.operands[1]
            mask = mask_expr.value
            assert isinstance(mask, int)
            # high_bits_mask[vvar.bits - 1:vvar.bits - self.zero_high_bits] == 0
            high_bits_mask = ((1 << vvar.bits) - 1) ^ ((1 << (vvar.bits - self.zero_high_bits)) - 1)
            high_bits_mask &= mask  # in case high bits of mask are zero
            new_mask = mask ^ high_bits_mask
            if new_mask == mask:
                return None
            if new_mask == 0:
                return Const(expr_idx, None, 0, expr.bits, **expr.tags)
            new_mask_expr = Const(mask_expr.idx, mask_expr.variable, new_mask, mask_expr.bits, **mask_expr.tags)
            return BinaryOp(expr_idx, expr.op, [vvar, new_mask_expr], bits=expr.bits, **expr.tags)
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)


class AILSimplifier(Analysis):
    """
    Perform function-level simplifications.
    """

    def __init__(
        self,
        func,
        func_graph=None,
        remove_dead_memdefs=False,
        stack_arg_offsets: set[tuple[int, int]] | None = None,
        unify_variables=False,
        ail_manager: Manager | None = None,
        gp: int | None = None,
        narrow_expressions=False,
        only_consts=False,
        fold_callexprs_into_conditions=False,
        use_callee_saved_regs_at_return=True,
        rewrite_ccalls=True,
        removed_vvar_ids: set[int] | None = None,
        arg_vvars: dict[int, tuple[VirtualVariable, SimVariable]] | None = None,
        avoid_vvar_ids: set[int] | None = None,
        secondary_stackvars: set[int] | None = None,
    ):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions: SRDAModel | None = None
        self._propagator: SPropagatorAnalysis | None = None

        self._remove_dead_memdefs = remove_dead_memdefs
        self._stack_arg_offsets = stack_arg_offsets
        self._unify_vars = unify_variables
        self._ail_manager: Manager | None = ail_manager
        self._gp = gp
        self._narrow_expressions = narrow_expressions
        self._only_consts = only_consts
        self._fold_callexprs_into_conditions = fold_callexprs_into_conditions
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        self._should_rewrite_ccalls = rewrite_ccalls
        self._removed_vvar_ids = removed_vvar_ids if removed_vvar_ids is not None else set()
        self._arg_vvars = arg_vvars
        self._avoid_vvar_ids = avoid_vvar_ids if avoid_vvar_ids is not None else set()
        self._propagator_dead_vvar_ids: set[int] = set()
        self._secondary_stackvars: set[int] = secondary_stackvars if secondary_stackvars is not None else set()

        self._calls_to_remove: set[CodeLocation] = set()
        self._assignments_to_remove: set[CodeLocation] = set()
        self.blocks = {}  # Mapping nodes to simplified blocks

        self.simplified: bool = False
        self._simplify()

    def _simplify(self):
        if self._narrow_expressions:
            _l.debug("Removing dead assignments before narrowing expressions")
            r = self._iteratively_remove_dead_assignments()
            if r:
                _l.debug("... dead assignments removed")
                self.simplified = True

            _l.debug("Narrowing expressions")
            narrowed_exprs = self._narrow_exprs()
            self.simplified |= narrowed_exprs
            if narrowed_exprs:
                _l.debug("... expressions narrowed")
                self._rebuild_func_graph()
                self._clear_cache()

        _l.debug("Folding expressions")
        folded_exprs = self._fold_exprs()
        self.simplified |= folded_exprs
        if folded_exprs:
            _l.debug("... expressions folded")
            self._rebuild_func_graph()
            # reaching definition analysis results are no longer reliable
            self._clear_cache()

        _l.debug("Propagating partial-constant expressions")
        pconst_propagated = self._propagate_partial_constant_exprs()
        self.simplified |= pconst_propagated
        if pconst_propagated:
            _l.debug("... partial-constant expressions propagated")
            self._rebuild_func_graph()
            # reaching definition analysis results are no longer reliable
            self._clear_cache()

        if self._only_consts:
            return

        if self._should_rewrite_ccalls:
            _l.debug("Rewriting ccalls")
            ccalls_rewritten = self._rewrite_ccalls()
            self.simplified |= ccalls_rewritten
            if ccalls_rewritten:
                _l.debug("... ccalls rewritten")
                self._rebuild_func_graph()
                self._clear_cache()

        if self._unify_vars:
            _l.debug("Removing dead assignments")
            r = self._iteratively_remove_dead_assignments()
            if r:
                _l.debug("... dead assignments removed")
                self.simplified = True

            _l.debug("Unifying local variables")
            r = self._unify_local_variables()
            if r:
                _l.debug("... local variables unified")
                self.simplified = True
                self._rebuild_func_graph()

            # _fold_call_exprs() may set self._calls_to_remove, which will be honored in _remove_dead_assignments()
            _l.debug("Folding call expressions")
            r = self._fold_call_exprs()
            if r:
                _l.debug("... call expressions folded")
                self.simplified = True
                self._rebuild_func_graph()
                self._clear_cache()

        _l.debug("Removing dead assignments")
        r = self._iteratively_remove_dead_assignments()
        if r:
            _l.debug("... dead assignments removed")
            self.simplified = True

    def _rebuild_func_graph(self):
        def _handler(node):
            return self.blocks.get(node, None)

        AILGraphWalker(self.func_graph, _handler, replace_nodes=True).walk()
        self.blocks = {}

    def _compute_reaching_definitions(self) -> SRDAModel:
        # Computing reaching definitions or return the cached one
        if self._reaching_definitions is not None:
            return self._reaching_definitions
        func_args = {vvar for vvar, _ in self._arg_vvars.values()} if self._arg_vvars else set()
        rd = self.project.analyses.SReachingDefinitions(
            subject=self.func,
            func_graph=self.func_graph,
            func_args=func_args,
            # use_callee_saved_regs_at_return=self._use_callee_saved_regs_at_return,
            # track_tmps=True,
        ).model
        self._reaching_definitions = rd
        return rd

    @timethis
    def _compute_propagation(self) -> SPropagatorAnalysis:
        # Propagate expressions or return the existing result
        if self._propagator is not None:
            return self._propagator
        func_args = {vvar for vvar, _ in self._arg_vvars.values()} if self._arg_vvars else set()
        prop = self.project.analyses[SPropagatorAnalysis].prep(fail_fast=self._fail_fast)(
            subject=self.func,
            func_graph=self.func_graph,
            func_args=func_args,
            # gp=self._gp,
            only_consts=self._only_consts,
        )
        self._propagator = prop
        self._propagator_dead_vvar_ids = prop.dead_vvar_ids
        return prop

    @timethis
    def _compute_equivalence(self) -> set[Equivalence]:
        equivalence = set()
        for block in self.func_graph:
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment):
                    if isinstance(stmt.dst, VirtualVariable) and isinstance(
                        stmt.src, (VirtualVariable, Tmp, Call, Convert)
                    ):
                        codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                        equivalence.add(Equivalence(codeloc, stmt.dst, stmt.src))
                elif isinstance(stmt, WeakAssignment):
                    codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                    equivalence.add(Equivalence(codeloc, stmt.dst, stmt.src, is_weakassignment=True))
                elif isinstance(stmt, Call):
                    if isinstance(stmt.ret_expr, (VirtualVariable, Load)):
                        codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                        equivalence.add(Equivalence(codeloc, stmt.ret_expr, stmt))
                    elif isinstance(stmt.fp_ret_expr, (VirtualVariable, Load)):
                        codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                        equivalence.add(Equivalence(codeloc, stmt.fp_ret_expr, stmt))
                elif (
                    isinstance(stmt, Store)
                    and isinstance(stmt.size, int)
                    and isinstance(stmt.data, (VirtualVariable, Tmp, Call, Convert))
                ):
                    if isinstance(stmt.addr, StackBaseOffset) and isinstance(stmt.addr.offset, int):
                        # stack variable
                        atom = SimStackVariable(stmt.addr.offset, stmt.size)
                        codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                        equivalence.add(Equivalence(codeloc, atom, stmt.data))
                    elif isinstance(stmt.addr, Const):
                        # global variable
                        atom = SimMemoryVariable(stmt.addr.value, stmt.size)
                        codeloc = CodeLocation(block.addr, stmt_idx, block_idx=block.idx, ins_addr=stmt.ins_addr)
                        equivalence.add(Equivalence(codeloc, atom, stmt.data))
        return equivalence

    def _clear_cache(self) -> None:
        self._propagator = None
        self._reaching_definitions = None

    def _clear_propagator_cache(self) -> None:
        self._propagator = None

    def _clear_reaching_definitions_cache(self) -> None:
        self._reaching_definitions = None

    #
    # Expression narrowing
    #

    @timethis
    def _narrow_exprs(self) -> bool:
        """
        A register may be used with full width even when only the lower bytes are really needed. This results in the
        incorrect determination of wider variables while the actual variable is narrower (e.g., int64 vs char). This
        optimization narrows a register definition if all its uses are narrower than the definition itself.
        """

        narrowed = False

        addr_and_idx_to_block: dict[tuple[int, int | None], Block] = {}
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        rd = self._compute_reaching_definitions()
        sorted_defs = sorted(rd.all_definitions, key=lambda d: d.codeloc, reverse=True)
        narrowing_candidates: dict[int, tuple[Definition, ExprNarrowingInfo]] = {}
        for def_ in (d_ for d_ in sorted_defs if d_.codeloc.context is None):
            if isinstance(def_.atom, atoms.VirtualVariable) and (def_.atom.was_reg or def_.atom.was_parameter):
                # only do this for general purpose register
                skip_def = False
                for reg in self.project.arch.register_list:
                    if not reg.artificial and reg.vex_offset == def_.atom.reg_offset and not reg.general_purpose:
                        skip_def = True
                        break

                if skip_def:
                    continue

                narrow = self._narrowing_needed(def_, rd, addr_and_idx_to_block)
                if narrow.narrowable:
                    # we cannot narrow it immediately because any definition that is used by phi variables must be
                    # narrowed together with all other definitions that can reach the phi variables.
                    # so we record the information and decide if we are going to narrow these expressions or not at the
                    # end of the loop.
                    narrowing_candidates[def_.atom.varid] = def_, narrow

        # first, determine which phi vars need to be narrowed and can be narrowed.
        # a phi var can only be narrowed if all its source vvars are narrowable
        vvar_to_narrowing_size = {}
        for def_varid, (_, narrow_info) in narrowing_candidates.items():
            vvar_to_narrowing_size[def_varid] = narrow_info.to_size

        blacklist_varids = set()
        while True:
            repeat, narrowables = self._compute_narrowables_once(
                rd, narrowing_candidates, vvar_to_narrowing_size, blacklist_varids
            )
            if not repeat:
                break

        # let's narrow them (finally)
        narrower = ExpressionNarrower(self.project, rd, narrowables, addr_and_idx_to_block, self.blocks)
        for old_block in addr_and_idx_to_block.values():
            new_block = self.blocks.get(old_block, old_block)
            new_block = narrower.walk(new_block)
            if narrower.narrowed_any:
                narrowed = True
                self.blocks[old_block] = new_block

        # update self._arg_vvars if necessary
        for new_vvars in narrower.replacement_core_vvars.values():
            for new_vvar in new_vvars:
                if new_vvar.was_parameter and self._arg_vvars:
                    for func_arg_idx in list(self._arg_vvars):
                        vvar, simvar = self._arg_vvars[func_arg_idx]
                        if vvar.varid == new_vvar.varid:
                            simvar_new = simvar.copy()
                            simvar_new._hash = None
                            simvar_new.size = new_vvar.size
                            self._arg_vvars[func_arg_idx] = new_vvar, simvar_new

        return narrowed

    @staticmethod
    def _compute_narrowables_once(
        rd, narrowing_candidates: dict, vvar_to_narrowing_size: dict[int, int], blacklist_varids: set
    ):
        repeat = False
        narrowable_phivarids = set()
        for def_vvarid in narrowing_candidates:
            if def_vvarid in blacklist_varids:
                continue
            if def_vvarid in rd.phi_vvar_ids:
                narrowing_sizes = set()
                src_vvarids = rd.phivarid_to_varids[def_vvarid]
                for vvarid in src_vvarids:
                    if vvarid in blacklist_varids:
                        narrowing_sizes.add(None)
                    else:
                        narrowing_sizes.add(vvar_to_narrowing_size.get(vvarid))
                if len(narrowing_sizes) == 1 and None not in narrowing_sizes:
                    # we can narrow this phi vvar!
                    narrowable_phivarids.add(def_vvarid)
                else:
                    # blacklist it for now
                    blacklist_varids.add(def_vvarid)

        # now determine what to narrow!
        narrowables = []

        for def_, narrow_info in narrowing_candidates.values():
            if def_.atom.varid in blacklist_varids:
                continue
            if not narrow_info.phi_vars:
                # not used by any other phi variables. good!
                narrowables.append((def_, narrow_info))
            else:
                if {phivar.varid for phivar in narrow_info.phi_vars}.issubset(narrowable_phivarids):
                    # all phi vvars that use this definition can be narrowed
                    narrowables.append((def_, narrow_info))
                else:
                    # this vvar cannot be narrowed
                    # note that all phi variables that relies on this vvar also cannot be narrowed! we must analyze
                    # again
                    repeat = True
                    blacklist_varids.add(def_.atom.varid)
                    blacklist_varids |= {phivar.varid for phivar in narrow_info.phi_vars}

        return repeat, narrowables

    def _narrowing_needed(self, def_, rd: SRDAModel, addr_and_idx_to_block) -> ExprNarrowingInfo:

        def_size = def_.size
        # find its uses
        # some use locations are phi assignments. we keep tracking the uses of phi variables and update the dictionary
        result = self._get_vvar_use_and_exprs_recursive(def_.atom, rd, addr_and_idx_to_block)
        if result is None:
            return ExprNarrowingInfo(False)
        use_and_exprs, phi_vars = result

        all_used_sizes = set()
        used_by: list[tuple[atoms.VirtualVariable, CodeLocation, tuple[str, tuple[Expression, ...]]]] = []
        used_by_loc = defaultdict(list)

        for atom, loc, expr in use_and_exprs:
            old_block = addr_and_idx_to_block.get((loc.block_addr, loc.block_idx), None)
            if old_block is None:
                # missing a block for whatever reason
                return ExprNarrowingInfo(False)

            block = self.blocks.get(old_block, old_block)
            assert loc.stmt_idx is not None
            if loc.stmt_idx >= len(block.statements):
                # missing a statement for whatever reason
                return ExprNarrowingInfo(False)
            stmt = block.statements[loc.stmt_idx]

            # special case: if the statement is a Call statement and expr is None, it means we have not been able to
            # determine if the expression is really used by the call or not. skip it in this case
            if isinstance(stmt, Call) and expr is None:
                continue
            # special case: if the statement is a phi statement, we ignore it
            if is_phi_assignment(stmt):
                continue

            expr_size, used_by_exprs = self._extract_expression_effective_size(stmt, expr)
            if expr_size is None:
                # it's probably used in full width
                return ExprNarrowingInfo(False)

            all_used_sizes.add(expr_size)
            used_by_loc[loc].append((atom, used_by_exprs))

        if len(all_used_sizes) == 1 and next(iter(all_used_sizes)) < def_size:
            for loc, atom_expr_pairs in used_by_loc.items():
                if len(atom_expr_pairs) == 1:
                    atom, used_by_exprs = atom_expr_pairs[0]
                    used_by.append((atom, loc, used_by_exprs))
                else:
                    # the order matters - we must replace the outer expressions first, then replace the inner
                    # expressions. replacing in the wrong order will lead to expressions that are not replaced in the
                    # end.
                    ordered = []
                    for atom, used_by_exprs in atom_expr_pairs:
                        last_inclusion = len(ordered) - 1  # by default we append at the end of the list
                        for idx in range(len(ordered)):
                            if self._is_expr0_included_in_expr1(ordered[idx][1], used_by_exprs):
                                # this element must be inserted before idx
                                ordered.insert(idx, (atom, used_by_exprs))
                                break
                            if self._is_expr0_included_in_expr1(used_by_exprs, ordered[idx][1]):
                                # this element can be inserted after this element. record the index
                                last_inclusion = idx
                        else:
                            ordered.insert(last_inclusion + 1, (atom, used_by_exprs))

                    for atom, used_by_exprs in ordered:
                        used_by.append((atom, loc, used_by_exprs))

            return ExprNarrowingInfo(True, to_size=next(iter(all_used_sizes)), use_exprs=used_by, phi_vars=phi_vars)

        return ExprNarrowingInfo(False)

    @staticmethod
    def _exprs_from_used_by_exprs(used_by_exprs) -> set[Expression]:
        use_type, expr_tuple = used_by_exprs
        match use_type:
            case "expr" | "mask" | "convert":
                return {expr_tuple[1]} if len(expr_tuple) == 2 else {expr_tuple[0]}
            case "phi-src-expr":
                return {expr_tuple[0]}
            case "binop-convert":
                return {expr_tuple[0], expr_tuple[1]}
            case _:
                return set()

    def _is_expr0_included_in_expr1(self, used_by_exprs0, used_by_exprs1) -> bool:
        # extract expressions
        exprs0 = self._exprs_from_used_by_exprs(used_by_exprs0)
        exprs1 = self._exprs_from_used_by_exprs(used_by_exprs1)

        # test for inclusion
        for expr1 in exprs1:
            walker = HasExprWalker(exprs0)
            walker.walk_expression(expr1)
            if walker.contains_exprs:
                return True
        return False

    def _get_vvar_use_and_exprs_recursive(
        self, initial_atom: atoms.VirtualVariable, rd, block_dict: dict[tuple[int, int | None], Block]
    ) -> tuple[list[tuple[atoms.VirtualVariable, CodeLocation, Expression]], set[VirtualVariable]] | None:
        result = []
        atom_queue = [initial_atom]
        phi_vars = set()
        seen = set()
        while atom_queue:
            atom = atom_queue.pop(0)
            seen.add(atom)

            expr_and_uses = rd.all_vvar_uses[atom.varid]

            for expr, loc in set(expr_and_uses):
                old_block = block_dict.get((loc.block_addr, loc.block_idx), None)
                if old_block is None:
                    # missing a block for whatever reason
                    return None

                block: Block = self.blocks.get(old_block, old_block)
                if loc.stmt_idx >= len(block.statements):
                    # missing a statement for whatever reason
                    return None
                stmt = block.statements[loc.stmt_idx]

                if is_phi_assignment(stmt):
                    phi_vars.add(stmt.dst)
                    new_atom = atoms.VirtualVariable(
                        stmt.dst.varid, stmt.dst.size, stmt.dst.category, oident=stmt.dst.oident
                    )
                    if new_atom not in seen:
                        atom_queue.append(new_atom)
                        seen.add(new_atom)
                else:
                    result.append((atom, loc, expr))
        return result, phi_vars

    def _extract_expression_effective_size(
        self, statement, expr
    ) -> tuple[int | None, tuple[str, tuple[Expression, ...]] | None]:
        """
        Determine the effective size of an expression when it's used.
        """

        walker = NarrowingInfoExtractor(expr)
        walker.walk_statement(statement)
        if not walker.operations:
            if expr is None:
                return None, None
            return expr.size, ("expr", (expr,))

        ops = walker.operations
        first_op = ops[0]
        if isinstance(first_op, BinaryOp) and first_op.op in {"Add", "Sub"}:
            # expr + x
            ops = ops[1:]
            if not ops:
                if expr is None:
                    return None, None
                return expr.size, ("expr", (expr,))
            first_op = ops[0]
        if isinstance(first_op, Convert) and first_op.to_bits >= self.project.arch.byte_width:
            # we need at least one byte!
            return first_op.to_bits // self.project.arch.byte_width, ("convert", (first_op,))
        if isinstance(first_op, BinaryOp):
            second_op = None
            if len(ops) >= 2:
                second_op = ops[1]
            if (
                first_op.op == "And"
                and isinstance(first_op.operands[1], Const)
                and (
                    second_op is None or (isinstance(second_op, BinaryOp) and isinstance(second_op.operands[1], Const))
                )
            ):
                mask = first_op.operands[1].value
                if mask == 0xFF:
                    return 1, ("mask", (first_op, second_op)) if second_op is not None else ("mask", (first_op,))
                if mask == 0xFFFF:
                    return 2, ("mask", (first_op, second_op)) if second_op is not None else ("mask", (first_op,))
                if mask == 0xFFFF_FFFF:
                    return 4, ("mask", (first_op, second_op)) if second_op is not None else ("mask", (first_op,))
            if (
                (first_op.operands[0] is expr or first_op.operands[1] is expr)
                and first_op.op not in {"Shr", "Sar"}
                and isinstance(second_op, Convert)
                and second_op.from_bits == expr.bits
                and second_op.to_bits >= self.project.arch.byte_width  # we need at least one byte!
            ):
                return min(expr.bits, second_op.to_bits) // self.project.arch.byte_width, (
                    "binop-convert",
                    (expr, first_op, second_op),
                )

        if expr is None:
            return None, None
        return expr.size, ("expr", (expr,))

    #
    # Expression folding
    #

    def _fold_exprs(self):
        """
        Fold expressions: Fold assigned expressions that are constant or only used once.
        """

        # propagator
        propagator = self._compute_propagation()
        replacements = propagator.replacements

        # take replacements and rebuild the corresponding blocks
        replacements_by_block_addrs_and_idx = defaultdict(dict)
        for codeloc, reps in replacements.items():
            if reps:
                replacements_by_block_addrs_and_idx[(codeloc.block_addr, codeloc.block_idx)][codeloc] = reps

        if not replacements_by_block_addrs_and_idx:
            return False

        blocks_by_addr_and_idx = {(node.addr, node.idx): node for node in self.func_graph.nodes()}

        if self._stack_arg_offsets:
            insn_addrs_using_stack_args = {ins_addr for ins_addr, _ in self._stack_arg_offsets}
        else:
            insn_addrs_using_stack_args = None

        replaced = False
        for (block_addr, block_idx), reps in replacements_by_block_addrs_and_idx.items():
            block = blocks_by_addr_and_idx[(block_addr, block_idx)]

            # only replace loads if there are stack arguments in this block
            replace_loads: bool = insn_addrs_using_stack_args is not None and bool(
                {stmt.ins_addr for stmt in block.statements}.intersection(insn_addrs_using_stack_args)
            )

            # remove virtual variables in the avoid list
            if self._avoid_vvar_ids:
                filtered_reps = {}
                for loc, rep_dict in reps.items():
                    filtered_reps[loc] = {
                        k: v
                        for k, v in rep_dict.items()
                        if not (isinstance(k, VirtualVariable) and k.varid in self._avoid_vvar_ids)
                    }
                reps = filtered_reps

            r, new_block = BlockSimplifier._replace_and_build(block, reps, gp=self._gp, replace_loads=replace_loads)
            replaced |= r
            self.blocks[block] = new_block

        if replaced:
            # blocks have been rebuilt - expression propagation results are no longer reliable
            self._clear_cache()
        return replaced

    #
    # Partial constant expression propagation
    #

    def _propagate_partial_constant_exprs(self) -> bool:
        """
        Discover virtual variables whose certain consecutive bits are constant and propagate these bits.
        """

        # vvar_zero_bits[varid] = N  ==>  the high N bits of vvar varid are 0s
        vvar_zero_bits: dict[int, int] = {}

        # go over all vvar definitions and find the ones with partial constants
        for block in self.func_graph:
            for stmt in block.statements:
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and isinstance(stmt.src, Convert)
                    and stmt.src.to_bits > stmt.src.from_bits
                ):
                    # this is a conversion from a wider to a narrower type; the top N bits are 0s
                    vvar_zero_bits[stmt.dst.varid] = stmt.src.to_bits - stmt.src.from_bits

        if not vvar_zero_bits:
            return False

        # now replace the uses of these vvars
        addr_and_idx_to_block: dict[tuple[int, int | None], Block] = {}
        for block in self.func_graph:
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        rda = self._compute_reaching_definitions()
        changed = False
        for vvarid, zero_high_bits in vvar_zero_bits.items():
            rewriter = PartialConstantExprRewriter(vvarid, zero_high_bits)
            for _, use_loc in rda.all_vvar_uses[vvarid]:
                assert use_loc.block_addr is not None
                original_block = addr_and_idx_to_block[(use_loc.block_addr, use_loc.block_idx)]
                block = self.blocks.get(original_block, original_block)
                stmt = block.statements[use_loc.stmt_idx]
                new_stmt = rewriter.walk_statement(stmt, block)

                if new_stmt is not None and new_stmt is not stmt:
                    statements = block.statements[::]
                    statements[use_loc.stmt_idx] = new_stmt
                    new_block = block.copy(statements=statements)

                    self.blocks[original_block] = new_block
                    changed = True

        return changed

    #
    # Unifying local variables
    #

    @timethis
    def _unify_local_variables(self) -> bool:
        """
        Find variables that are definitely equivalent and then eliminate unnecessary copies.
        """

        simplified = False

        equivalence = self._compute_equivalence()
        if not equivalence:
            return simplified

        addr_and_idx_to_block: dict[tuple[int, int | None], Block] = {}
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        equivalences: dict[Any, set[Equivalence]] = defaultdict(set)
        atom_by_loc = set()
        for eq in equivalence:
            equivalences[eq.atom1].add(eq)
            atom_by_loc.add((eq.codeloc, eq.atom1))

        # sort keys to ensure a reproducible result
        sorted_loc_and_atoms = sorted(atom_by_loc, key=lambda x: x[0])

        for _, atom in sorted_loc_and_atoms:
            eqs = equivalences[atom]
            if len(eqs) > 1:
                continue

            eq = next(iter(eqs))

            # Acceptable equivalence classes:
            #
            # stack variable == register
            # register variable == register
            # stack variable == Conv(register, M->N)
            # global variable == register
            #
            # Equivalence is generally created at assignment sites. Therefore, eq.atom0 is the definition and
            # eq.atom1 is the use.
            the_def = None
            if (isinstance(eq.atom0, VirtualVariable) and eq.atom0.was_stack) or (
                isinstance(eq.atom0, SimMemoryVariable)
                and not isinstance(eq.atom0, SimStackVariable)
                and isinstance(eq.atom0.addr, int)
            ):
                if isinstance(eq.atom1, VirtualVariable) and eq.atom1.was_reg:
                    # stack_var == register or global_var == register
                    to_replace = eq.atom1
                    to_replace_is_def = False
                elif (
                    isinstance(eq.atom0, VirtualVariable)
                    and eq.atom0.was_stack
                    and isinstance(eq.atom1, VirtualVariable)
                    and eq.atom1.was_parameter
                ):
                    # stack_var == parameter
                    to_replace = eq.atom0
                    to_replace_is_def = True
                elif (
                    isinstance(eq.atom1, Convert)
                    and isinstance(eq.atom1.operand, VirtualVariable)
                    and eq.atom1.operand.was_reg
                ):
                    # stack_var == Conv(register, M->N)
                    to_replace = eq.atom1.operand
                    to_replace_is_def = False
                else:
                    continue

            elif isinstance(eq.atom0, VirtualVariable) and eq.atom0.was_reg:
                if isinstance(eq.atom1, VirtualVariable):
                    if eq.atom1.was_reg or eq.atom1.was_parameter:
                        # register == register
                        if self.project.arch.is_artificial_register(eq.atom0.reg_offset, eq.atom0.size):
                            to_replace = eq.atom0
                            to_replace_is_def = True
                        else:
                            to_replace = eq.atom1
                            to_replace_is_def = False
                    elif eq.atom1.was_stack:
                        # register == stack (but we try to replace the register vvar with the stack vvar)
                        to_replace = eq.atom0
                        to_replace_is_def = True
                    else:
                        continue
                else:
                    continue

            else:
                continue

            assert isinstance(to_replace, VirtualVariable)

            # find the definition of this virtual register
            rd = self._compute_reaching_definitions()
            if to_replace_is_def:
                # find defs
                defs = []
                for def_ in rd.all_definitions:
                    if def_.atom.varid == to_replace.varid:
                        defs.append(def_)
                if len(defs) != 1:
                    continue
                the_def = defs[0]
            else:
                # find uses
                defs = rd.get_uses_by_location(eq.codeloc)
                if len(defs) != 1:
                    # there are multiple defs for this register - we do not support replacing all of them
                    continue
                for def_ in defs:
                    def_: Definition
                    if (
                        isinstance(def_.atom, atoms.VirtualVariable)
                        and def_.atom.category == to_replace.category
                        and def_.atom.oident == to_replace.oident
                    ):
                        # found it!
                        the_def = def_
                        break
            if the_def is None:
                continue
            if the_def.codeloc.context:  # FIXME: now the_def.codeloc.context is never filled in
                # the definition is in a callee function
                continue

            def_eq_rel: DefEqRelation = DefEqRelation.UNKNOWN
            if isinstance(the_def.codeloc, ExternalCodeLocation) or (
                isinstance(eq.atom1, VirtualVariable) and eq.atom1.was_parameter
            ):
                # this is a function argument. we enter a slightly different logic and try to eliminate copies of this
                # argument if
                # (a) the on-stack or in-register copy of it has never been modified in this function
                # (b) the function argument register has never been updated.
                #     TODO: we may loosen requirement (b) once we have real register versioning in AIL.
                defs = [def_ for def_ in rd.all_definitions if def_.codeloc == eq.codeloc]
                all_uses_with_def = None
                replace_with = None
                remove_initial_assignment = None
                def_eq_rel = DefEqRelation.DEF_IS_FUNCARG

                if defs and len(defs) == 1:
                    arg_copy_def = defs[0]
                    if (isinstance(arg_copy_def.atom, atoms.VirtualVariable) and arg_copy_def.atom.was_stack) or (
                        isinstance(arg_copy_def.atom, atoms.VirtualVariable) and arg_copy_def.atom.was_reg
                    ):
                        # found the copied definition (either a stack variable or a register variable)

                        # Make sure there is no other write to this stack location if the copy is a stack variable
                        if (
                            isinstance(arg_copy_def.atom, atoms.VirtualVariable)
                            and arg_copy_def.atom.was_stack
                            and any(
                                (def_ != arg_copy_def and def_.atom.stack_offset == arg_copy_def.atom.stack_offset)
                                for def_ in rd.all_definitions
                                if isinstance(def_.atom, atoms.VirtualVariable) and def_.atom.was_stack
                            )
                        ):
                            continue

                        # Make sure the register is never updated across this function
                        if any(
                            (def_ != the_def and def_.atom == the_def.atom)
                            for def_ in rd.all_definitions
                            if isinstance(def_.atom, atoms.VirtualVariable)
                            and def_.atom.was_reg
                            and rd.get_vvar_uses(def_.atom)
                        ):
                            continue

                        # find all its uses
                        all_arg_copy_var_uses: set[tuple[Any, CodeLocation]] = rd.get_vvar_uses_with_expr(
                            arg_copy_def.atom
                        )
                        all_uses_with_def = set()

                        should_abort = False
                        for use in all_arg_copy_var_uses:
                            used_expr = use[0]
                            if used_expr is not None and used_expr.size != arg_copy_def.size:
                                should_abort = True
                                break
                            all_uses_with_def.add((arg_copy_def, use))
                        if should_abort:
                            continue

                        replace_with = eq.atom1
                        remove_initial_assignment = True

                if all_uses_with_def is None:
                    continue

            else:
                if (
                    eq.codeloc.block_addr == the_def.codeloc.block_addr
                    and eq.codeloc.block_idx == the_def.codeloc.block_idx
                ):
                    # the definition and the eq location are within the same block, and the definition is before
                    # the eq location.
                    if eq.codeloc.stmt_idx < the_def.codeloc.stmt_idx:
                        continue
                    def_eq_rel = DefEqRelation.DEF_EQ_SAME_BLOCK
                else:
                    # the definition is in the predecessor block of the eq
                    eq_block = next(
                        iter(
                            bb
                            for bb in self.func_graph
                            if bb.addr == eq.codeloc.block_addr and bb.idx == eq.codeloc.block_idx
                        )
                    )
                    eq_block_preds = set(self.func_graph.predecessors(eq_block))
                    if not any(
                        pred.addr == the_def.codeloc.block_addr and pred.idx == the_def.codeloc.block_idx
                        for pred in eq_block_preds
                    ):
                        continue
                    def_eq_rel = DefEqRelation.DEF_IN_EQ_PRED_BLOCK

                if isinstance(eq.atom0, VirtualVariable) and eq.atom0.was_stack:
                    # create the replacement expression
                    if isinstance(eq.atom1, VirtualVariable) and eq.atom1.was_parameter:
                        # replacing atom0
                        new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                        replace_with = VirtualVariable(
                            new_idx,
                            eq.atom1.varid,
                            eq.atom1.bits,
                            category=eq.atom1.category,
                            oident=eq.atom1.oident,
                            **eq.atom1.tags,
                        )
                    else:
                        # replacing atom1
                        new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                        replace_with = VirtualVariable(
                            new_idx,
                            eq.atom0.varid,
                            eq.atom0.bits,
                            category=eq.atom0.category,
                            oident=eq.atom0.oident,
                            **eq.atom0.tags,
                        )
                elif isinstance(eq.atom0, SimMemoryVariable) and isinstance(eq.atom0.addr, int):
                    # create the memory loading expression
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with = Load(
                        new_idx,
                        Const(None, None, eq.atom0.addr, self.project.arch.bits),
                        eq.atom0.size,
                        endness=self.project.arch.memory_endness,
                        **eq.atom1.tags,
                    )
                elif isinstance(eq.atom0, VirtualVariable) and eq.atom0.was_reg:
                    if isinstance(eq.atom1, VirtualVariable):
                        if eq.atom1.was_reg:
                            if self.project.arch.is_artificial_register(eq.atom0.reg_offset, eq.atom0.size):
                                replace_with = eq.atom1
                            else:
                                replace_with = eq.atom0
                        elif eq.atom1.was_stack:
                            replace_with = eq.atom1
                        else:
                            raise AngrRuntimeError(f"Unsupported atom1 vvar type {eq.atom1.category}.")
                    else:
                        raise AngrRuntimeError(f"Unsupported atom1 type {type(eq.atom1)}.")
                else:
                    raise AngrRuntimeError(f"Unsupported atom0 type {type(eq.atom0)}.")

                to_replace_def = the_def

                # check: the definition of expression being replaced should not be a phi variable
                if (
                    isinstance(to_replace_def.atom, atoms.VirtualVariable)
                    and to_replace_def.atom.varid in rd.phi_vvar_ids
                ):
                    continue

                # find all uses of this definition
                # we make a copy of the set since we may touch the set (uses) when replacing expressions
                all_uses: set[tuple[Any, CodeLocation]] = set(rd.all_vvar_uses[to_replace_def.atom.varid])
                # make sure none of these uses are phi nodes (depends on more than one def)
                all_uses_with_unique_def = set()
                for expr_and_use in all_uses:
                    used_expr, use_loc = expr_and_use
                    defs_and_exprs = rd.get_uses_by_location(use_loc, exprs=True)
                    filtered_defs = {
                        def_
                        for def_, expr_ in defs_and_exprs
                        if expr_ is not None and used_expr is not None and expr_.varid == used_expr.varid
                    }
                    if len(filtered_defs) == 1:
                        all_uses_with_unique_def.add(expr_and_use)
                    else:
                        # optimization: break early
                        break

                if len(all_uses) != len(all_uses_with_unique_def):
                    # only when all uses are determined by the same definition will we continue with the simplification
                    continue

                # one more check: there can be at most one assignment in all these use locations if the expression is
                # not going to be replaced with a parameter. the assignment can be an Assignment statement, but may also
                # be a Store if it's a global variable (via Load) that we are replacing with

                if not (isinstance(replace_with, VirtualVariable) and replace_with.was_parameter):
                    assignment_ctr = 0
                    all_use_locs = {use_loc for _, use_loc in all_uses}
                    for use_loc in all_use_locs:
                        if use_loc == eq.codeloc:
                            continue
                        assert use_loc.block_addr is not None
                        assert use_loc.stmt_idx is not None
                        block = addr_and_idx_to_block[(use_loc.block_addr, use_loc.block_idx)]
                        stmt = block.statements[use_loc.stmt_idx]
                        if isinstance(stmt, Assignment) or (isinstance(replace_with, Load) and isinstance(stmt, Store)):
                            assignment_ctr += 1
                    if assignment_ctr > 1:
                        continue

                all_uses_with_def = {(to_replace_def, expr_and_use) for expr_and_use in all_uses}

                remove_initial_assignment = False  # expression folding will take care of it

            assert replace_with is not None

            to_replace_used_in_refs = False
            if isinstance(to_replace, VirtualVariable) and to_replace.was_stack:
                # if the variable being replaced has ever been accessed as a reference, we cannot replace it safely
                for _, (_, use_loc) in all_uses_with_def:
                    assert use_loc.block_addr is not None and use_loc.stmt_idx is not None
                    block = addr_and_idx_to_block[(use_loc.block_addr, use_loc.block_idx)]
                    stmt = block.statements[use_loc.stmt_idx]
                    if self._statement_uses_ref_vvar(stmt, to_replace.varid):
                        to_replace_used_in_refs = True
                        break
            if to_replace_used_in_refs:
                continue

            if any(not isinstance(expr_and_use[0], VirtualVariable) for _, expr_and_use in all_uses_with_def):
                # if any of the uses are phi assignments, we skip
                used_in_phi_assignment = False
                for _, expr_and_use in all_uses_with_def:
                    u = expr_and_use[1]
                    assert u.block_addr is not None
                    assert u.stmt_idx is not None
                    block = addr_and_idx_to_block[(u.block_addr, u.block_idx)]
                    stmt = block.statements[u.stmt_idx]
                    if is_phi_assignment(stmt):
                        used_in_phi_assignment = True
                        break
                if used_in_phi_assignment:
                    continue

            # ensure the uses we consider are all after the eq location
            filtered_all_uses_with_def = []
            for def_, expr_and_use in all_uses_with_def:
                u = expr_and_use[1]
                if (
                    u.block_addr == eq.codeloc.block_addr
                    and u.block_idx == eq.codeloc.block_idx
                    and u.stmt_idx < eq.codeloc.stmt_idx
                ):
                    # this use happens before the assignment - ignore it
                    continue
                if def_eq_rel == DefEqRelation.DEF_IN_EQ_PRED_BLOCK and u.block_addr == def_.codeloc.block_addr:
                    # the definition is in a predecessor block of the eq location, so all uses must be in the same
                    # block as the eq location. (technically it can also be in a successor block to the eq location, but
                    # we don't support it yet).
                    continue
                filtered_all_uses_with_def.append((def_, expr_and_use))
            all_uses_with_def = filtered_all_uses_with_def

            if not all_uses_with_def:
                # definitions without uses may simply be our data-flow analysis being incorrect. do not remove them.
                continue

            # TODO: We can only replace all these uses with the stack variable if the stack variable isn't
            # TODO: re-assigned of a new value. Perform this check.

            # replace all uses
            all_uses_replaced = True
            for def_, expr_and_use in all_uses_with_def:
                used_expr, u = expr_and_use

                use_expr_defns = []
                for d in rd.get_uses_by_location(u):
                    if (
                        isinstance(d.atom, atoms.VirtualVariable)
                        and d.atom.was_reg
                        and isinstance(def_.atom, atoms.VirtualVariable)
                        and def_.atom.was_reg
                        and d.atom.reg_offset == def_.atom.reg_offset
                    ) or d.atom == def_.atom:
                        use_expr_defns.append(d)
                # you can never replace a use with dependencies from outside the checked defn
                if len(use_expr_defns) != 1 or next(iter(use_expr_defns)) != def_:
                    if not use_expr_defns:
                        _l.warning("There was no use_expr_defns for %s, this is likely a bug", u)
                    # TODO: can you have multiple definitions which can all be eliminated?
                    all_uses_replaced = False
                    continue

                if u == eq.codeloc:
                    # skip the very initial assignment location
                    continue
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue
                if used_expr is None:
                    all_uses_replaced = False
                    continue

                # ensure the expression that we want to replace with is still up-to-date
                replace_with_original_def = self._find_atom_def_at(replace_with, rd, def_.codeloc)
                if replace_with_original_def is not None and not self._check_atom_last_def(
                    replace_with, u, rd, replace_with_original_def
                ):
                    all_uses_replaced = False
                    continue

                # if there is an updated block, use it
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                replace_with_copy = replace_with.copy()
                if used_expr.size != replace_with_copy.size:
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with_copy = Convert(
                        new_idx,
                        replace_with_copy.bits,
                        used_expr.bits,
                        False,
                        replace_with_copy,
                    )

                r, new_block = self._replace_expr_and_update_block(
                    the_block, u.stmt_idx, stmt, used_expr, replace_with_copy
                )
                if r:
                    self.blocks[old_block] = new_block
                else:
                    # failed to replace a use - we need to keep the initial assignment!
                    all_uses_replaced = False
                simplified |= r

            if all_uses_replaced and remove_initial_assignment:
                # the initial statement can be removed
                self._assignments_to_remove.add(eq.codeloc)

        if simplified:
            self._clear_cache()
        return simplified

    @staticmethod
    def _find_atom_def_at(atom, rd, codeloc: CodeLocation) -> Definition | None:
        if isinstance(atom, Register):
            defs = rd.get_defs(atom, codeloc, OP_BEFORE)
            return next(iter(defs)) if len(defs) == 1 else None

        return None

    @staticmethod
    def _check_atom_last_def(atom, codeloc, rd, the_def) -> bool:
        if isinstance(atom, Register):
            defs = rd.get_defs(atom, codeloc, OP_BEFORE)
            for d in defs:
                if d.codeloc != the_def.codeloc:
                    return False

        return True

    #
    # Folding call expressions
    #

    @staticmethod
    def _is_expr_using_temporaries(expr: Expression) -> bool:
        walker = AILBlockTempCollector()
        walker.walk_expression(expr)
        return len(walker.temps) > 0

    @staticmethod
    def _is_stmt_using_temporaries(stmt: Statement) -> bool:
        walker = AILBlockTempCollector()
        walker.walk_statement(stmt)
        return len(walker.temps) > 0

    @timethis
    def _fold_call_exprs(self) -> bool:
        """
        Fold a call expression (statement) into other statements if the return value of the call expression (statement)
        is only used once, and the use site and the call site belongs to the same supernode.

        Example::

            s1 = func();
            s0 = s1;
            if (s0) ...

        after folding, it will be transformed to::

            s0 = func();
            if (s0) ...

        s0 can be folded into the condition, which means this example can further be transformed to::

            if (func()) ...

        this behavior is controlled by fold_callexprs_into_conditions. This to avoid cases where func() is called more
        than once after simplification and graph structuring where conditions might be duplicated (e.g., in Dream).
        In such cases, the one-use expression folder in RegionSimplifier will perform this transformation.
        """

        # pylint:disable=unreachable
        simplified = False

        equivalence = self._compute_equivalence()
        if not equivalence:
            return simplified

        addr_and_idx_to_block: dict[tuple[int, int | None], Block] = {}
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        def_locations_to_remove: set[CodeLocation] = set()
        updated_use_locations: set[CodeLocation] = set()

        for eq in equivalence:
            # register variable == Call
            if isinstance(eq.atom0, VirtualVariable) and eq.atom0.was_reg:
                if isinstance(eq.atom1, Call):
                    # register variable = Call
                    call: Expression = eq.atom1
                    # call_addr = call.target.value if isinstance(call.target, Const) else None
                elif isinstance(eq.atom1, Convert) and isinstance(eq.atom1.operand, Call):
                    # register variable = Convert(Call)
                    call = eq.atom1
                    # call_addr = call.operand.target.value if isinstance(call.operand.target, Const) else None
                elif eq.is_weakassignment:
                    # variable =w something else
                    call = eq.atom1
                else:
                    continue

                if self._is_expr_using_temporaries(call):
                    continue

                if eq.codeloc in updated_use_locations:
                    # this def is now created by an updated use. the corresponding statement will be updated in the end.
                    # we must rerun Propagator to get an updated definition (and Equivalence)
                    continue

                # find all uses of this virtual register
                rd = self._compute_reaching_definitions()

                the_def: Definition = Definition(
                    atoms.VirtualVariable(
                        eq.atom0.varid, eq.atom0.size, category=eq.atom0.category, oident=eq.atom0.oident
                    ),
                    eq.codeloc,
                )
                assert the_def.codeloc.block_addr is not None
                assert the_def.codeloc.stmt_idx is not None

                all_uses: set[tuple[Any, CodeLocation]] = rd.get_vvar_uses_with_expr(the_def.atom)
                if eq.is_weakassignment:
                    # eliminate the "use" at the weak assignment site
                    all_uses = {use for use in all_uses if use[1] != eq.codeloc}

                if len(all_uses) != 1:
                    continue
                used_expr, u = next(iter(all_uses))
                if used_expr is None:
                    continue
                assert u.block_addr is not None
                assert u.stmt_idx is not None

                if u in def_locations_to_remove:
                    # this use site has been altered by previous folding attempts. the corresponding statement will be
                    # removed in the end. in this case, this Equivalence is probably useless, and we must rerun
                    # Propagator to get an updated Equivalence.
                    continue

                if not self._fold_callexprs_into_conditions:
                    # check the statement and make sure it's not a conditional jump
                    the_block = addr_and_idx_to_block[(u.block_addr, u.block_idx)]
                    if isinstance(the_block.statements[u.stmt_idx], ConditionalJump):
                        continue

                # check if the use and the definition is within the same supernode
                # also we do not allow any calls between the def site and the use site
                if not self._loc_within_superblock(
                    addr_and_idx_to_block[(the_def.codeloc.block_addr, the_def.codeloc.block_idx)],
                    u.block_addr,
                    u.block_idx,
                    terminate_with_calls=True,
                ):
                    continue

                # ensure there are no other calls between the def site and the use site.
                # this is because we do not want to alter the order of calls.
                u_inclusive = CodeLocation(u.block_addr, u.stmt_idx + 1, block_idx=u.block_idx)
                # note that the target statement being a store is fine
                if (
                    has_call_in_between_stmts(
                        self.func_graph,
                        addr_and_idx_to_block,
                        the_def.codeloc,
                        u_inclusive,
                        skip_if_contains_vvar=the_def.atom.varid,
                    )
                    or has_store_stmt_in_between_stmts(self.func_graph, addr_and_idx_to_block, the_def.codeloc, u)
                    or has_load_expr_in_between_stmts(
                        self.func_graph,
                        addr_and_idx_to_block,
                        the_def.codeloc,
                        u_inclusive,
                        skip_if_contains_vvar=the_def.atom.varid,
                    )
                ):
                    continue

                # replace all uses
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue

                # if there is an updated block, use that
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                if isinstance(eq.atom0, VirtualVariable):
                    src = used_expr
                    dst: Expression = call.copy()

                    if isinstance(dst, Call) and dst.ret_expr is not None:
                        dst_bits = dst.ret_expr.bits
                        # clear the ret_expr and fp_ret_expr of dst, then set bits so that it can be used as an
                        # expression
                        dst.ret_expr = None
                        dst.fp_ret_expr = None
                        dst.bits = dst_bits

                    if src.bits != dst.bits and not eq.is_weakassignment:
                        dst = Convert(None, dst.bits, src.bits, False, dst)
                else:
                    continue

                # ensure what we are going to replace only appears once
                expr_ctr = SingleExpressionCounter(stmt, src)
                if expr_ctr.count > 1:
                    continue

                replaced, new_block = self._replace_expr_and_update_block(the_block, u.stmt_idx, stmt, src, dst)

                if replaced:
                    self.blocks[old_block] = new_block
                    # this call has been folded to the use site. we can remove this call.
                    self._calls_to_remove.add(eq.codeloc)
                    simplified = True
                    def_locations_to_remove.add(eq.codeloc)
                    updated_use_locations.add(u)

        # no need to clear the cache at the end of this method
        return simplified

    def _get_super_node_blocks(self, start_node: Block) -> list[Block]:
        lst: list[Block] = [start_node]
        while True:
            b = lst[-1]
            successors = list(self.func_graph.successors(b))
            if len(successors) == 0:
                break
            if len(successors) == 1:
                succ = successors[0]
                # check its predecessors
                succ_predecessors = list(self.func_graph.predecessors(succ))
                if len(succ_predecessors) == 1:
                    if succ in lst:
                        # we are about to form a loop - bad!
                        # example: binary ce1897b492c80bf94083dd783aefb413ab1f6d8d4981adce8420f6669d0cb3e1, block
                        # 0x2976EF7.
                        break
                    lst.append(succ)
                else:
                    break
            else:
                # too many successors
                break
        return lst

    def _loc_within_superblock(
        self, start_node: Block, block_addr: int, block_idx: int | None, terminate_with_calls=False
    ) -> bool:
        b = start_node
        if block_addr == b.addr and block_idx == b.idx:
            return True

        encountered_block_addrs: set[tuple[int, int | None]] = {(b.addr, b.idx)}
        while True:
            if terminate_with_calls and b.statements and isinstance(b.statements[-1], Call):
                return False

            encountered_block_addrs.add((b.addr, b.idx))
            successors = list(self.func_graph.successors(b))
            if len(successors) == 0:
                # did not encounter the block before running out of successors
                return False
            if len(successors) == 1:
                succ = successors[0]
                # check its predecessors
                succ_predecessors = list(self.func_graph.predecessors(succ))
                if len(succ_predecessors) == 1:
                    if (succ.addr, succ.idx) in encountered_block_addrs:
                        # we are about to form a loop - bad!
                        # example: binary ce1897b492c80bf94083dd783aefb413ab1f6d8d4981adce8420f6669d0cb3e1, block
                        # 0x2976EF7.
                        return False
                    if block_addr == succ.addr and block_idx == succ.idx:
                        return True
                    b = succ
                else:
                    return False
            else:
                # too many successors
                return False

    @staticmethod
    def _replace_expr_and_update_block(block, stmt_idx, stmt, src_expr, dst_expr) -> tuple[bool, Block | None]:
        replaced, new_stmt = stmt.replace(src_expr, dst_expr)
        if replaced:
            new_block = block.copy()
            new_block.statements = block.statements[::]
            new_block.statements[stmt_idx] = new_stmt
            return True, new_block

        return False, None

    @timethis
    def _iteratively_remove_dead_assignments(self) -> bool:
        anything_removed = False
        while True:
            r = self._remove_dead_assignments()
            if not r:
                return anything_removed
            self._rebuild_func_graph()
            self._clear_cache()

    @timethis
    def _remove_dead_assignments(self) -> bool:

        # keeping tracking of statements to remove and statements (as well as dead vvars) to keep allows us to handle
        # cases where a statement defines more than one atom, e.g., a call statement that defines both the return
        # value and the floating-point return value.
        stmts_to_remove_per_block: dict[tuple[int, int | None], set[int]] = defaultdict(set)
        stmts_to_keep_per_block: dict[tuple[int, int | None], set[int]] = defaultdict(set)
        dead_vvar_ids: set[int] = self._removed_vvar_ids.copy()
        dead_vvar_codelocs: set[CodeLocation] = set()
        blocks: dict[tuple[int, int | None], Block] = {
            (node.addr, node.idx): self.blocks.get(node, node) for node in self.func_graph.nodes()
        }

        # Find all statements that should be removed
        mask = (1 << self.project.arch.bits) - 1

        rd = self._compute_reaching_definitions()
        stackarg_offsets = (
            {(tpl[1] & mask) for tpl in self._stack_arg_offsets} if self._stack_arg_offsets is not None else None
        )

        while True:
            new_dead_vars_found = False

            # traverse all virtual variable definitions
            for vvar_id, codeloc in rd.all_vvar_definitions.items():
                if vvar_id in dead_vvar_ids:
                    continue
                uses = None
                if vvar_id in self._propagator_dead_vvar_ids:
                    # we are definitely removing this variable if it has no uses
                    uses = rd.all_vvar_uses[vvar_id]

                if uses is None:
                    vvar = rd.varid_to_vvar[vvar_id]
                    def_codeloc = rd.all_vvar_definitions[vvar_id]
                    if isinstance(def_codeloc, ExternalCodeLocation):
                        def_stmt = None
                    else:
                        assert def_codeloc.block_addr is not None and def_codeloc.stmt_idx is not None
                        def_stmt = blocks[(def_codeloc.block_addr, def_codeloc.block_idx)].statements[
                            def_codeloc.stmt_idx
                        ]
                    if is_vvar_eliminatable(vvar, def_stmt):
                        uses = rd.all_vvar_uses[vvar_id]
                    elif vvar.was_stack:
                        if not self._remove_dead_memdefs:
                            if rd.is_phi_vvar_id(vvar_id):
                                # we always remove unused phi variables
                                pass
                            elif vvar_id in self._secondary_stackvars:
                                # secondary stack variables are potentially removable
                                pass
                            elif stackarg_offsets is not None:
                                # we always remove definitions for stack arguments
                                assert vvar.stack_offset is not None
                                if (vvar.stack_offset & mask) not in stackarg_offsets:
                                    continue
                            else:
                                continue
                        uses = rd.all_vvar_uses[vvar_id]

                    else:
                        uses = set()

                # remove uses where vvars are going to be removed
                filtered_uses_count = 0
                for _, loc in uses:
                    if loc in dead_vvar_codelocs and loc.block_addr is not None and loc.stmt_idx is not None:
                        stmt = blocks[(loc.block_addr, loc.block_idx)].statements[loc.stmt_idx]
                        if not self._statement_has_call_exprs(stmt) and not isinstance(stmt, (DirtyStatement, Call)):
                            continue
                    filtered_uses_count += 1

                if filtered_uses_count == 0:
                    new_dead_vars_found = True
                    dead_vvar_ids.add(vvar_id)
                    dead_vvar_codelocs.add(codeloc)
                    if not isinstance(codeloc, ExternalCodeLocation):
                        assert codeloc.block_addr is not None
                        assert codeloc.stmt_idx is not None
                        stmts_to_remove_per_block[(codeloc.block_addr, codeloc.block_idx)].add(codeloc.stmt_idx)
                        stmts_to_keep_per_block[(codeloc.block_addr, codeloc.block_idx)].discard(codeloc.stmt_idx)
                else:
                    if not isinstance(codeloc, ExternalCodeLocation):
                        assert codeloc.block_addr is not None
                        assert codeloc.stmt_idx is not None
                        stmts_to_keep_per_block[(codeloc.block_addr, codeloc.block_idx)].add(codeloc.stmt_idx)

            if not new_dead_vars_found:
                # nothing more is found. let's end the loop
                break

        # find all phi variables that rely on variables that no longer exist
        removed_vvar_ids = self._removed_vvar_ids
        while True:
            new_removed_vvar_ids = set()
            for phi_varid, phi_use_varids in rd.phivarid_to_varids.items():
                if phi_varid not in dead_vvar_ids and any(vvarid in removed_vvar_ids for vvarid in phi_use_varids):
                    loc = rd.all_vvar_definitions[phi_varid]
                    assert loc.block_addr is not None and loc.stmt_idx is not None
                    if loc.stmt_idx not in stmts_to_remove_per_block[(loc.block_addr, loc.block_idx)]:
                        stmts_to_remove_per_block[(loc.block_addr, loc.block_idx)].add(loc.stmt_idx)
                        new_removed_vvar_ids.add(phi_varid)
                        dead_vvar_ids.add(phi_varid)
            if not new_removed_vvar_ids:
                break
            removed_vvar_ids = new_removed_vvar_ids

        # find all phi variables that are only ever used by other phi variables
        redundant_phi_and_dirty_varids = self._find_cyclic_dependent_phis_and_dirty_vvars(rd, dead_vvar_ids)
        for varid in redundant_phi_and_dirty_varids:
            loc = rd.all_vvar_definitions[varid]
            assert loc.block_addr is not None and loc.stmt_idx is not None
            if loc.stmt_idx not in stmts_to_remove_per_block[(loc.block_addr, loc.block_idx)]:
                stmts_to_remove_per_block[(loc.block_addr, loc.block_idx)].add(loc.stmt_idx)
                stmts_to_keep_per_block[(loc.block_addr, loc.block_idx)].discard(loc.stmt_idx)

        for codeloc in self._calls_to_remove | self._assignments_to_remove:
            # this call can be removed. make sure it exists in stmts_to_remove_per_block
            assert codeloc.block_addr is not None and codeloc.stmt_idx is not None
            stmts_to_remove_per_block[codeloc.block_addr, codeloc.block_idx].add(codeloc.stmt_idx)

        simplified = False

        # Remove the statements
        for old_block in self.func_graph.nodes():
            # if there is an updated block, use it
            block = self.blocks.get(old_block, old_block)

            if not isinstance(block, Block):
                continue

            if (block.addr, block.idx) not in stmts_to_remove_per_block:
                continue

            new_statements = []
            stmts_to_remove = stmts_to_remove_per_block[(block.addr, block.idx)]
            stmts_to_keep = stmts_to_keep_per_block[(block.addr, block.idx)]

            if not stmts_to_remove:
                continue

            for idx, stmt in enumerate(block.statements):
                if idx in stmts_to_remove and idx in stmts_to_keep and isinstance(stmt, Call):
                    # this statement declares more than one variable. we should handle it surgically
                    # case 1: stmt.ret_expr and stmt.fp_ret_expr are both set, but one of them is not used
                    if isinstance(stmt.ret_expr, VirtualVariable) and stmt.ret_expr.varid in dead_vvar_ids:
                        stmt = stmt.copy()
                        stmt.ret_expr = None
                        simplified = True
                    if isinstance(stmt.fp_ret_expr, VirtualVariable) and stmt.fp_ret_expr.varid in dead_vvar_ids:
                        stmt = stmt.copy()
                        stmt.fp_ret_expr = None
                        simplified = True

                if idx in stmts_to_remove and idx not in stmts_to_keep and not isinstance(stmt, DirtyStatement):
                    if isinstance(stmt, (Assignment, WeakAssignment, Store)):
                        # Special logic for Assignment and Store statements

                        # if this statement writes to a virtual variable that must be preserved, we ignore it
                        if (
                            isinstance(stmt, Assignment)
                            and isinstance(stmt.dst, VirtualVariable)
                            and stmt.dst.varid in self._avoid_vvar_ids
                        ):
                            new_statements.append(stmt)
                            continue

                        # if this statement triggers a call, it should only be removed if it's in self._calls_to_remove
                        codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.ins_addr, block_idx=block.idx)
                        if codeloc in self._assignments_to_remove:
                            # it should be removed
                            simplified = True
                            self._assignments_to_remove.discard(codeloc)
                            continue

                        if self._statement_has_call_exprs(stmt):
                            if codeloc in self._calls_to_remove:
                                # it has a call and must be removed
                                self._calls_to_remove.discard(codeloc)
                                simplified = True
                                continue
                            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                                # no one is using the returned virtual variable.
                                # now the things are a bit tricky here
                                if isinstance(stmt.src, Call):
                                    # replace this assignment statement with a call statement
                                    stmt = stmt.src
                                elif isinstance(stmt.src, Convert) and isinstance(stmt.src.operand, Call):
                                    # the convert is useless now
                                    stmt = stmt.src.operand
                                else:
                                    # we can't change this stmt at all because it has an expression with Calls inside
                                    pass
                        else:
                            # no calls. remove it
                            simplified = True
                            continue
                    elif isinstance(stmt, Call):
                        codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.ins_addr, block_idx=block.idx)
                        if codeloc in self._calls_to_remove:
                            # this call can be removed
                            self._calls_to_remove.discard(codeloc)
                            simplified = True
                            continue

                        if stmt.ret_expr is not None or stmt.fp_ret_expr is not None:
                            # both the return expr and the fp_ret_expr are not used
                            stmt = stmt.copy()
                            stmt.ret_expr = None
                            stmt.fp_ret_expr = None
                            simplified = True
                    else:
                        # Should not happen!
                        raise NotImplementedError

                new_statements.append(stmt)

            new_block = block.copy()
            new_block.statements = new_statements
            self.blocks[old_block] = new_block

        return simplified

    @staticmethod
    def _get_vvar_used_by(
        vvar_id: int, rd: SRDAModel, blocks_dict: dict[tuple[int, int | None], Block]
    ) -> set[int | None]:
        """
        Get all atoms that use a specified virtual variable. The atoms are in the form of virtual variable ID or None
        (indicating the virtual variable is used by another statement like Store).

        :param vvar_id:     ID of the virtual variable.
        :param rd:          The SRDA model.
        :return:            The set of vvar use atoms.
        """

        used_by: set[int | None] = set()
        for used_vvar, loc in rd.all_vvar_uses[vvar_id]:
            if used_vvar is None:
                # no explicit reference
                used_by.add(None)
            elif loc.block_addr is not None:
                assert loc.stmt_idx is not None
                stmt = blocks_dict[(loc.block_addr, loc.block_idx)].statements[loc.stmt_idx]
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    used_by.add(stmt.dst.varid)
                else:
                    used_by.add(None)
        return used_by

    def _find_cyclic_dependent_phis_and_dirty_vvars(self, rd: SRDAModel, dead_vvar_ids: set[int]) -> set[int]:
        blocks_dict: dict[tuple[int, int | None], Block] = {(bb.addr, bb.idx): bb for bb in self.func_graph}

        # find dirty vvars and vexccall vvars
        dirty_vvar_ids = set()
        for bb in self.func_graph:
            for stmt in bb.statements:
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_reg
                    and isinstance(stmt.src, (DirtyExpression, VEXCCallExpression))
                ):
                    dirty_vvar_ids.add(stmt.dst.varid)

        phi_and_dirty_vvar_ids = (rd.phi_vvar_ids | dirty_vvar_ids).difference(dead_vvar_ids)

        vvar_used_by: dict[int, set[int | None]] = defaultdict(set)
        for var_id in phi_and_dirty_vvar_ids:
            if var_id in rd.phivarid_to_varids:
                for used_by_varid in rd.phivarid_to_varids[var_id]:
                    if used_by_varid in dead_vvar_ids:
                        # this variable no longer exists
                        continue
                    if used_by_varid not in vvar_used_by:
                        vvar_used_by[used_by_varid] |= self._get_vvar_used_by(
                            used_by_varid, rd, blocks_dict
                        ).difference(dead_vvar_ids)
                    vvar_used_by[used_by_varid].add(var_id)  # probably unnecessary
            vvar_used_by[var_id] |= self._get_vvar_used_by(var_id, rd, blocks_dict).difference(dead_vvar_ids)

        g = networkx.DiGraph()
        dummy_vvar_id = -1
        for var_id, used_by_initial in vvar_used_by.items():
            for u in used_by_initial:
                if u is None:
                    # we can't have None in networkx.DiGraph
                    g.add_edge(var_id, dummy_vvar_id)
                else:
                    g.add_edge(var_id, u)

        cyclic_dependent_phi_varids = set()
        for scc in networkx.strongly_connected_components(g):
            if len(scc) == 1:
                continue

            bail = False
            for varid in scc:
                # ensure this vvar is not used by anything else outside the scc (regardless of whether this vvar is a
                # phi variable or not)
                if varid in vvar_used_by and None in vvar_used_by[varid]:
                    bail = True
                    break
                if bail is False:
                    succs = list(g.successors(varid))
                    if any(succ_varid not in scc for succ_varid in succs):
                        bail = True
                        break
            if bail:
                continue

            if all(varid in phi_and_dirty_vvar_ids or rd.varid_to_vvar[varid].was_reg for varid in scc):
                cyclic_dependent_phi_varids |= set(scc)

        return cyclic_dependent_phi_varids

    #
    # Rewriting ccalls
    #

    def _rewrite_ccalls(self):
        rewriter_cls = CCALL_REWRITERS.get(self.project.arch.name, None)
        if rewriter_cls is None:
            return False

        walker = AILBlockWalker()

        class _any_update:
            """
            Dummy class for storing if any result has been updated.
            """

            v = False

        def _handle_expr(
            expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
        ) -> Expression | None:
            if isinstance(expr, VEXCCallExpression):
                rewriter = rewriter_cls(expr, self.project.arch)
                if rewriter.result is not None:
                    _any_update.v = True
                    return rewriter.result
                return None

            return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        blocks_by_addr_and_idx = {(node.addr, node.idx): node for node in self.func_graph.nodes()}
        walker._handle_expr = _handle_expr

        updated = False
        for block in blocks_by_addr_and_idx.values():
            _any_update.v = False
            old_block = block.copy()
            walker.walk(block)
            if _any_update.v:
                self.blocks[old_block] = block
                updated = True

        return updated

    #
    # Util functions
    #

    @staticmethod
    def _statement_has_call_exprs(stmt: Statement) -> bool:
        def _handle_callexpr(expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
            raise HasCallNotification

        walker = AILBlockWalker()
        walker.expr_handlers[Call] = _handle_callexpr
        try:
            walker.walk_statement(stmt)
        except HasCallNotification:
            return True

        return False

    @staticmethod
    def _expression_has_call_exprs(expr: Expression) -> bool:
        def _handle_callexpr(expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
            raise HasCallNotification

        walker = AILBlockWalker()
        walker.expr_handlers[Call] = _handle_callexpr
        try:
            walker.walk_expression(expr)
        except HasCallNotification:
            return True

        return False

    @staticmethod
    def _exprs_contain_vvar(exprs: Iterable[Expression], vvar_ids: set[int]) -> bool:
        def _handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
            if expr.varid in vvar_ids:
                raise HasVVarNotification

        walker = AILBlockWalker()
        walker.expr_handlers[VirtualVariable] = _handle_VirtualVariable

        for expr in exprs:
            try:
                walker.walk_expression(expr)
            except HasVVarNotification:
                return True
        return False

    @staticmethod
    def _statement_uses_ref_vvar(stmt: Statement, vvar_id: int) -> bool:
        def _handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
            if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.varid == vvar_id:
                raise HasRefVVarNotification

        walker = AILBlockWalker()
        walker.expr_handlers[UnaryOp] = _handle_UnaryOp
        try:
            walker.walk_statement(stmt)
        except HasRefVVarNotification:
            return True

        return False


AnalysesHub.register_default("AILSimplifier", AILSimplifier)
