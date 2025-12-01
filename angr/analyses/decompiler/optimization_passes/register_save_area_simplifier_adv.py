# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
import logging


from angr.ailment.statement import Assignment
from angr.ailment.expression import VirtualVariable
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.analyses.decompiler.stack_item import StackItem, StackItemType
from angr.utils.ail import is_phi_assignment
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class RegisterSaveAreaSimplifierAdvanced(OptimizationPass):
    """
    Optimizes away registers that are stored to or restored on the stack space.

    This analysis is more complex than RegisterSaveAreaSimplifier because it handles:
    (1) Registers that are stored in the stack shadow space (sp+N) according to the Windows x64 calling convention.
    (2) Registers that are aliases of sp.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify register save areas (advanced)"
    DESCRIPTION = __doc__.strip()  # type:ignore

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._srda = None

        self.analyze()

    def _check(self):

        self._srda = self.project.analyses.SReachingDefinitions(
            subject=self._func, func_graph=self._graph, func_args=self._arg_vvars
        )
        info = self._find_reg_store_and_restore_locations()
        if not info:
            return False, None

        return True, {"info": info}

    @staticmethod
    def _modify_statement(
        old_block, stmt_idx_: int, updated_blocks_, stack_offset: int | None = None
    ):  # pylint:disable=unused-argument
        if old_block not in updated_blocks_:
            block = old_block.copy()
            updated_blocks_[old_block] = block
        else:
            block = updated_blocks_[old_block]
        block.statements[stmt_idx_] = None

    def _analyze(self, cache=None):

        if cache is None:
            return

        info: list[tuple[int, CodeLocation, int, CodeLocation, int]] = cache["info"]
        updated_blocks = {}

        for _regvar, regvar_loc, _stackvar, stackvar_loc, _ in info:
            # remove storing statements
            old_block = self._get_block(regvar_loc.block_addr, idx=regvar_loc.block_idx)
            assert regvar_loc.stmt_idx is not None
            self._modify_statement(old_block, regvar_loc.stmt_idx, updated_blocks)
            old_block = self._get_block(stackvar_loc.block_addr, idx=stackvar_loc.block_idx)
            assert stackvar_loc.stmt_idx is not None
            self._modify_statement(old_block, stackvar_loc.stmt_idx, updated_blocks)

        for old_block, new_block in updated_blocks.items():
            # remove all statements that are None
            new_block.statements = [stmt for stmt in new_block.statements if stmt is not None]
            # update it
            self._update_block(old_block, new_block)

        if updated_blocks:
            # update stack_items
            for _, _, _, _, stack_offset in info:
                self.stack_items[stack_offset] = StackItem(
                    stack_offset, self.project.arch.bytes, "regs", StackItemType.SAVED_REGS
                )

    def _find_reg_store_and_restore_locations(self) -> list[tuple[int, CodeLocation, int, CodeLocation, int]]:
        results = []

        assert self._srda is not None
        srda_model = self._srda.model
        # find all registers that are defined externally and used exactly once
        saved_vvars: set[tuple[int, CodeLocation]] = set()
        for vvar_id, loc in srda_model.all_vvar_definitions.items():
            if isinstance(loc, ExternalCodeLocation):
                uses = srda_model.all_vvar_uses.get(vvar_id, [])
                if len(uses) == 1:
                    vvar, used_loc = next(iter(uses))
                    if vvar is not None and vvar.was_reg:
                        saved_vvars.add((vvar_id, used_loc))

        if not saved_vvars:
            return results

        # for each candidate, we check to ensure:
        # - it is stored onto the stack (into a stack virtual variable)
        # - the stack virtual variable is only used once and restores the value to the same register
        # - the restore location is in the dominance frontier of the store location
        for vvar_id, used_loc in saved_vvars:
            def_block = self._get_block(used_loc.block_addr, idx=used_loc.block_idx)
            assert def_block is not None and used_loc.stmt_idx is not None
            stmt = def_block.statements[used_loc.stmt_idx]
            if not (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and isinstance(stmt.src, VirtualVariable)
                and stmt.src.was_reg
                and stmt.src.varid == vvar_id
            ):
                continue
            stack_vvar = stmt.dst
            all_stack_vvar_uses = srda_model.all_vvar_uses.get(stack_vvar.varid, [])
            # eliminate the use location if it's a phi statement
            stack_vvar_uses = set()
            for vvar_, loc_ in all_stack_vvar_uses:
                use_block = self._get_block(loc_.block_addr, idx=loc_.block_idx)
                if use_block is None or loc_.stmt_idx is None:
                    continue
                use_stmt = use_block.statements[loc_.stmt_idx]
                if is_phi_assignment(use_stmt):
                    continue
                stack_vvar_uses.add((vvar_, loc_))
            if len(stack_vvar_uses) != 1:
                continue
            _, stack_vvar_use_loc = next(iter(stack_vvar_uses))
            restore_block = self._get_block(stack_vvar_use_loc.block_addr, idx=stack_vvar_use_loc.block_idx)
            assert restore_block is not None
            restore_stmt = restore_block.statements[stack_vvar_use_loc.stmt_idx]

            if not (
                isinstance(restore_stmt, Assignment)
                and isinstance(restore_stmt.src, VirtualVariable)
                and restore_stmt.src.varid == stack_vvar.varid
                and isinstance(restore_stmt.dst, VirtualVariable)
                and restore_stmt.dst.was_reg
                and restore_stmt.dst.reg_offset == stmt.src.reg_offset
            ):
                continue
            # this is the dumb version of the dominance frontier check
            if self._within_dominance_frontier(def_block, restore_block, True, True):
                results.append(
                    (stmt.src.varid, used_loc, stack_vvar.varid, stack_vvar_use_loc, stack_vvar.stack_offset)
                )

        return results

    def _within_dominance_frontier(self, dom_node, node, use_preds: bool, use_succs: bool) -> bool:
        if use_succs:
            # scan forward
            succs = [succ for succ in self._graph.successors(dom_node) if succ is not dom_node]
            if len(succs) == 1:
                succ = succs[0]
                succ_preds = [pred for pred in self._graph.predecessors(succ) if pred is not succ]
                if len(succ_preds) == 0:
                    # the successor has no other predecessors
                    r = self._within_dominance_frontier(succ, node, False, True)
                    if r:
                        return True

                else:
                    # the successor has other predecessors; gotta step back
                    preds = [pred for pred in self._graph.predecessors(node) if pred is not node]
                    if len(preds) == 1 and preds[0] is node:
                        return True
            elif len(succs) == 2:
                return any(succ is node for succ in succs)

        if use_preds:
            # scan backward
            preds = [pred for pred in self._graph.predecessors(dom_node) if pred is not dom_node]
            if len(preds) == 1:
                pred = preds[0]
                pred_succs = [succ for succ in self._graph.successors(pred) if succ is not pred]
                if len(pred_succs) == 0:
                    # the predecessor has no other successors
                    return self._within_dominance_frontier(pred, node, True, False)

                # the predecessor has other successors; gotta step forward
                succs = [succ for succ in self._graph.successors(node) if succ is not node]
                if len(succs) == 1:
                    return self._graph.has_edge(node, succs[0])
            elif len(preds) == 2:
                return False

        return False
