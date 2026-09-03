from __future__ import annotations

import logging

from angr.ailment.block import Block
from angr.ailment.expression import Call, Const
from angr.ailment.statement import Assignment, Jump, Label, SideEffectStatement, Store
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.utils.graph import conditional_pred, leads_to, skip_jumps
from angr.go.utils.names import call_target_name
from angr.utils.ail import CallFinder, get_terminal_call
from angr.utils.go_runtime import GO_CHECK_PANIC_NAMES, normalize_go_func_name

l = logging.getLogger(__name__)

_BARRIER_PREFIXES = ("runtime.gcWriteBarrier", "runtime.wbBufFlush")


def is_go_check_panic_name(name: str | None) -> bool:
    return name is not None and normalize_go_func_name(name) in GO_CHECK_PANIC_NAMES


def is_go_write_barrier_name(name: str | None) -> bool:
    return name is not None and normalize_go_func_name(name).startswith(_BARRIER_PREFIXES)


class GoCheckRemover(OptimizationPass, CFGTransformationMixin):
    """
    Remove compiler-inserted checks whose failure path is a panic stub, and GC write-barrier slow paths.

    A bounds/division check branches to a sink block that only spills the operands and calls a ``runtime.panic*``
    helper; the block and the branch to it are dropped, so ``s[i]`` reads as an index expression again. A pointer
    store compiles to ``if runtime.writeBarrier.enabled { gcWriteBarrierN(); buf[...] = ... }`` followed by the
    real store on the join block; the barrier block only records the old and new pointers for the GC, so it and the
    branch are dropped as well.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Remove Go bounds/division checks and write barriers"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        removed = False
        for block in list(self._graph.nodes):
            if block not in self._graph:
                continue
            chain = [block] if self._is_panic_block(block) else self._barrier_chain(block)
            if chain is None:
                continue
            l.debug("Removing check block %#x of %s", block.addr, self._func.name)
            if self._remove(chain):
                removed = True
        if removed:
            self.out_graph = self._graph

    #
    # Shapes
    #

    @staticmethod
    def _calls(block: Block) -> list:
        calls = []
        for stmt in block.statements:
            finder = CallFinder()
            finder.walk_statement(stmt, block)
            if finder.call is not None:
                calls.append(finder.call)
        return calls

    @staticmethod
    def _only_spills(block: Block) -> bool:
        # register/temporary moves and stores that do not target a global
        for stmt in block.statements[:-1]:
            if isinstance(stmt, (Label, Assignment, Jump)):
                continue
            if isinstance(stmt, Store) and not isinstance(stmt.addr, Const):
                continue
            return False
        return True

    def _is_panic_block(self, block: Block) -> bool:
        if self._graph.out_degree(block) != 0:
            return False
        call = get_terminal_call(block)
        if call is None or not is_go_check_panic_name(call_target_name(self.project, call)):
            return False
        return len(self._calls(block)) == 1 and self._only_spills(block)

    @staticmethod
    def _fills_buffer_only(block: Block) -> bool:
        # no global stores, no control flow of its own
        return all(
            isinstance(stmt, (Label, Assignment, Jump, Store, Call, SideEffectStatement))
            and not (isinstance(stmt, Store) and isinstance(stmt.addr, Const))
            for stmt in block.statements
        )

    def _barrier_chain(self, block: Block) -> list[Block] | None:
        """The blocks of a write-barrier slow path starting at ``block``: the call, then the buffer fills."""
        calls = self._calls(block)
        if len(calls) != 1 or not is_go_write_barrier_name(call_target_name(self.project, calls[0])):
            return None
        if not self._fills_buffer_only(block):
            return None
        chain = [block]
        succs = list(self._graph.successors(block))
        if not succs:
            # the CFG treated the barrier stub as non-returning
            return chain
        # the call ends its block; the buffer stores follow in single-entry blocks up to the join
        while (
            len(succs) == 1
            and self._graph.in_degree(succs[0]) == 1
            and self._fills_buffer_only(succs[0])
            and not self._calls(succs[0])
        ):
            chain.append(succs[0])
            succs = list(self._graph.successors(succs[0]))
        if len(succs) != 1:
            return None
        cond = conditional_pred(self._graph, block)
        if cond is None:
            return None
        others = [s for s in self._graph.successors(cond) if not leads_to(self._graph, s, block)]
        if len(others) == 1 and skip_jumps(self._graph, others[0]) is skip_jumps(self._graph, succs[0]):
            return chain
        return None

    #
    # Removal
    #

    def _remove(self, chain: list[Block]) -> bool:
        preds = list(self._graph.predecessors(chain[0]))
        for block in chain:
            if not self.remove_block(block):
                return False
        for pred in preds:
            self._prune_dead_end(pred)
        return True

    def _prune_dead_end(self, block: Block) -> None:
        # a trampoline whose jump was just removed has nothing left; take its predecessors' branch away too
        while (
            block in self._graph
            and self._graph.out_degree(block) == 0
            and all(isinstance(stmt, Label) for stmt in block.statements)
        ):
            preds = list(self._graph.predecessors(block))
            if not self.remove_block(block) or len(preds) != 1:
                return
            block = preds[0]
