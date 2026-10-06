from __future__ import annotations

import logging

from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.utils.names import is_go_morestack_call
from angr.utils.ail import get_terminal_call

l = logging.getLogger(__name__)


class GoStackCheckRemover(OptimizationPass, CFGTransformationMixin):
    """
    Remove the goroutine stack-growth check every Go function starts with.

    The check compares the stack pointer against g.stackguard0 and, when the frame does not fit, branches to a
    trampoline that spills the register arguments, calls runtime.morestack, reloads the arguments and jumps back to the
    function entry. Neither the compare, the spills nor the restart mean anything at the source level, so the
    trampoline is dropped and the branch leading to it becomes a plain jump; the now-dead compare is cleaned up by later
    stages. runtime.morestackc (//go:systemstack functions) does not return, so its trampoline ends at the call.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Remove the goroutine stack-growth check"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _morestack_call_block(self, block) -> bool:
        call = get_terminal_call(block)
        return call is not None and is_go_morestack_call(self.project, call)

    def _restart_block(self, block):
        """The block after the morestack call that reloads the arguments and jumps back to the entry, if any."""
        succs = list(self._graph.successors(block))
        if len(succs) != 1:
            return None
        restart = succs[0]
        if restart is block or self._graph.in_degree(restart) != 1:
            return None
        if [succ.addr for succ in self._graph.successors(restart)] != [self._func.addr]:
            return None
        return restart

    def _analyze(self, cache=None):
        removed = False
        for block in list(self._graph.nodes):
            if block not in self._graph or not self._morestack_call_block(block):
                continue
            if self._graph.out_degree(block) != 0:
                restart = self._restart_block(block)
                if restart is None:
                    continue
                # dropped directly: remove_block() would also drop the entry if the restart were its only predecessor
                self._graph.remove_node(restart)
                self._block_by_addr_and_idx.pop((restart.addr, restart.idx), None)
            l.debug("Removing morestack block %#x of %s", block.addr, self._func.name)
            if self.remove_block(block):
                removed = True
        if removed:
            self.out_graph = self._graph
