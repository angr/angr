from __future__ import annotations

import logging

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.utils.names import call_target_name, is_go_morestack_name
from angr.rust.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.rust.utils.ail import get_terminal_call

l = logging.getLogger(__name__)


class GoStackCheckRemover(OptimizationPass, CFGTransformationMixin):
    """
    Remove the goroutine stack-growth check every Go function starts with.

    The check compares the stack pointer against g.stackguard0 and, when the frame does not fit, spills the register
    arguments and calls runtime.morestack, which grows the stack and restarts the function. Neither the compare nor the
    spills mean anything at the source level, so the morestack block is dropped and the branch leading to it becomes a
    plain jump; the now-dead compare is cleaned up by later stages.
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

    def _is_morestack_block(self, block) -> bool:
        # runtime.morestack never returns to the caller, so the block is a sink in the function graph
        if self._graph.out_degree(block) != 0:
            return False
        call = get_terminal_call(block)
        if call is None:
            return False
        return is_go_morestack_name(call_target_name(self.project, call))

    def _analyze(self, cache=None):
        removed = False
        for block in list(self._graph.nodes):
            if not self._is_morestack_block(block):
                continue
            l.debug("Removing morestack block %#x of %s", block.addr, self._func.name)
            if self.remove_block(block):
                removed = True
        if removed:
            self.out_graph = self._graph
