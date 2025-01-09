from ailment.statement import Return

from ..mixins.cfg_transformation_mixin import CFGTransformationMixin
from ..mixins.cfa_mixin import CFAMixin
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass

CLEANUP_FUNCTIONS = ("__rust_dealloc", "close", "core::ptr::drop_in_place", "core::ops::drop::Drop::drop")


class CleanupCodeRemover(OptimizationPass, CFGTransformationMixin, CFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove cleanup code"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        CFGTransformationMixin.__init__(self, self._graph)
        CFAMixin.__init__(self, self._graph, self.project)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _get_real_successor(self, blocks_to_replace, block):
        visited = {block}
        while (block := blocks_to_replace[block][1]) not in visited:
            visited.add(block)
            if block not in blocks_to_replace:
                return block
        return None

    def _is_if(self, if_head, if_body):
        if self.num_successors(if_body) == 1:
            if_end = self.get_one_successor(if_body)
            return set(self._graph.successors(if_head)) == {if_body, if_end}
        return False

    def _simplify_if_drop(self):
        blocks_to_replace = {}
        for block in self._graph.nodes:
            if self.match_call(block, CLEANUP_FUNCTIONS):
                predecessors = list(filter(lambda pred: self._is_if(pred, block), self._graph.predecessors(block)))
                successors = list(self._graph.successors(block))
                if len(predecessors) >= 1 and len(successors) == 1:
                    successor = next(iter(successors))
                    blocks_to_replace[block] = (predecessors, successor)
        fixed_blocks_to_replace = {}
        for block, (predecessors, successor) in blocks_to_replace.items():
            new_predecessors = list(filter(lambda pred: pred not in blocks_to_replace, predecessors))
            new_successor = self._get_real_successor(blocks_to_replace, block)
            if len(new_predecessors) and new_successor:
                fixed_blocks_to_replace[block] = (new_predecessors, new_successor)
        for block, (predecessors, successor) in fixed_blocks_to_replace.items():
            for predecessor in predecessors:
                self.replace_jump_target(predecessor, block.addr, block.idx, successor.addr, successor.idx)
            self.remove_block(block)

    def _is_do_while_loop(self, do_while_loop_head, do_while_loop_end):
        return self.num_successors(do_while_loop_end) == 2 and do_while_loop_head in set(
            self._graph.successors(do_while_loop_end)
        )

    def _is_for_loop(self, for_loop_head, for_loop_body_head, for_loop_end):
        return self.num_successors(for_loop_head) == 2 and {for_loop_body_head, for_loop_end} == set(
            self._graph.successors(for_loop_head)
        )

    def _simplify_for_loop_drop(self):
        blocks_to_remove = set()
        jumps_to_replace = {}
        for block in self._graph.nodes:
            if self.match_call(block, CLEANUP_FUNCTIONS):
                if self.num_successors(block) == 1 and self.num_predecessors(block) == 1:
                    do_while_loop_head = self.get_one_predecessor(block)
                    intermediate_block = self.get_one_successor(block)
                    if self.num_successors(intermediate_block) != 1:
                        continue
                    do_while_loop_end = self.get_one_successor(intermediate_block)
                    if (
                        self._is_do_while_loop(do_while_loop_head, do_while_loop_end)
                        and self.num_predecessors(do_while_loop_head) == 2
                    ):
                        predecessors = set(self._graph.predecessors(do_while_loop_head))
                        predecessors.remove(do_while_loop_end)
                        for_loop_body_head = next(iter(predecessors))
                        for_loop_end = set(self._graph.successors(do_while_loop_end))
                        for_loop_end.remove(do_while_loop_head)
                        if len(for_loop_end) == 1:
                            for_loop_end = next(iter(for_loop_end))
                        else:
                            continue
                        for_loop_heads = list(self._graph.predecessors(for_loop_body_head))
                        if all(
                            self._is_for_loop(for_loop_head, for_loop_body_head, for_loop_end)
                            for for_loop_head in for_loop_heads
                        ):
                            blocks_to_remove.update(
                                {for_loop_body_head, do_while_loop_head, block, intermediate_block, do_while_loop_end}
                            )
                            for for_loop_head in for_loop_heads:
                                jumps_to_replace[for_loop_head] = for_loop_end

        for src, dst in jumps_to_replace.items():
            self.replace_jump_target(src, None, None, dst.addr, dst.idx)
        for block in blocks_to_remove:
            self.remove_block(block)

    def _simplify_drop(self):
        blocks_to_remove = set()
        for block in self._graph.nodes:
            if self.match_call(block, CLEANUP_FUNCTIONS):
                if isinstance(block.statements[-1], Return):
                    block.statements[-1].ret_exprs = []
                else:
                    blocks_to_remove.add(block)
        for block in blocks_to_remove:
            if block.addr != self._func.addr:
                self.remove_block(block)

    def _analyze(self, cache=None):
        self._simplify_for_loop_drop()
        self._simplify_if_drop()
        self._simplify_drop()
