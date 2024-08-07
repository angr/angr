from collections import defaultdict

from .base import TransformationPass
from ..stats import Stats
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from .utils import *


DECONSTRUCTION_FUNCTIONS = ("__rust_dealloc", "close", "core::ptr::drop_in_place")


class EpilogueSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove unnecessary code in Rust AIL CFG"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _is_potential_junk_block(self, block):
        for stmt in reversed(block.statements):
            if any(
                pred.statements
                and isinstance(pred.statements[-1], Call)
                and not self.match_call(pred, DECONSTRUCTION_FUNCTIONS)
                for pred in self._graph.predecessors(block)
            ):
                return False
            if (
                isinstance(stmt, Label)
                or isinstance(stmt, Jump)
                or isinstance(stmt, ConditionalJump)
                or isinstance(stmt, Assignment)
                or isinstance(stmt, Return)
            ):
                continue
            elif self.match_call(stmt, DECONSTRUCTION_FUNCTIONS):
                continue
            else:
                return False
        return True

    def _find_epilogue_blocks(self, return_blocks):
        all_epilogue_blocks = set()
        queue = list(return_blocks)
        visited = set()
        while len(queue):
            block = queue.pop(0)
            if block in visited:
                continue
            visited.add(block)
            if self._is_potential_junk_block(block):
                all_epilogue_blocks.add(block)
                for pred in self._graph.predecessors(block):
                    queue.append(pred)
        updated = True
        while updated:
            updated = False
            for block in set(all_epilogue_blocks):
                if any(succ not in all_epilogue_blocks for succ in self._graph.successors(block)):
                    all_epilogue_blocks.remove(block)
                    updated = True

        epilogue_blocks = defaultdict(set)
        for return_block in return_blocks:
            queue = [return_block]
            visited = set()

            while len(queue):
                block = queue.pop(0)
                if block in visited:
                    continue
                visited.add(block)
                epilogue_blocks[return_block].add(block)
                for pred in self._graph.predecessors(block):
                    succs = self._graph.successors(pred)
                    if pred in all_epilogue_blocks and succs and all(b in all_epilogue_blocks for b in succs):
                        queue.append(pred)
        return epilogue_blocks

    def _simlify_epilogue(self):
        return_blocks = set()

        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                return_blocks.add(block)

        epilogue_blocks = self._find_epilogue_blocks(return_blocks)

        redirected = set()

        for block in self._graph.nodes:
            for return_block, bad_blocks in epilogue_blocks.items():
                if block not in bad_blocks and block.statements:
                    succs = list(self._graph.successors(block))
                    if succs and all(succ in bad_blocks for succ in succs):
                        self.replace_jump_target(block, None, return_block)
                        redirected.add(block)
                    else:
                        for succ in list(self._graph.successors(block)):
                            if succ in bad_blocks:
                                self.replace_jump_target(block, succ, return_block)
                                redirected.add(block)

        Stats.redirected_blocks += len(redirected)

        for return_block, bad_blocks in epilogue_blocks.items():
            for bad_block in bad_blocks:
                if bad_block not in return_blocks:
                    Stats.removed_epilogue_blocks += 1
                    self._graph.remove_node(bad_block)

    def _analyze(self, cache=None):
        self._simlify_epilogue()
