import itertools
from typing import Tuple, List

from ailment.statement import Jump, ConditionalJump, Label, Statement

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from angr.analyses.decompiler.block_similarity import is_similar


class BlockSimilarityMaximizer(OptimizationPass):
    """
    Maximize the similarity between blocks.
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Maximize block similarity"
    DESCRIPTION = __doc__
    REMOVABLE_STMTS = (Jump, ConditionalJump, Label)

    def __init__(self, func, *args, node_idx_start: int = 0, **kwargs):
        super().__init__(func, *args, **kwargs)
        self._node_idx_start = node_idx_start
        self.analyze()

    def _analyze(self, cache=None):
        for b0, b1 in itertools.combinations(self._graph.nodes(), 2):
            # ignore exact copies
            if b0 is b1 or not b0.statements or not b1.statements or is_similar(b0, b1):
                continue

            rmd_stmts = {b0: [], b1: []}
            curr_stmts = {b0: b1.statements.copy(), b1: b1.statements.copy()}
            for blk in (b0, b1):
                for stmt in blk.statements:
                    if isinstance(stmt, self.REMOVABLE_STMTS):
                        rmd_stmts[blk].append((stmt, 0))
                        curr_stmts[blk].remove(stmt)

            if not curr_stmts[b0] and not curr_stmts[b1]:
                continue

            changed = True
            max_iters = (len(curr_stmts[b0]) + len(curr_stmts[b1])) * 2
            curr_iters = 0
            while changed:
                changed = False
                for tgt0, tgt1 in ((b0, b1), (b1, b0)):
                    t0_stmts = curr_stmts[tgt0]
                    t1_stmts = curr_stmts[tgt1]
                    if not t0_stmts or not t1_stmts:
                        break

                    new_stmts = None
                    # maximize up
                    if t0_stmts[0].likes(t1_stmts[0]):
                        rmd_stmts[b0].append((t0_stmts.pop(0), 0))
                        rmd_stmts[b1].append((t1_stmts.pop(0), 0))
                        updated, new_stmts = self._maximize_ends(t0_stmts, t1_stmts, up=True)
                        changed |= updated

                    # maximize down
                    elif t0_stmts[-1].likes(t1_stmts[-1]):
                        rmd_stmts[b0].append((t0_stmts.pop(), -1))
                        rmd_stmts[b1].append((t1_stmts.pop(), -1))
                        updated, new_stmts = self._maximize_ends(t0_stmts, t1_stmts, down=True)
                        changed |= updated

                    curr_iters += 1
                    if curr_iters > max_iters:
                        raise ValueError("We looped more times than should have been possible!")

                    if changed:
                        curr_stmts[b0], curr_stmts[b1] = new_stmts
                        break

    def _maximize_ends(
        self, b0_stmts, b1_stmts, up=False, down=False
    ) -> Tuple[bool, Tuple[List[Statement], List[Statement]]]:
        self._assert_up_or_down(up, down)

    def _move_to_end(self, stmt, stmts, up=False, down=False):
        self._assert_up_or_down(up, down)

    def _assert_up_or_down(self, up, down):
        if up and down:
            raise ValueError("Cannot maximize both up and down")
        if not up and not down:
            raise ValueError("Must maximize either up or down")
