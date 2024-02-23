import itertools
from typing import Tuple, List, Optional
import logging

from ailment import Block
from ailment.statement import Jump, ConditionalJump, Statement
import networkx as nx

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.block_similarity import is_similar, index_of_similar_stmts
from angr.analyses.decompiler.ailblock_io_finder import AILStmtIOFinder
from angr.analyses.decompiler.utils import to_ail_supergraph, remove_labels, add_labels

_l = logging.getLogger(name=__name__)


class CodeMotionOptimization(OptimizationPass):
    """
    Moves common statements out of blocks that share the same predecessors or the same
    successors. This is done to reduce the number of statements in a block and to make the
    blocks more similar to each other.

    As an example:
    if (x) {
        b = 2;
        a = 1;
        c = 3;
    } else {
        b = 2;
        c = 3;
    }

    Will be turned into:
    if (x) {
        a = 1;
    }
    b = 2;
    c = 3;

    Current limitations (conservative):
    - moving statements above conditional jumps is not supported
    - only immediate children and parents are considered for moving statements
    - when moving statements down, a block is only considered if already has a matching statement at the end
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Move common statements out of blocks"
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    DESCRIPTION = __doc__

    def __init__(self, func, max_iters=10, *args, node_idx_start: int = 0, **kwargs):
        super().__init__(func, *args, **kwargs)
        self._node_idx_start = node_idx_start
        self._max_optimization_runs = max_iters
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        optimization_runs = 0
        graph_copy = remove_labels(nx.DiGraph(self._graph))
        updates = True
        graph_changed = False
        while optimization_runs < self._max_optimization_runs and updates:
            optimization_runs += 1
            super_graph = to_ail_supergraph(graph_copy)
            updates, updated_blocks = self._move_common_code(graph_copy)
            if updates:
                graph_copy = self.update_original_blocks_with_supers(graph_copy, super_graph, updated_blocks)

        if graph_changed:
            self._graph = add_labels(graph_copy)

    def update_original_blocks_with_supers(
        self, original_graph, super_graph, updated_blocks: List[Block]
    ) -> nx.DiGraph:
        # TODO: MUST COMPLETE THIS
        return original_graph

    def _move_common_code(self, graph) -> Tuple[bool, Optional[List[Block]]]:
        """
        Returns a list of blocks that have been updated in some way.
        """
        # TODO: how can you handle an odd-numbered switch case?
        for b0, b1 in itertools.combinations(graph.nodes, 2):
            # ignore exact copies
            if b0 is b1 or not b0.statements or not b1.statements or is_similar(b0, b1):
                continue

            # TODO: re-add this when you figure out how to handle the conditional jump rda, see move code
            # TODO: also, how do you deal with short-circuiting?
            # first, target any blocks with one (and only) parent that is shared
            # b0_preds = list(graph.predecessors(b0))
            # b1_preds = list(graph.predecessors(b1))
            # if (len(b0_preds) == len(b1_preds) == 1) and b0_preds[0] == b1_preds[0]:
            #    success, updated_blocks = self._move_common_code_up(b0, b1, b0_preds[0])
            #    if success:
            #        return True, updated_blocks

            # second, target any blocks with one (and only) child that is shared
            b0_succs = list(graph.successors(b0))
            b1_succs = list(graph.successors(b1))
            if (len(b0_succs) == len(b1_succs) == 1) and b0_succs[0] == b1_succs[0]:
                success, updated_blocks = self._move_common_code_down(b0, b1, b0_succs[0])
                if success:
                    return True, updated_blocks

        return False, None

    def _move_common_code_up(self, b0: Block, b1: Block, parent: Block):
        # TODO: this function does not work yet because you need to figure out if you can move a stmt above
        #   a conditional jump, which requires cross-block analysis
        changed, new_b0, new_b1 = self._make_stmts_end_similar(b0, b1, up=True)
        if not changed:
            return False, None

        # move the longest common suffix to the parent
        new_b0_stmts = new_b0.statements
        new_b1_stmts = new_b1.statements
        common_len = 0
        for idx in range(len(new_b0_stmts)):
            if not new_b0_stmts[idx].likes(new_b1_stmts[idx]):
                break
            common_len += 1

        if not common_len:
            raise ValueError("No common statements found, this is unexpected")

        common_stmts = [new_b0_stmts.pop(0) for _ in range(common_len)]
        for _ in range(common_len):
            new_b1_stmts.pop(0)

        parent_stmts = parent.statements.copy() or []
        if isinstance(parent_stmts[-1], (ConditionalJump, Jump)):
            parent_stmts = parent_stmts[:-1] + common_stmts + [parent_stmts[-1]]
        new_parent = parent.copy(statements=parent_stmts)

        return True, [new_b0, new_b1, new_parent]

    def _move_common_code_down(self, b0: Block, b1: Block, child: Block):
        changed, new_b0, new_b1 = self._make_stmts_end_similar(b0, b1, down=True)
        if not changed:
            return False, None

        # move the longest common suffix to the parent
        new_b0_stmts = new_b0.statements
        new_b1_stmts = new_b1.statements
        common_len = 0
        # start from the end and move towards the beginning
        for idx in range(max(len(new_b0_stmts), len(new_b1_stmts)) - 1, -1, -1):
            if not new_b0_stmts[idx].likes(new_b1_stmts[idx]):
                break
            common_len += 1

        if not common_len:
            raise ValueError("No common statements found, this is unexpected")

        common_stmts = [new_b0_stmts.pop() for _ in range(common_len)]
        for _ in range(common_len):
            new_b1_stmts.pop()

        child_stmts = child.statements.copy() or []
        new_child = child.copy(statements=common_stmts + child_stmts)

        return True, [new_b0, new_b1, new_child]

    def _make_stmts_end_similar(
        self, b0: Block, b1: Block, up=False, down=False
    ) -> Tuple[bool, Optional[Block], Optional[Block]]:
        self._assert_up_or_down(up, down)
        # copy the statements while filtering out statements that are not needed in the specific
        # movement case (up or down)
        curr_stmts = {}
        for blk in (b0, b1):
            new_stmts = blk.statements.copy()
            if down:
                last_stmt = new_stmts[-1]
                if isinstance(last_stmt, Jump):
                    new_stmts.pop()
                elif isinstance(last_stmt, ConditionalJump):
                    _l.warning("ConditionalJump at the end of block %s, this should never happen!", blk)
                    return False, None, None

            curr_stmts[blk] = new_stmts
        if not curr_stmts[b0] or not curr_stmts[b1]:
            return False, None, None

        # attempt to do a swapping algorithm to maximize the number of similar statements at the end
        changed = True
        stmts_updated = False
        matched_stmts = {b0: [], b1: []}
        max_iters = len(curr_stmts[b0]) * len(curr_stmts[b1])
        curr_iters = 0
        while changed and curr_iters < max_iters:
            changed = False
            try_next_swap = False
            for tgt0, tgt1 in ((b0, b1), (b1, b0)):
                t0_stmts = curr_stmts[tgt0]
                t1_stmts = curr_stmts[tgt1]
                if not t0_stmts or not t1_stmts:
                    break

                if up:
                    # maximize up
                    if t0_stmts[0].likes(t1_stmts[0]):
                        matched_stmts[b0].append((t0_stmts.pop(0), 0))
                        matched_stmts[b1].append((t1_stmts.pop(0), 0))
                        if not t0_stmts or not t1_stmts:
                            break
                        try_next_swap = True
                elif down:
                    # maximize down
                    if t0_stmts[-1].likes(t1_stmts[-1]):
                        matched_stmts[b0].append((t0_stmts.pop(), -1))
                        matched_stmts[b1].append((t1_stmts.pop(), -1))
                        if not t0_stmts or not t1_stmts:
                            break
                        try_next_swap = True

                if not try_next_swap:
                    continue

                swap_occurred, new_stmts = self._maximize_ends(t0_stmts, t1_stmts, up=up, down=down)
                if swap_occurred:
                    changed = True
                    stmts_updated = True
                    curr_stmts[b0], curr_stmts[b1] = new_stmts
                    break
                else:
                    try_next_swap = True

            curr_iters += 1
            if curr_iters > max_iters:
                raise ValueError("Exceeded max iterations, likely stuck in infinite loop")

        # did any changes occur?
        if not stmts_updated:
            return False, None, None

        # reconstruct the blocks and return them
        new_blks = {}
        for blk in (b0, b1):
            new_stmts = curr_stmts[blk]
            for stmt, idx in matched_stmts[blk][::-1]:
                new_stmts.insert(idx, stmt)

            new_blks[blk] = blk.copy(statements=new_stmts)

        return True, new_blks[b0], new_blks[b1]

    def _maximize_ends(
        self, b0_stmts, b1_stmts, up=False, down=False
    ) -> Tuple[bool, Tuple[List[Statement], List[Statement]]]:
        self._assert_up_or_down(up, down)

        similar_stmt = b0_stmts[0] if up else b0_stmts[-1]
        idx_similar = index_of_similar_stmts([similar_stmt], b1_stmts)
        if idx_similar is None or len(b1_stmts) == 1:
            return False, (b0_stmts, b1_stmts)

        target_stmt = b1_stmts[idx_similar]
        success, new_b1_stmts = self._move_to_end(target_stmt, b1_stmts, up=up, down=down)
        changes = new_b1_stmts != b1_stmts
        return changes, (b0_stmts, new_b1_stmts)

    def _move_to_end(self, stmt, stmts, up=False, down=False) -> Tuple[bool, List[Statement]]:
        new_stmts = stmts.copy()
        stmt_idx = new_stmts.index(stmt)
        swap_offset = -1 if up else 1
        swap_order = range(stmt_idx + 1, len(new_stmts)) if down else range(stmt_idx - 1, -1, -1)
        io_finder = AILStmtIOFinder(new_stmts, self.project)
        for swap_pos in swap_order:
            src_stmt = new_stmts[stmt_idx]
            dst_stmt = new_stmts[swap_pos]
            if self._can_swap(src_stmt, dst_stmt, io_finder, up=up, down=down):
                new_stmts[stmt_idx], new_stmts[swap_pos] = new_stmts[swap_pos], new_stmts[stmt_idx]
                stmt_idx += swap_offset
            else:
                return False, stmts

        return True, new_stmts

    def _can_swap(
        self, src_stmt: Statement, dst_stmt: List[Statement], io_finder: AILStmtIOFinder, up=False, down=False
    ):
        # TODO: MUST COMPLETE THIS, requires finishing the AILStmtIOFinder
        pass

    def _assert_up_or_down(self, up, down):
        if up and down:
            raise ValueError("Cannot maximize both up and down")
        if not up and not down:
            raise ValueError("Must maximize either up or down")
