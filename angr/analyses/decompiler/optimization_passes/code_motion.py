import itertools
from typing import Tuple, List, Optional, Dict
import logging

from ailment import Block
from ailment.statement import Jump, ConditionalJump, Statement, DirtyStatement
import networkx as nx

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.block_similarity import is_similar, index_of_similar_stmts
from angr.analyses.decompiler.block_io_finder import BlockIOFinder
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

    Current limitations (for very conservative operations):
    - moving statements above conditional jumps is not supported
    - only immediate children and parents are considered for moving statements
    - when moving statements down, a block is only considered if already has a matching statement at the end
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Merge common statements in sub-scopes"
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    DESCRIPTION = __doc__

    def __init__(self, func, *args, max_iters=10, node_idx_start: int = 0, **kwargs):
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
            updates, updated_blocks = self._move_common_code(super_graph)
            if updates:
                critical_fail = self.update_graph_with_super_edits(graph_copy, super_graph, updated_blocks)
                if critical_fail:
                    _l.error("Critical failure in updating graph with super edits, aborting")
                    break
                graph_changed = True

        if graph_changed:
            self.out_graph = add_labels(graph_copy)

    @staticmethod
    def update_graph_with_super_edits(
        original_graph: nx.DiGraph, super_graph: nx.DiGraph, updated_blocks: Dict[Block, Block]
    ) -> bool:
        """
        This function updates an graph when doing block edits on a supergraph version of that same graph.
        The updated blocks must be provided as a dictionary where the keys are original block in the supergraph and
        the values are the new blocks that should replace them.

        The supergraph MUST be generated using the to_ail_supergraph function, since it stores the original nodes
        each super node represents. This is necessary to update the original graph with the new super nodes.
        """
        og_to_super = {}
        for old_super, new_super in updated_blocks.items():
            original_blocks = super_graph.nodes[old_super]["original_nodes"]
            for original_block in original_blocks:
                og_to_super[original_block] = new_super

        for old_super, new_super in updated_blocks.items():
            original_blocks = super_graph.nodes[old_super]["original_nodes"]
            first_node_preds = []
            last_node_preds = []
            for original_block in original_blocks:
                if original_block not in original_graph.nodes:
                    return True

                external_preds = [
                    pred for pred in original_graph.predecessors(original_block) if pred not in original_blocks
                ]
                external_succs = [
                    succ for succ in original_graph.successors(original_block) if succ not in original_blocks
                ]
                if external_preds:
                    first_node_preds = external_preds
                if external_succs:
                    last_node_preds = external_succs

            original_graph.remove_nodes_from(original_blocks)
            original_graph.add_node(new_super)
            for pred in first_node_preds:
                original_graph.add_edge(og_to_super[pred] if pred in og_to_super else pred, new_super)
            for succ in last_node_preds:
                original_graph.add_edge(new_super, og_to_super[succ] if succ in og_to_super else succ)

        return False

    def _move_common_code(self, graph) -> Tuple[bool, Optional[Dict[Block, Block]]]:
        """
        Does two things at a high level:
        1. rearrange code in blocks to maximize the number of similar statements at the end of the block
        2. move common code out of blocks

        To understand the limitations of this approach, see the TODOs.
        """
        # TODO: how can you handle an odd-numbered switch case? or many blocks with the same child?
        for b0, b1 in itertools.combinations(graph.nodes, 2):
            if (
                b0 is b1
                or not b0.statements
                or not b1.statements
                or any(isinstance(stmt, DirtyStatement) for stmt in b0.statements + b1.statements)
                or is_similar(b0, b1)
            ):
                continue

            # TODO: add support for moving code to a shared parent block, which requires that we figure out how to
            #   move code above conditional jumps. Hard since you need to know if the condition executes code.
            # TODO: also, how do you deal with short-circuiting, which is a region parent, not just a block?

            # target any blocks that have a shared child and move common code to the child
            b0_succs = list(graph.successors(b0))
            b1_succs = list(graph.successors(b1))
            if (len(b0_succs) == len(b1_succs) == 1) and b0_succs[0] == b1_succs[0]:
                common_succ = b0_succs[0]
                common_succ_preds = list(graph.predecessors(common_succ))
                # you can only safely move code to a child if all the common_succ's preds are the ones
                # we are moving code from (2 nodes).
                if all(csp in (b0, b1) for csp in common_succ_preds):
                    success, updated_blocks = self._move_common_code_to_child(b0, b1, common_succ)
                    if success:
                        return True, updated_blocks

        return False, None

    def _move_common_code_to_parent(self, b0: Block, b1: Block, parent: Block):
        # TODO: this function does not work yet because you need to figure out if you can move a stmt above
        #   a conditional jump, which requires cross-block analysis
        changed, new_b0, new_b1 = self._make_stmts_end_similar(b0, b1, up=True)
        if not changed:
            return False, None

        # move the longest common suffix to the parent
        new_b0_stmts = new_b0.statements
        new_b1_stmts = new_b1.statements
        common_len = 0
        for idx, new_b0_stmt in enumerate(new_b0_stmts):
            if not new_b0_stmt.likes(new_b1_stmts[idx]):
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

        return True, {b0: new_b0, b1: new_b1, parent: new_parent}

    def _move_common_code_to_child(self, b0: Block, b1: Block, child: Block):
        changed, new_b0, new_b1 = self._make_stmts_end_similar(b0, b1, down=True)
        if not changed:
            return False, None

        # move the longest common suffix to the parent
        new_b0_stmts = new_b0.statements
        new_b1_stmts = new_b1.statements
        common_len = 0
        # start from the -1 index and go backwards
        for idx in range(-1, -(min(len(new_b0_stmts), len(new_b1_stmts))) - 1, -1):
            if not new_b0_stmts[idx].likes(new_b1_stmts[idx]):
                break
            common_len += 1

        if not common_len:
            raise ValueError("No common statements found, this is unexpected")

        common_stmts = [new_b0_stmts.pop() for _ in range(common_len)]
        for _ in range(common_len):
            new_b1_stmts.pop()

        child_stmts = child.statements.copy() or []
        new_child = child.copy(statements=common_stmts[::-1] + child_stmts)

        return True, {b0: new_b0, b1: new_b1, child: new_child}

    def _make_stmts_end_similar(
        self, b0: Block, b1: Block, up=False, down=False
    ) -> Tuple[bool, Optional[Block], Optional[Block]]:
        """
        This algorithm attempts to rearrange two blocks to have the longest common sequence of statements
        at either ends of the blocks. It is flawed in that it currently only attempts to do this rearrangement
        if the blocks have at least one matching statement at the end.

        This algorithm iteratively removes statements from the ends of the blocks and then attempts to match
        the ends of the blocks. It will only do this if one of the two ends has a matching statement in the other.
        """
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
                    while t0_stmts and t1_stmts:
                        if t0_stmts[0].likes(t1_stmts[0]):
                            matched_stmts[b0].append((t0_stmts.pop(0), 0))
                            matched_stmts[b1].append((t1_stmts.pop(0), 0))
                            try_next_swap = True
                        else:
                            break
                    if not t0_stmts or not t1_stmts:
                        break
                elif down:
                    # maximize down
                    while t0_stmts and t1_stmts:
                        if t0_stmts[-1].likes(t1_stmts[-1]):
                            matched_stmts[b0].append((t0_stmts.pop(), -1))
                            matched_stmts[b1].append((t1_stmts.pop(), -1))
                            try_next_swap = True
                        else:
                            break
                    if not t0_stmts or not t1_stmts:
                        break

                if not try_next_swap:
                    continue

                stmts_updated = True
                swap_occurred, new_stmts = self._maximize_ends(t0_stmts, t1_stmts, up=up, down=down)
                if swap_occurred:
                    changed = True
                    curr_stmts[b0], curr_stmts[b1] = new_stmts
                    break

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
                if idx == -1:
                    new_stmts.append(stmt)
                else:
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
        return (success and (b1_stmts != new_b1_stmts)), (b0_stmts, new_b1_stmts)

    def _move_to_end(self, stmt, stmts, up=False, down=False) -> Tuple[bool, List[Statement]]:
        """
        Attempts to move a stmt to either the top or the bottom of stmts.
        It does this by attempting to swap, 1 by 1, in either direction it is targeting.
        """
        new_stmts = stmts.copy()
        stmt_idx = new_stmts.index(stmt)
        swap_offset = -1 if up else 1
        swap_order = range(stmt_idx + 1, len(new_stmts)) if down else range(stmt_idx - 1, -1, -1)
        io_finder = BlockIOFinder(new_stmts, self.project)
        for swap_pos in swap_order:
            src_stmt = new_stmts[stmt_idx]
            if io_finder.can_swap(src_stmt, new_stmts, 1 if down else -1):
                new_stmts[stmt_idx], new_stmts[swap_pos] = new_stmts[swap_pos], new_stmts[stmt_idx]
                stmt_idx += swap_offset
            else:
                return False, stmts

        return True, new_stmts

    @staticmethod
    def _assert_up_or_down(up, down):
        if up and down:
            raise ValueError("Cannot maximize both up and down")
        if not up and not down:
            raise ValueError("Must maximize either up or down")
