# pylint:disable=unnecessary-pass
import logging
from typing import Tuple, List

from ailment import Block
from ailment.statement import ConditionalJump, Return

from ....utils.graph import subgraph_between_nodes
from ..utils import remove_labels, to_ail_supergraph, update_labels
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(__name__)


class ReturnDeduplicator(OptimizationPass):
    """
    Transforms:
    - if (cond) { ... return x; } return x;

    into:
    - if (cond) { ... } return x;

    TODO: its possible that this can be expanded to all rets that are equivalent. Testing needed.
    """

    ARCHES = ["X86", "AMD64", "ARMEL", "ARMHF", "ARMCortexM", "MIPS32", "MIPS64"]
    PLATFORMS = ["windows", "linux", "cgc"]
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Deduplicates return statements that may have been duplicated"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        graph_updated = False
        if_ret_regions = self._find_if_ret_regions()
        for region_head, true_child, false_child, super_true, super_false in if_ret_regions:
            graph_updated |= self._fix_if_ret_region(region_head, true_child, false_child, super_true, super_false)

        if graph_updated:
            self.out_graph = update_labels(self._graph)

    def _fix_if_ret_region(self, region_head, true_child, false_child, super_true, super_false):
        """
              A
            /  \
           C    B

        =>
              A
            /  \
           C    B
           \\   /
             D


        The super blocks of the true and falst child will be used as the replacement for the true and false child
        to assure correctness.
        """

        if any(node not in self._graph for node in (region_head, true_child, false_child)):
            return False

        # destroy all but the head in the region
        for child in (true_child, false_child):
            region_nodes = subgraph_between_nodes(self._graph, region_head, [child], include_frontier=True)
            for node in region_nodes:
                if node is region_head:
                    continue

                self._remove_block(node)

        # replace the head with a new if-stmt corrected block
        if_stmt = region_head.statements[-1]
        if_stmt.true_target.value = super_true.addr
        if_stmt.false_target.value = super_false.addr
        new_head = region_head.copy()
        new_head.statements[-1] = if_stmt
        # assures that preds still point to this block
        self._update_block(region_head, new_head)

        # create new children
        new_children = []
        for child in (super_true, super_false):
            new_child = child.copy()
            new_child.statements = new_child.statements[:-1]
            new_children.append(new_child)

        # create a new return block
        true_ret: Return = true_child.statements[-1]
        false_ret: Return = false_child.statements[-1]
        ret_stmt = true_ret if true_ret.ins_addr > false_ret.ins_addr else false_ret
        # XXX: this size is wrong, but unknown how to fix
        ret_block = Block(self.new_block_addr(), 1, [ret_stmt])

        # head -> [children]
        self._graph.add_edges_from([(new_head, new_children[0]), (new_head, new_children[1])])
        # [children] -> ret
        self._graph.add_edges_from([(new_children[0], ret_block), (new_children[1], ret_block)])

        return True

    def _find_if_ret_regions(self):
        """
        We are looking for patterns in the graph that match the following schema:
        A: if (cond) goto B else goto C;
        B: ...; return x;
        C: ...; return x;
        """

        # find all the if-stmt blocks in a graph with no single successor edges
        super_graph = to_ail_supergraph(remove_labels(self._graph))
        if_stmt_blocks = []
        for node in super_graph.nodes():
            if not node.statements:
                continue

            if isinstance(node.statements[-1], ConditionalJump):
                if_stmt_blocks.append(node)

        if_ret_candidates = []
        for if_stmt_block in if_stmt_blocks:
            if_stmt = if_stmt_block.statements[-1]
            children = list(super_graph.successors(if_stmt_block))
            if len(children) != 2 or children[0] is children[1]:
                continue

            # find the true and false child of the if-stmt
            true_child, false_child = None, None
            for child in children:
                if child.addr == if_stmt.true_target.value:
                    true_child = child
                elif child.addr == if_stmt.false_target.value:
                    false_child = child
            # children must exist
            if (
                true_child is None
                or false_child is None
                or true_child not in super_graph
                or false_child not in super_graph
            ):
                continue
            # they must also have some statements to work with
            if not true_child.statements or not false_child.statements:
                continue

            # equivalent returns
            true_stmt = true_child.statements[-1]
            false_stmt = false_child.statements[-1]
            if (
                not isinstance(true_stmt, Return)
                or not isinstance(false_stmt, Return)
                or not true_stmt.likes(false_stmt)
            ):
                continue

            # both children must have only one predecessor
            if (
                len(list(super_graph.predecessors(true_child))) != 1
                or len(list(super_graph.predecessors(false_child))) != 1
            ):
                continue

            if_ret_candidates.append((if_stmt_block, true_child, false_child))

        return self._get_original_regions(if_ret_candidates)

    def _get_original_regions(self, if_ret_candidates: List[Tuple[Block, Block, Block]]):
        """
        Input: [(if_stmt_block, super_true_child, super_false_child), ...]
        Output: [(if_stmt_block, true_child, false_child, super_true_child, super_false_child), ...]

        super_* is the associated super block in the original graph
        """

        # re-find all the blocks we intend to delete in the original graph
        ids = {}
        for blocks in if_ret_candidates:
            for block in blocks:
                if not block.statements:
                    continue

                last_stmt = block.statements[-1]
                ids[(last_stmt.ins_addr, hash(last_stmt))] = block

        super_block_map = {}
        for block in self._graph.nodes():
            if not block.statements:
                continue

            last_stmt = block.statements[-1]
            stmt_id = (last_stmt.ins_addr, hash(last_stmt))
            if stmt_id in ids:
                super_block = ids[stmt_id]
                super_block_map[super_block] = block

        if_ret_regions = []
        for super_blocks in if_ret_candidates:
            corrected_region = []
            for super_block in super_blocks:
                block = super_block_map.get(super_block, None)
                if block is None:
                    break

                corrected_region.append(block)
            else:
                # super_true
                corrected_region.append(super_blocks[1])
                # super_false
                corrected_region.append(super_blocks[2])
                # all blocks were found
                if_ret_regions.append(corrected_region)

        return if_ret_regions
