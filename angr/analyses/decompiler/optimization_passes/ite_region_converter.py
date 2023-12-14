# pylint:disable=unnecessary-pass
import logging

from ailment.statement import ConditionalJump, Assignment, Jump
from ailment.expression import ITE

from ....utils.graph import subgraph_between_nodes
from ..utils import remove_labels, to_ail_supergraph
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(__name__)


class ITERegionConverter(OptimizationPass):
    """
    Transform regions of the form `if (c) {x = a} else {x = b}` into `x = c ? a : b`.
    """

    ARCHES = ["X86", "AMD64", "ARMEL", "ARMHF", "ARMCortexM", "MIPS32", "MIPS64"]
    PLATFORMS = ["windows", "linux", "cgc"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Transform ITE-assignment regions into ternary expression assignments"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, max_updates=10, **kwargs):
        super().__init__(func, **kwargs)
        self._max_updates = max_updates
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        graph_updated = False
        for _ in range(self._max_updates):
            round_update = False
            ite_assign_regions = self._find_ite_assignment_regions()
            if not ite_assign_regions:
                break

            for region_head, region_tail, true_stmt, false_stmt in ite_assign_regions:
                round_update |= self._convert_region_to_ternary_expr(region_head, region_tail, true_stmt, false_stmt)

            if not round_update:
                break

            graph_updated |= True

        if graph_updated:
            self.out_graph = self._graph

    def _find_ite_assignment_regions(self):
        # find all the if-stmt blocks in a graph with no single successor edges
        super_graph = to_ail_supergraph(remove_labels(self._graph))
        if_stmt_blocks = []
        for node in super_graph.nodes():
            if not node.statements:
                continue

            if isinstance(node.statements[-1], ConditionalJump):
                if_stmt_blocks.append(node)

        # re-find the if-stmts blocks in the original graph
        super_if_ids = {(node.statements[-1].ins_addr, node.statements[-1].idx): node for node in if_stmt_blocks}
        super_to_normal_node = {}
        for node in self._graph.nodes():
            if not node.statements:
                continue

            if isinstance(node.statements[-1], ConditionalJump):
                if_stmt = node.statements[-1]
                if (if_stmt.ins_addr, if_stmt.idx) in super_if_ids:
                    super_node = super_if_ids[(if_stmt.ins_addr, if_stmt.idx)]
                    super_to_normal_node[super_node] = node

        # validate each if-stmt block matches a ternary schema
        ite_candidates = []
        for if_stmt_block in if_stmt_blocks:
            if_stmt = if_stmt_block.statements[-1]
            children = list(super_graph.successors(if_stmt_block))
            if len(children) != 2 or children[0] is children[1]:
                continue

            true_child, false_child = None, None
            for child in children:
                if if_stmt.true_target is not None and child.addr == if_stmt.true_target.value:
                    true_child = child
                elif if_stmt.false_target is not None and child.addr == if_stmt.false_target.value:
                    false_child = child

            if (
                true_child is None
                or false_child is None
                or true_child not in super_graph
                or false_child not in super_graph
            ):
                continue

            # verify the only statements in the two children are assignments
            true_stmts = [stmt for stmt in true_child.statements if not isinstance(stmt, Jump)]
            false_stmts = [stmt for stmt in false_child.statements if not isinstance(stmt, Jump)]
            if len(true_stmts) != 1 or len(false_stmts) != 1:
                continue

            true_stmt = true_stmts[0]
            false_stmt = false_stmts[0]
            if (
                not isinstance(true_stmt, Assignment)
                or not isinstance(false_stmt, Assignment)
                or not true_stmt.dst.likes(false_stmt.dst)
            ):
                continue

            # must contain a single common predecessor
            if (
                len(list(super_graph.predecessors(true_child))) != 1
                or len(list(super_graph.predecessors(false_child))) != 1
            ):
                continue

            # must contain the same common successor
            true_successors = list(super_graph.successors(true_child))
            if len(true_successors) != 1 or true_successors != list(super_graph.successors(false_child)):
                continue
            common_successor = true_successors[0]

            # lastly, normalize the region we will be editing
            region_head = super_to_normal_node.get(if_stmt_block, None)
            tail_blocks = list(self.blocks_by_addr.get(common_successor.addr, []))
            region_tail = tail_blocks[0] if tail_blocks else None
            if region_head is None or region_tail is None:
                continue

            # we have now found a valid ITE-like expression case
            ite_candidates.append((region_head, region_tail, true_stmt, false_stmt))

        return ite_candidates

    def _convert_region_to_ternary_expr(self, region_head, region_tail, true_stmt, false_stmt):
        if region_head not in self._graph or region_tail not in self._graph:
            return False

        #
        # create a new region_head
        #

        new_region_head = region_head.copy()
        addr_obj = true_stmt.src if "ins_addr" in true_stmt.src.tags else true_stmt
        ternary_expr = ITE(
            None,
            region_head.statements[-1].condition,
            true_stmt.src,
            false_stmt.src,
            ins_addr=addr_obj.ins_addr,
            vex_block_addr=addr_obj.vex_block_addr,
            vex_stmt_idx=addr_obj.vex_stmt_idx,
        )
        new_assignment = true_stmt.copy()
        new_assignment.src = ternary_expr
        new_region_head.statements[-1] = new_assignment

        #
        # destroy all the old region blocks
        #

        region_nodes = subgraph_between_nodes(self._graph, region_head, [region_tail])
        for node in region_nodes:
            if node is region_head or node is region_tail:
                continue

            self._remove_block(node)

        #
        # update head and tail
        #

        self._update_block(region_head, new_region_head)
        self._graph.add_edge(new_region_head, region_tail)

        return True
