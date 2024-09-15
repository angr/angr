# pylint:disable=unnecessary-pass
from __future__ import annotations
import logging

from ailment.block import Block
from ailment.statement import Statement, Call, ConditionalJump, Assignment, Jump
from ailment.expression import ITE, Const, VirtualVariable, Phi

from angr.utils.ail import is_phi_assignment
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

            for region_head, region_tail, true_block, true_stmt, false_block, false_stmt in ite_assign_regions:
                round_update |= self._convert_region_to_ternary_expr(
                    region_head, region_tail, true_block, true_stmt, false_block, false_stmt
                )

            if not round_update:
                break

            graph_updated |= True

        if graph_updated:
            self.out_graph = self._graph

    def _find_ite_assignment_regions(self):
        # find all the if-stmt blocks in a graph with no single successor edges
        blocks_by_end_addr = {(block.addr + block.original_size, block.idx): block for block in self._graph.nodes()}
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
            if not self._is_assigning_to_vvar(true_stmt) or not self._is_assigning_to_vvar(false_stmt):
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

            # find the corresponding blocks for true_child and false_child in the original graph
            # this is because the phi expressions only records source addresses of the original blocks, not the
            # addresses of super blocks
            true_child_original = blocks_by_end_addr.get(
                (true_child.addr + true_child.original_size, true_child.idx), true_child
            )
            false_child_original = blocks_by_end_addr.get(
                (false_child.addr + false_child.original_size, false_child.idx), false_child
            )

            # the common successor must have a phi assignment with source variables being assigned to in true_stmt and
            # false_stmt
            if not self._has_qualified_phi_assignments(
                common_successor, true_child_original, true_stmt, false_child_original, false_stmt
            ):
                continue

            # lastly, normalize the region we will be editing
            region_head = super_to_normal_node.get(if_stmt_block)
            tail_blocks = list(self.blocks_by_addr.get(common_successor.addr, []))
            region_tail = tail_blocks[0] if tail_blocks else None
            if region_head is None or region_tail is None:
                continue

            # we have now found a valid ITE-like expression case
            ite_candidates.append((region_head, region_tail, true_child, true_stmt, false_child, false_stmt))

        return ite_candidates

    @staticmethod
    def _has_qualified_phi_assignments(
        block: Block, block0: Block, stmt0: Assignment | Call, block1: Block, stmt1: Assignment | Call
    ):
        vvar0 = stmt0.dst if isinstance(stmt0, Assignment) else stmt0.ret_expr
        vvar1 = stmt1.dst if isinstance(stmt1, Assignment) else stmt1.ret_expr

        addr0 = block0.addr, block0.idx
        addr1 = block1.addr, block1.idx

        found_phi_assignment = False
        has_unexpected_phi_assignment = False
        for stmt in block.statements:
            if not is_phi_assignment(stmt):
                continue
            src_vars = {src: vvar.varid if vvar is not None else None for src, vvar in stmt.src.src_and_vvars}
            if src_vars.get(addr0) == vvar0.varid and src_vars.get(addr1) == vvar1.varid:
                # this is the phi assignment that assigns stmt0.dst and stmt1.dst to a new variable
                found_phi_assignment = True
            else:
                if addr0 in src_vars and addr1 in src_vars and src_vars[addr0] == src_vars[addr1]:
                    # for all other phi assignments, the source variable out of the two origins must be the same one
                    pass
                else:
                    has_unexpected_phi_assignment = True

        return found_phi_assignment and not has_unexpected_phi_assignment

    def _convert_region_to_ternary_expr(
        self,
        region_head,
        region_tail,
        true_block,
        true_stmt: Assignment | Call,
        false_block,
        false_stmt: Assignment | Call,
    ):
        if region_head not in self._graph or region_tail not in self._graph:
            return False

        #
        # create a new region_head
        #

        new_region_head = region_head.copy()
        conditional_jump: ConditionalJump = region_head.statements[-1]

        true_stmt_src = true_stmt.src if isinstance(true_stmt, Assignment) else true_stmt
        true_stmt_dst = true_stmt.dst if isinstance(true_stmt, Assignment) else true_stmt.ret_expr
        false_stmt_src = false_stmt.src if isinstance(false_stmt, Assignment) else false_stmt

        addr_obj = true_stmt_src if "ins_addr" in true_stmt_src.tags else true_stmt
        ternary_expr = ITE(
            None,
            conditional_jump.condition,
            false_stmt_src,
            true_stmt_src,
            ins_addr=addr_obj.ins_addr,
            vex_block_addr=addr_obj.vex_block_addr,
            vex_stmt_idx=addr_obj.vex_stmt_idx,
        )
        dst = VirtualVariable(
            true_stmt_dst.idx,
            self.vvar_id_start,
            true_stmt_dst.bits,
            true_stmt_dst.category,
            oident=true_stmt_dst.oident,
            **true_stmt_dst.tags,
        )
        self.vvar_id_start += 1
        src = ternary_expr
        new_assignment = Assignment(true_stmt.idx, dst, src, **true_stmt.tags)
        new_region_head.statements[-1] = new_assignment

        # add a goto statement to the region tail so it can be transformed into a break or other types of control-flow
        # transitioning statement in the future
        goto_stmt = Jump(
            None, Const(None, None, region_tail.addr, self.project.arch.bits), region_tail.idx, **conditional_jump.tags
        )
        new_region_head.statements.append(goto_stmt)

        #
        # destroy all the old region blocks
        #

        region_nodes = subgraph_between_nodes(self._graph, region_head, [region_tail])
        for node in region_nodes:
            if node is region_head or node is region_tail:
                continue

            self._remove_block(node)

        #
        # Update phi assignments in region tail
        #

        stmts = []
        for stmt in region_tail.statements:
            if not is_phi_assignment(stmt):
                stmts.append(stmt)
                continue
            new_src_and_vvars = []
            for src, vvar in stmt.src.src_and_vvars:
                if src not in {(true_block.addr, true_block.idx), (false_block.addr, false_block.idx)}:
                    new_src_and_vvars.append((src, vvar))
            new_vvar = new_assignment.dst.copy()
            new_src_and_vvars.append(((region_head.addr, region_head.idx), new_vvar))

            new_phi = Phi(
                stmt.src.idx,
                stmt.src.bits,
                new_src_and_vvars,
                **stmt.src.tags,
            )
            new_phi_assignment = Assignment(
                stmt.idx,
                stmt.dst,
                new_phi,
                **stmt.tags,
            )
            stmts.append(new_phi_assignment)
        new_region_tail = Block(region_tail.addr, region_tail.original_size, statements=stmts, idx=region_tail.idx)

        #
        # update head and tail
        #

        self._update_block(region_head, new_region_head)
        self._update_block(region_tail, new_region_tail)
        self._graph.add_edge(new_region_head, new_region_tail)

        return True

    @staticmethod
    def _is_assigning_to_vvar(stmt: Statement) -> bool:
        return (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            or isinstance(stmt, Call)
            and isinstance(stmt.ret_expr, VirtualVariable)
        )
