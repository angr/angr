from typing import Tuple, List, Optional
import itertools

import networkx as nx
from ailment import Block
from ailment.statement import ConditionalJump
import ailment.expression

from angr.utils.graph import dominates, dfs_back_edges, GraphUtils
from angr.analyses.decompiler.utils import to_ail_supergraph
from angr.analyses.decompiler.optimization_passes.optimization_pass import StructuringOptimizationPass
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.atoms import Register


class InvariantHeaderCandidate:
    def __init__(self, inv_header_blk, og_header_blk, inv_init_node, iter_var, iter_atom_val):
        self.inv_header = inv_header_blk
        self.og_header = og_header_blk
        self.inv_init_node = inv_init_node
        self.iter_var = iter_var
        self.iter_atom_val = iter_atom_val

    def __repr__(self):
        return f"<InvariantHeaderCandidate: {self.inv_header} -> {self.og_header}>"


class LoopHeaderCopyReverter(StructuringOptimizationPass):
    """
    A deoptimization pass discovered during the SAILR paper, but not used inside the actual evaluation of the paper.
    This pass is designed to target compilers that optimize away invariant headers in loops by duplicating the header
    and moving the invariant initialization code to the top of the loop. This is similar to an ISD pass, but it's more
    complicated becasue it produces no gotos to indicate that it happened.

    Here is the simple case we are targeting:
    if (x > 0) {
        i = 0
        do {
            <use i>
            ...
        } while(x > i)
    }

    This will be transformed into:
    for (i = 0; i < x; <use i>) { ... }

    Instead of doing this in a schema matcher, we apply the edits to the AIL graph directly. By doing this,
    later structuring passes will be able to pick up on the new structure and optimize it further.
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Duplicate return blocks to reduce goto statements"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, *args, **kwargs):
        super().__init__(func, *args, max_opt_iters=1, prevent_new_gotos=True, **kwargs)
        _heads = [node for node in self._graph.nodes if self._graph.in_degree(node) == 0]
        self._graph_head = _heads[0] if len(_heads) == 1 else None
        if self._graph_head is not None:
            self.analyze()

    def _check(self):
        return not nx.is_directed_acyclic_graph(self._graph), None

    def _analyze(self, cache=None) -> bool:
        loops = self._find_loops()
        if not loops:
            return False

        inv_candidate = self._find_invariant_header_candidate(loops)
        if inv_candidate is None:
            return False

        return self._merge_headers(inv_candidate)

    def _merge_headers(self, inv_candidate: InvariantHeaderCandidate):
        """
        TODO: implement this

        Steps:
        1. Delete the invariant header
        2. Point all the predecessors of inv_header to the inv_initer block instead
        3. Move the original header to the top of the loop
        4. Profit!
        """
        return False

    def _find_loops(self) -> List[Tuple[nx.DiGraph, Block, Block]]:
        """
        This function finds very simple loops
        Returns:
        [(loop_graph, loop_head, loop_bottom), ...]

        """
        loops = list(nx.simple_cycles(self.out_graph))
        back_edges = list(dfs_back_edges(self.out_graph, self._graph_head))
        topi_sort_nodes = GraphUtils.quasi_topological_sort_nodes(self.out_graph)
        found_loops = []

        for loop_nodes in loops:
            bad_loop = False
            heads = []
            bottoms = []
            for node in loop_nodes:
                preds = self.out_graph.predecessors(node)
                preds_outside = [pred for pred in preds if pred not in loop_nodes]
                # we only consider loops with a single entry for now
                if len(preds_outside) > 1:
                    bad_loop = True
                    break

                # find head and bottom
                for src, dst in back_edges:
                    if src == node and dst in loop_nodes:
                        heads.append(dst)
                        bottoms.append(src)

            if bad_loop or not bottoms or not heads:
                continue

            for _node in topi_sort_nodes:
                if _node in heads:
                    head = _node
                    break
            else:
                head = None

            for _node in reversed(topi_sort_nodes):
                if _node in bottoms:
                    bot = _node
                    break
            else:
                bot = None

            found_loops.append((nx.DiGraph(nx.subgraph(self.out_graph, loop_nodes)), head, bot))

        return found_loops

    def _find_invariant_header_candidate(self, loops) -> Optional[InvariantHeaderCandidate]:
        """
        We are searching for this case:
        ```
        if (x > 0) {            // matches og header if hoisted inv init var
            y = 0               // inv init var
            do {
                <use y>
            } while(x > y)      // og header, shares inv init var
        }
        ```
        Invariant Header: x > 0
        Original Header: x > y
        """
        bottom_loop_nodes = {bot: (loop_g, head) for loop_g, head, bot in loops}
        idoms = None
        # Iterate only nodes in a loop who could have a match outside of it
        candidates = list(itertools.product(bottom_loop_nodes.keys(), list(self.out_graph.nodes)))
        flipped = [can[::-1] for can in candidates]
        candidates += flipped
        for inv_header_blk, og_header_blk in candidates:
            if not inv_header_blk.statements or not og_header_blk.statements or inv_header_blk is og_header_blk:
                continue

            # Both headers should end with a conditional jump, which should have the same type of condition
            # TODO: implement a check for when the condition is simply the flipped version of the other
            inv_header, og_header = inv_header_blk.statements[-1], og_header_blk.statements[-1]
            if (
                not isinstance(og_header, ConditionalJump)
                or not isinstance(inv_header, ConditionalJump)
                or (type(inv_header.condition) is not type(og_header.condition))
            ):
                continue

            # Both headers should be in normal if-stmt form: only two successors. This eliminates switch statements.
            inv_succs = list(self.out_graph.successors(inv_header_blk))
            og_succs = list(self.out_graph.successors(og_header_blk))
            if len(inv_succs) != len(og_succs) or len(og_succs) != 2:
                continue

            # Check that the condition in comparison is at least _somewhat_ similar to the other one.
            # Currently, that means if at least one part of the binary operation matches, after normalization,
            # than we should continue assuming it's a valid candidate.
            og_cond, inv_cond = og_header.condition.copy(), inv_header.condition.copy()
            if not isinstance(og_cond, ailment.expression.BinaryOp) or not isinstance(
                inv_cond, ailment.expression.BinaryOp
            ):
                # TODO add support for unary type conditions
                continue

            if og_cond.op != inv_cond.op:
                continue

            # you can kill the convert on operands if it's in the og_condition and the operations makes the bits
            # less or equal to the original comparison
            for i, operands in enumerate(zip(og_cond.operands, inv_cond.operands)):
                og_o, inv_o = operands
                # TODO: this is a very aggressive conversion and COULD be wrong
                #   need to just check with more complex cases of this optimization triggering
                if isinstance(og_o, ailment.expression.Convert) and og_o.to_bits:
                    # if hasattr(inv_o, "bits") and inv_o.bits >= og_o.to_bits:
                    og_cond.operands[i] = og_o.operand
                if isinstance(inv_o, ailment.expression.Convert) and inv_o.to_bits:
                    # if hasattr(og_o, "bits") and inv_o.to_bits >= og_o.bits:
                    inv_cond.operands[i] = inv_o.operand

            # check the operand after normalization
            mismatched_op_pos = None
            all_mismatch = False
            for i, operands in enumerate(zip(og_cond.operands, inv_cond.operands)):
                og_o, inv_o = operands
                if og_o and inv_o and og_o.likes(inv_o):
                    continue
                elif mismatched_op_pos is None:
                    mismatched_op_pos = i
                elif mismatched_op_pos is not None:
                    all_mismatch = True
            if all_mismatch:
                continue

            # All invariants should dominate the original header, since they are a split version of the original
            if idoms is None:
                idoms = nx.immediate_dominators(self.out_graph, self._graph_head)
            if not dominates(idoms, dominator_node=inv_header_blk, node=og_header_blk):
                continue

            # The original header should be the bottom of the loop dominated by the invariant header
            loop_graph, loop_head = bottom_loop_nodes.get(og_header_blk, (None, None))
            if loop_graph is None or loop_head is None:
                continue

            # Verify that there is only one block, the invariant initer, between the two headers
            header_paths = list(nx.all_simple_paths(self.out_graph, source=inv_header_blk, target=og_header_blk))
            if len(list(header_paths)) > 1:
                continue
            between_graph = to_ail_supergraph(
                nx.subgraph(self.out_graph, [n for n in header_paths[0] if n not in (inv_header_blk, og_header_blk)])
            )
            if len(between_graph.nodes) > 1:
                # TODO: make this less aggressive, there may be non-linear blocks between the two headers
                continue
            inv_init_node = list(between_graph.nodes)[0]

            # at this point both conditions should have been normalized and at least one of the operands
            # already matches across both conditions. now we need to check that their exists two more things:
            # 1. An assignment to the invariant iter var that's dominated by the first if-stmt
            # 2. The invariant iter var is also the value of invariant comparison

            # find the variable that is used to iterate the loop
            iter_var = og_cond.operands[mismatched_op_pos]
            if not isinstance(iter_var, ailment.expression.Register) or not hasattr(iter_var, "reg_name"):
                # TODO: add support for non-register iteration variables
                continue
            iter_atom = Register(iter_var.reg_offset, iter_var.size, self.project.arch)

            rda = self.project.analyses.ReachingDefinitions(
                subject=self._func,
                observation_points=[("insn", og_header.ins_addr, OP_AFTER), ("node", inv_init_node.addr, OP_AFTER)],
            )

            # Get the value of the iter variable right after we leave the invariant header.
            # This also means we should be at the head of the graph between the header and the loop.
            inv_header_end_state = rda.get_reaching_definitions_by_node(inv_init_node.addr, OP_AFTER)
            iter_atom_val = inv_header_end_state.get_concrete_value(iter_atom)
            if iter_atom_val is None or not isinstance(iter_atom_val, int):
                # TODO: support for non-constant iter vars, i.e. memory locations
                continue

            # Now validate that the invariant headers mismatched operand is the same as the iter var value
            # at the end of the invariant header
            operand = inv_header.condition.operands[mismatched_op_pos]
            if not isinstance(operand, ailment.expression.Const) or operand.value != iter_atom_val:
                # only consts supported right now
                continue

            return InvariantHeaderCandidate(inv_header_blk, og_header_blk, inv_init_node, iter_var, iter_atom_val)

        return None
