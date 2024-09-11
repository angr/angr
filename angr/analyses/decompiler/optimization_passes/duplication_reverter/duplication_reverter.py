from __future__ import annotations
from collections import defaultdict
import logging
from itertools import combinations
import itertools

import networkx as nx

import ailment
from ailment.block import Block
from ailment.statement import ConditionalJump, Jump, Assignment, Return, Label
from ailment.expression import Const, Register, Convert, Expression

from .ail_merge_graph import AILMergeGraph, AILBlockSplit
from .errors import SAILRSemanticError
from .similarity import longest_ail_graph_subseq

from .utils import (
    replace_node_in_graph,
    find_block_in_successors_by_addr,
    copy_graph_and_nodes,
    correct_jump_targets,
    deepcopy_ail_anyjump,
)
from ..optimization_pass import StructuringOptimizationPass
from ...block_io_finder import BlockIOFinder
from ...block_similarity import is_similar, index_of_similar_stmts, longest_ail_subseq
from ...utils import to_ail_supergraph, remove_labels
from ...counters.boolean_counter import BooleanCounter
from .....knowledge_plugins.key_definitions.atoms import MemoryLocation
from .....utils.graph import dominates

_l = logging.getLogger(name=__name__)


class DuplicationReverter(StructuringOptimizationPass):
    """
    This (de)optimization reverts the effects of many compiler optimizations that cause code duplication in
    the decompilation. This deoptimization is the implementation of the USENIX 2024 paper SAILR's ISD
    doptimization. As such, the main goal of this optimization is to remove code duplication by merging
    semantically similar blocks in the AIL graph.
    """

    NAME = "Revert Statement Duplication Optimizations"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, max_guarding_conditions=4, **kwargs):
        super().__init__(
            func,
            prevent_new_gotos=True,
            strictly_less_gotos=False,
            recover_structure_fails=True,
            must_improve_rel_quality=True,
            max_opt_iters=30,
            simplify_ail=True,
            require_gotos=True,
            readd_labels=True,
            **kwargs,
        )

        self.max_guarding_conditions = max_guarding_conditions
        self.write_graph: nx.DiGraph | None = None
        self.read_graph: nx.DiGraph | None = None
        self.candidate_blacklist = set()

        # cache items
        self._idom_cache = {}
        self._entry_node_cache = {}

        self.analyze()

    #
    # Superclass methods
    #

    def _check(self):
        return True, {}

    def _get_new_gotos(self):
        future_irreducible_gotos = self._find_future_irreducible_gotos()
        return [goto for goto in self._goto_manager.gotos if goto not in future_irreducible_gotos]

    #
    # Main Analysis
    #

    def _analyze(self, cache=None) -> bool:
        """
        This function is the main analysis function for this deoptimization which implements SAILR's ISD deoptimization.
        There are generally three steps to this deoptimization:
        1. Search for candidates to merge based on the ISD-schema
        2. Construct the middle graph/node that is merged from the duplicate candidate
        3. Reinsert the merged candidate into the original graph

        Of these stages, the later two are the most complex. In stage 2, we create a new AILMergeGraph that represents
        the merging of two subgraphs that are duplicates. This stage will also record how blocks map to the split forms
        (see AILMergeGraph class string for more information). During this stage, semantic failures can happen, which
        mean that while creating the merged graph we encounter a scenario that is non-verifiable to not harm the graph.
        In these cases, we bail. In stage 3, we reinsert the merged candidate into the original graph. This stage is
        also a little messy because need to correct every jump address.

        Finally, the _analyze function returns True if the analysis was successful and a change was made to the graph.
        In this case, we return True if this optimization requires another iteration, and False if it does not.
        It can be True even if no changes were made to the graph.
        """
        # construct graphs for writing and reading so we can corrupt the write graph
        # but still have a clean copy to read from
        graph = self.out_graph or self._graph
        self.write_graph = remove_labels(to_ail_supergraph(copy_graph_and_nodes(graph), allow_fake=True))
        self.read_graph: nx.DiGraph = self.write_graph.copy()

        # phase 1: search for candidates to merge based on the ISD-schema
        candidate = self._search_for_deduplication_candidate()
        if candidate is None:
            return False

        # phase 2: construct the middle graph/node that is merged from the duplicate candidate
        try:
            ail_merge_graph, candidate = self._construct_merged_candidate(candidate)
        except SAILRSemanticError as e:
            _l.debug("Skipping this candidate because of %s...", e)
            self.candidate_blacklist.add(tuple(candidate))
            return True

        # phase 3: reinsert the merged candidate into the original graph
        success = self._reinsert_merged_candidate(ail_merge_graph, candidate)
        if not success:
            self.candidate_blacklist.add(tuple(candidate))
            return True

        self.out_graph = to_ail_supergraph(self.write_graph)
        return True

    def _search_for_deduplication_candidate(self) -> tuple[Block, Block] | None:
        candidates = self._find_initial_candidates()
        if not candidates:
            _l.debug("There are no duplicate statements in this function, stopping analysis")
            return None

        # with merge_candidates=False, max size for a candidate is 2
        candidates = self._filter_candidates(candidates, merge_candidates=False)
        if not candidates:
            _l.debug("There are no duplicate blocks in this function, stopping analysis")
            return None

        candidates = sorted(candidates, key=len)
        _l.debug("Located %d candidates for merging: %s", len(candidates), candidates)

        candidate = sorted(candidates[0], key=lambda x: x.addr)
        _l.debug("Selecting the candidate: %s", candidate)
        return candidate[0], candidate[1]

    def _construct_merged_candidate(
        self, candidate: tuple[Block, Block]
    ) -> tuple[AILMergeGraph, tuple[Block, Block]] | None:
        ail_merge_graph = self.create_merged_subgraph(candidate, self.write_graph)
        new_candidate = ail_merge_graph.starts
        for block in ail_merge_graph.original_ends:
            if self._block_has_goto_edge(
                block, [b for b in ail_merge_graph.original_ends if b is not block], graph=self.write_graph
            ):
                break
        else:
            raise SAILRSemanticError("An initial candidate was incorrectly reported to have gotos at it's ends!")

        return ail_merge_graph, new_candidate

    def _reinsert_merged_candidate(self, ail_merge_graph: AILMergeGraph, candidate: tuple[Block, Block]) -> bool:
        og_succs, og_preds = {}, {}
        for block, original_blocks in ail_merge_graph.original_blocks.items():
            # collect all the old edges
            for og_block in original_blocks:
                og_succs[og_block] = list(self.write_graph.successors(og_block))
                og_preds[og_block] = list(self.write_graph.predecessors(og_block))

            # delete all the blocks that will be merged into the merge_graph
            self.write_graph.remove_nodes_from(original_blocks)

        # add the new graph in to the original graph
        self.write_graph = nx.compose(self.write_graph, ail_merge_graph.graph)

        # connect all the out-edges that may have been altered
        for merged_node, originals in ail_merge_graph.merge_blocks_to_originals.items():
            last_stmt = merged_node.statements[-1]
            curr_succs = list(self.write_graph.successors(merged_node))

            # skip any nodes that already have enough successors
            broken_conditional_jump = not isinstance(last_stmt, (ConditionalJump, Jump)) and len(curr_succs) == 1
            if (
                broken_conditional_jump
                or (isinstance(last_stmt, Jump) and len(curr_succs) == 1)
                or (isinstance(last_stmt, ConditionalJump) and len(curr_succs) == 2)
            ):
                continue

            all_og_succs = set()
            for orig in originals:
                orig_block = orig.original if isinstance(orig, AILBlockSplit) else orig
                if orig_block not in og_succs:
                    continue

                for og_suc in og_succs[orig_block]:
                    if og_suc not in self.write_graph:
                        continue

                    all_og_succs.add(og_suc)

            # no if-stmt updating is needed here!
            for og_succ in all_og_succs:
                self.write_graph.add_edge(merged_node, og_succ)

        # correct all the in-edges that may have been altered
        all_preds = set()
        for block in candidate:
            for original in ail_merge_graph.original_blocks[block]:
                if original not in og_preds:
                    continue

                orig_preds = og_preds[original]
                for orig_pred in orig_preds:
                    if orig_pred not in self.write_graph:
                        continue

                    all_preds.add(orig_pred)

        for orig_pred in all_preds:
            last_stmt = orig_pred.statements[-1]
            if isinstance(last_stmt, (Jump, ConditionalJump)):
                target_addrs = []
                if isinstance(last_stmt, Jump):
                    if not isinstance(last_stmt.target, Const):
                        _l.debug("Candidate %s is a child of an indirect-jump, which is not supported", candidate)
                        self.write_graph = self.read_graph.copy()
                        return False

                    target_addrs = [last_stmt.target.value] if isinstance(last_stmt.target, Const) else []
                elif isinstance(last_stmt, ConditionalJump):
                    target_addrs = [last_stmt.true_target.value, last_stmt.false_target.value]

                replacement_map = {}
                for target_addr in target_addrs:
                    target_candidates = []
                    for mblock, oblocks in ail_merge_graph.merge_blocks_to_originals.items():
                        for oblock in oblocks:
                            if (
                                isinstance(oblock, AILBlockSplit)
                                and oblock.original.addr == target_addr
                                or isinstance(oblock, Block)
                                and oblock.addr == target_addr
                            ):
                                target_candidates.append(mblock)

                    if not target_candidates:
                        continue

                    new_target = None
                    curr_succs = list(self.write_graph.successors(orig_pred))
                    target_candidates = [t for t in target_candidates if t not in curr_succs]
                    for target_can in target_candidates:
                        if target_can.addr == target_addr:
                            new_target = target_can
                            break

                    if new_target is None:
                        for target_can in target_candidates:
                            found = False
                            for orig in ail_merge_graph.merge_blocks_to_originals[target_can]:
                                if isinstance(orig, Block):
                                    new_target = target_can
                                    found = True
                                    break

                            if found:
                                break

                    if new_target is None:
                        for split_type in ["up_split", "match_split", "down_split"]:
                            found = False

                            for target_can in target_candidates:
                                if ail_merge_graph.merged_is_split_type(target_can, split_type):
                                    new_target = target_can
                                    found = True
                                    break

                            if found:
                                break

                        if new_target is None:
                            raise RuntimeError("Unable to correct a predecessor, this is a bug!")

                    replacement_map[target_addr] = new_target.addr
                    self.write_graph.add_edge(orig_pred, new_target)

                new_pred = orig_pred.copy()
                new_pred.statements[-1] = correct_jump_targets(new_pred.statements[-1], replacement_map, new_stmt=True)
                if new_pred != orig_pred:
                    replace_node_in_graph(self.write_graph, orig_pred, new_pred)
            else:
                # we are at a block that has no ending, if this block does not end in one successor, then
                # it is just an incorrect graph
                orig_pred_succs = list(self.read_graph.successors(orig_pred))
                assert len(orig_pred_succs) == 1

                orig_pred_succ = orig_pred_succs[0]
                new_succ = None
                for merge, originals in ail_merge_graph.merge_blocks_to_originals.items():
                    found = False
                    for og in originals:
                        if (og == orig_pred_succ) or (isinstance(og, AILBlockSplit) and og.original == orig_pred_succ):
                            new_succ = merge
                            found = True
                            break

                    if found:
                        break

                if new_succ is None:
                    raise RuntimeError("Unable to find the successor for block with no jump or condition!")

                self.write_graph.add_edge(orig_pred, new_succ)

        self.write_graph = self._correct_all_broken_jumps(self.write_graph)
        self.write_graph = self._uniquify_addrs(self.write_graph)
        _l.info("Candidate merge successful on blocks: %s", candidate)
        return True

    #
    # Helpers
    #

    def _uniquify_addrs(self, graph):
        new_graph = nx.DiGraph()
        new_nodes = {}
        nodes_by_addr = defaultdict(list)
        for node in graph.nodes:
            nodes_by_addr[node.addr].append(node)

        for _, nodes in nodes_by_addr.items():
            if len(nodes) == 1:
                continue

            # we have multiple nodes with the same address
            duplicate_addr_nodes = sorted(nodes, key=lambda x: (x.idx or -1), reverse=True)
            for duplicate_node in duplicate_addr_nodes:
                new_node = duplicate_node.copy()
                new_node.idx = None
                new_addr = self.new_block_addr()
                new_node.addr = new_addr
                for i, stmt in enumerate(new_node.statements):
                    if stmt.tags and "ins_addr" in stmt.tags:
                        stmt.tags["ins_addr"] = new_addr + i + 1

                new_nodes[duplicate_node] = new_node

        # reset the idx for all of them since they are unique now, also fix the jump targets idx
        for node in graph.nodes:
            new_node = new_nodes[node] if node in new_nodes else node.copy()
            new_node.idx = None
            if new_node.statements and isinstance(new_node.statements[-1], Jump):
                new_node.statements[-1].target_idx = None

            new_nodes[node] = new_node

        # fixup every single jump target (before adding them to the graph)
        for src, dst, data in graph.edges(data=True):
            new_src = new_nodes[src]
            new_dst = new_nodes[dst]
            if new_dst is not dst:
                new_new_src = new_src.copy()
                new_new_src.statements[-1] = correct_jump_targets(new_new_src.statements[-1], {dst.addr: new_dst.addr})
                new_nodes[src] = new_new_src

        # add all the nodes in the same order back to the graph
        for node in graph.nodes:
            new_graph.add_node(new_nodes[node])
        for src, dst, data in graph.edges(data=True):
            new_graph.add_edge(new_nodes[src], new_nodes[dst], **data)

        return new_graph

    def _correct_all_broken_jumps(self, graph):
        new_graph = nx.DiGraph()
        new_nodes = {}
        for node in graph.nodes:
            # correct the last statement of the node for single-successor nodes
            new_node = node
            if graph.out_degree(node) == 1:
                last_stmt = node.statements[-1]
                successor = next(iter(graph.successors(node)))
                if isinstance(last_stmt, Jump):
                    if last_stmt.target.value != successor.addr:
                        new_last_stmt = deepcopy_ail_anyjump(last_stmt, idx=last_stmt.idx)
                        last_stmt.target_idx = successor.idx
                        new_last_stmt.target = Const(None, None, successor.addr, self.project.arch.bits)
                        new_node = node.copy()
                        new_node.statements[-1] = new_last_stmt
                # the last statement is not a jump, but this node should have one, so add it
                else:
                    new_node = node.copy()
                    new_last_stmt = Jump(
                        None, Const(None, None, successor.addr, self.project.arch.bits), target_idx=successor.idx
                    )
                    # TODO: improve addressing here
                    new_last_stmt.tags["ins_addr"] = new_node.addr + 1
                    new_node.statements.append(new_last_stmt)

            elif graph.out_degree(node) == 2:
                last_stmt = node.statements[-1]
                if isinstance(last_stmt, ConditionalJump):
                    real_successor_addrs = [_n.addr for _n in graph.successors(node)]
                    addr_map = {}
                    unmapped_addrs = []
                    for target in (last_stmt.true_target, last_stmt.false_target):
                        if target.value in real_successor_addrs:
                            addr_map[target.value] = target.value
                            real_successor_addrs.remove(target.value)
                        else:
                            unmapped_addrs.append(target.value)

                    # right now we can only correct cases where one edge is incorrect
                    if len(real_successor_addrs) == 1 and len(unmapped_addrs) == 1:
                        addr_map[unmapped_addrs[0]] = real_successor_addrs[0]
                        new_last_stmt = correct_jump_targets(last_stmt, addr_map, new_stmt=True)
                        new_node = node.copy()
                        new_node.statements[-1] = new_last_stmt

            new_nodes[node] = new_node
            new_graph.add_node(new_node)

        for src, dst, data in graph.edges(data=True):
            new_graph.add_edge(new_nodes[src], new_nodes[dst], **data)

        return new_graph

    def _construct_best_condition_block_for_merge(self, blocks, graph) -> tuple[Block, Block]:
        # find the conditions that block both of these blocks
        common_cond = self.shared_common_conditional_dom(blocks, graph)
        conditions_by_start = self.collect_conditions_between_nodes(graph, common_cond, blocks)

        best_condition_pair = None
        for start, condition in conditions_by_start.items():
            if best_condition_pair is None:
                best_condition_pair = (start, condition)
                continue

            if isinstance(condition, Const):
                continue

            _, best_cond = best_condition_pair
            if self.boolean_operators_in_condition(condition) < self.boolean_operators_in_condition(best_cond):
                best_condition_pair = start, condition

        true_block, best_condition = best_condition_pair
        boolean_cnt = self.boolean_operators_in_condition(best_condition)
        if boolean_cnt >= self.max_guarding_conditions:
            self.candidate_blacklist.add(tuple(blocks))
            raise SAILRSemanticError("A condition would be too long for a fixup, this analysis must skip it")

        cond_block = Block(common_cond.addr, 1, idx=common_cond.idx + 1 if isinstance(common_cond.idx, int) else 1)
        old_stmt_tags = common_cond.statements[0].tags
        cond_jump = ConditionalJump(
            1,
            best_condition.copy() if best_condition is not None else None,
            Const(None, None, 0, self.project.arch.bits),
            Const(None, None, 0, self.project.arch.bits),
            **old_stmt_tags,
        )
        cond_block.statements = [cond_jump]

        return cond_block, true_block

    @staticmethod
    def boolean_operators_in_condition(condition: Expression):
        """
        TODO: this entire boolean checking semantic we use needs to be removed, see how it is used for other dels needed
        we need to replace it with a boolean variable insertion on both branches that lead to the new block
        say we have:
        if (A()) {
            do_thing();
        }
        if (B()) {
            do_thing():
        }

        We want to translate it to:
        int should_do_thing = 0;
        if (A())
            should_do_thing = 1;
        if (B())
            should_do_thing = 1;

        if (should_do_thing):
            do_thing();

        Although longer, this code can be optimized to look like:
        int should_do_thing = A() || B();
        if (should_do_thing)
            do_thing();
        """
        walker = BooleanCounter()
        walker.walk_expression(condition)
        return walker.boolean_cnt

    @staticmethod
    def _input_defined_by_other_stmt(target_idx, other_idx, io_finder):
        target_inputs = io_finder.inputs_by_stmt[target_idx]
        # any memory location, not on stack, is not movable
        if any(isinstance(i, MemoryLocation) and not i.is_on_stack for i in target_inputs):
            return True

        other_outputs = io_finder.outputs_by_stmt[other_idx]
        return target_inputs.intersection(other_outputs)

    @staticmethod
    def _output_used_by_other_stmt(target_idx, other_idx, io_finder):
        target_output = io_finder.outputs_by_stmt[target_idx]
        # any memory location, not on stack, is not movable
        if any(isinstance(o, MemoryLocation) and not o.is_on_stack for o in target_output):
            return True

        other_input = io_finder.inputs_by_stmt[other_idx]
        return target_output.intersection(other_input)

    def stmt_can_move_to(self, stmt, block, new_idx, io_finder=None):
        if stmt not in block.statements:
            raise NotImplementedError("Statement not in block, and we can't compute moving a stmt to a new block!")

        # jumps of any kind are not moveable
        if (
            new_idx == len(block.statements) - 1 and isinstance(block.statements[new_idx], (ConditionalJump, Jump))
        ) or isinstance(stmt, (ConditionalJump, Jump)):
            return False

        io_finder = io_finder or BlockIOFinder(block, self.project)
        curr_idx = block.statements.index(stmt)
        move_up = new_idx < curr_idx

        # moving a statement up in the statements:
        # we must check if it's defined by anything above it (lower in index)
        can_move = True
        if move_up:
            # exclude curr_idx in range
            for mid_idx in range(new_idx, curr_idx):
                if self._input_defined_by_other_stmt(curr_idx, mid_idx, io_finder):
                    can_move = False
                    break

        # moving a statement down in the statements:
        # we much check if it's used by anything below it (greater in index)
        else:
            for mid_idx in range(curr_idx + 1, new_idx + 1):
                if self._output_used_by_other_stmt(curr_idx, mid_idx, io_finder):
                    can_move = False
                    break

        return can_move

    def maximize_similarity_of_blocks(self, block1, block2, graph) -> tuple[Block, Block]:
        """
        This attempts to rearrange the order of statements in block1 and block2 to maximize the similarity between them.
        This implementation is a little outdated since CodeMotion optimization was implemented, but it should
        be disabled until we have a good SSA implementation.

        TODO: reimplement me when we have better SSA
        """
        new_block1, new_block2 = block1.copy(), block2.copy()

        updates = True
        prev_moved = set()
        while updates:
            updates = False
            _, lcs_idxs = longest_ail_subseq([new_block1.statements, new_block2.statements])
            lcs_idx_by_block = {new_block1: lcs_idxs[0], new_block2: lcs_idxs[1]}
            if any(v is None for v in lcs_idx_by_block.values()):
                break

            io_finder_by_block = {
                new_block1: BlockIOFinder(new_block1, self.project),
                new_block2: BlockIOFinder(new_block2, self.project),
            }

            for search_offset in (-1, 1):
                for b1, b2 in itertools.permutations([new_block1, new_block2], 2):
                    if lcs_idx_by_block[b1] + search_offset < 0 or lcs_idx_by_block[b1] + search_offset >= len(
                        b1.statements
                    ):
                        continue

                    b1_unmatched = b1.statements[lcs_idx_by_block[b1] + search_offset]
                    if b1_unmatched in prev_moved:
                        continue

                    unmatched_b2_positions = index_of_similar_stmts([b1_unmatched], b2.statements, all_positions=True)
                    if unmatched_b2_positions is None:
                        continue

                    # b1_unmatched must be in b2
                    for b2_pos in unmatched_b2_positions:
                        b2_stmt = b2.statements[b2_pos]
                        if b2_stmt in prev_moved:
                            continue

                        if b2_pos + search_offset < 0 or b2_pos + search_offset >= len(b2.statements):
                            continue

                        # a stmt must be independent to be moveable
                        if self.stmt_can_move_to(
                            b2_stmt, b2, lcs_idx_by_block[b2] + search_offset, io_finder=io_finder_by_block[b2]
                        ):
                            # prev_stmts = b2.statements.copy()
                            b2.statements.remove(b2_stmt)
                            b2.statements.insert(lcs_idx_by_block[b2] + search_offset, b2_stmt)
                            prev_moved.add(b2_stmt)
                            prev_moved.add(b1_unmatched)

                            # new_lcs, _ = longest_ail_subseq([b1.statements, b2.statements])
                            ## if changes make don't make the lcs longer, revert changes
                            # if len(lcs) >= len(new_lcs):
                            #    b2.statements = prev_stmts
                            updates = True
                            break

                    if updates:
                        break
                if updates:
                    break
            else:
                # no updates happen, we are ready to kill this search
                break

        graph_changed = False
        if new_block1.statements != block1.statements:
            replace_node_in_graph(graph, block1, new_block1)
            graph_changed = True

        if new_block2.statements != block2.statements:
            replace_node_in_graph(graph, block2, new_block2)
            graph_changed = True

        if graph_changed:
            return new_block1, new_block2

        return block1, block2

    def create_merged_subgraph(self, blocks, graph: nx.DiGraph, maximize_similarity=False) -> AILMergeGraph:
        # Before creating a full graph LCS, optimize the common seq between the starting blocks
        if maximize_similarity:
            # TODO: this is disabled by default right now because it's both slow and incorrect. It should
            #   be fixed one day when we have a good SSA implementation. To test this, use the following:
            #   https://github.com/mahaloz/sailr-eval/blob/d9f99b3521b60b9a1fd862d106b77e5664a9d175
            #   /tests/test_deoptimization.py#L130
            blocks = list(self.maximize_similarity_of_blocks(blocks[0], blocks[1], graph))
        else:
            blocks = list(blocks)

        # Eliminate all cases that may only have returns (we should do that in a later pass)
        all_only_returns = True
        for block in blocks:
            for stmt in block.statements:
                if not isinstance(stmt, (Return, Label)):
                    all_only_returns = False
                    break
            if not all_only_returns:
                break
        if all_only_returns:
            self.candidate_blacklist.add(tuple(blocks))
            raise SAILRSemanticError("Both blocks only contain returns, this analysis must skip it")

        # Traverse both blocks subgraphs within the original graph and find the longest common AIL sequence.
        # Use one of the blocks subraphs to construct the top-half of the new merged graph that contains no inserted
        # conditions yet. This means the graph is still missing the divergence of the two graphs.
        try:
            graph_lcs = longest_ail_graph_subseq(blocks, graph)
        except SAILRSemanticError as e:
            self.candidate_blacklist.add(tuple(blocks))
            raise e

        ail_merge_graph = AILMergeGraph(original_graph=graph)
        # some blocks in originals may update during this time (if-statements can change)
        update_blocks = ail_merge_graph.create_conditionless_graph(blocks, graph_lcs)

        #
        # SPECIAL CASE: the merged graph contains only 1 node and no splits
        # allows for an early return without expensive computations
        #
        if len(ail_merge_graph.graph.nodes) == 1 and all(
            not splits for splits in ail_merge_graph.original_split_blocks.values()
        ):
            new_node = next(iter(ail_merge_graph.graph.nodes))
            base_successor = next(iter(graph.successors(blocks[0])))
            other_successor = next(iter(graph.successors(blocks[1])))
            conditional_block, true_target = self._construct_best_condition_block_for_merge(blocks, graph)
            if true_target == blocks[0]:
                conditional_block.statements[-1].true_target.value = base_successor.addr
                conditional_block.statements[-1].false_target.value = other_successor.addr
            else:
                conditional_block.statements[-1].true_target.value = other_successor.addr
                conditional_block.statements[-1].false_target.value = base_successor.addr

            ail_merge_graph.graph.add_edge(new_node, conditional_block)
            return ail_merge_graph

        # we have now generated the top half of the merge graph. We now need to create a mapping for all the
        # merge_graph blocks to the original blocks from the two targets we are merging. This map will store
        # the AILBlockSplit if it is a split, so we can track preds and succss later.
        merge_end_pairs = ail_merge_graph.create_mapping_to_merge_graph(update_blocks, blocks)

        # collect the conditions
        # make a new conditional block
        conditional_block, true_target = self._construct_best_condition_block_for_merge(blocks, graph)
        true_target = ail_merge_graph.starts[0] if true_target is blocks[0] else ail_merge_graph.starts[1]
        ail_merge_graph.add_edges_to_condition(conditional_block, true_target, merge_end_pairs)

        return ail_merge_graph

    def similar_conditional_when_single_corrected(self, block1: Block, block2: Block, graph: nx.DiGraph):
        cond1, cond2 = block1.statements[-1], block2.statements[-1]
        if not isinstance(cond1, ConditionalJump) or not isinstance(cond2, ConditionalJump):
            return False

        # conditions must match
        if not cond1.condition.likes(cond2.condition):
            return False

        # collect the true and false targets for the condition
        block_to_target_map = defaultdict(dict)
        for block, cond in ((block1, cond1), (block2, cond2)):
            for succ in graph.successors(block):
                if succ.addr == cond.true_target.value:
                    block_to_target_map[block]["true_target"] = succ
                elif succ.addr == cond.false_target.value:
                    block_to_target_map[block]["false_target"] = succ
                else:
                    # exit early if you ever can't find a supposed target
                    return False

        # check if at least one block in successors match
        mismatched_blocks = {}
        for target_type in block_to_target_map[block1]:
            t1_blk, t2_blk = block_to_target_map[block1][target_type], block_to_target_map[block2][target_type]
            if not is_similar(t1_blk, t2_blk, partial=True):
                mismatched_blocks[target_type] = {block1: t1_blk, block2: t2_blk}

        if len(mismatched_blocks) != 1:
            return False

        # We now know that at least one block matches
        # at this moment we have something that looks like this:
        #   A ---> C <--- B
        #   |             |
        #   V             V
        #   D             E
        #
        # A and B both share the same condition, point to a block that is either similar to each
        # other or the same block, AND they have a mismatch block D & E. We want to make a new NOP
        # block that is between A->D and B->E to make a balanced merged graph:
        #
        #   A ---> C <--- B
        #   |             |
        #   V             V
        #   N -> D   E <- N'
        #
        # We now will have a balanced merge graph
        for target_type, block_map in mismatched_blocks.items():
            for src, dst in block_map.items():
                # create a new nop block
                nop_blk = Block(
                    self.new_block_addr(),
                    0,
                    statements=[Jump(0, Const(0, 0, 0, self.project.arch.bits), 0, ins_addr=self.new_block_addr())],
                )
                # point src -> nop -> dst
                graph.add_edge(src, nop_blk)
                graph.add_edge(nop_blk, dst)
                # unlink src -X-> dst
                graph.remove_edge(src, dst)
                # correct the targets of the src
                target = getattr(src.statements[-1], target_type)
                target.value = nop_blk.addr

        return True

    @staticmethod
    def _has_single_successor_path(source, target, graph):
        if source not in graph or target not in graph:
            return []

        if not nx.has_path(graph, source, target):
            return []

        for simple_path in nx.all_simple_paths(graph, source, target, cutoff=10):
            for node in simple_path:
                if node is target or node is source:
                    continue
                if graph.out_degree(node) != 1:
                    break
            else:
                if simple_path[-1] is target:
                    return simple_path

        return []

    def _block_has_goto_edge(self, block: ailment.Block, other_ends, graph=None):
        # case1:
        # A -> (goto) -> B.
        # if goto edge coming from end block, from any instruction in the block
        # since instructions can shift...
        last_stmt = block.statements[-1]

        gotos = self._goto_manager.gotos_in_block(block)
        for goto in gotos:
            target_block = find_block_in_successors_by_addr(goto.dst_addr, block, graph)
            if any(self._has_single_successor_path(end, target_block, graph) for end in other_ends):
                return True

        # case2:
        # A.last (conditional) -> (goto) -> B -> C
        #
        # Some condition ends in a goto to one of the ends of the merge graph. In this case,
        # we consider it a modified version of case2
        if graph:
            for pred in graph.predecessors(block):
                last_stmt = pred.statements[-1]
                if isinstance(last_stmt, ConditionalJump):
                    gotos = self._goto_manager.gotos_in_block(pred)
                    # TODO: this is only valid for duplication reverter, but it should be better
                    if gotos and block.idx is not None:
                        return True

                    for goto in gotos:
                        if goto.dst_addr in (block.addr, block.statements[0].ins_addr):
                            return True

            for succ in graph.successors(block):
                last_stmt = succ.statements[-1]
                if isinstance(last_stmt, ConditionalJump):
                    gotos = self._goto_manager.gotos_in_block(succ)
                    # TODO: this is only valid for duplication reverter, but it should be better
                    if gotos and block.idx is not None:
                        return True

                    for goto in gotos:
                        for other_end in other_ends:
                            found = False
                            for other_succ in graph.successors(other_end):
                                if other_succ.addr == goto.dst_addr:
                                    found = True

                            if not found:
                                break

        return False

    def _find_future_irreducible_gotos(self, max_endpoint_distance=5):
        """
        Checks if these gotos could be fixed by eager returns
        """
        endnodes = [node for node in self.out_graph.nodes() if self.out_graph.out_degree[node] == 0]
        blocks_by_addr = {blk.addr: blk for blk in self.out_graph.nodes()}

        bad_gotos = set()
        for goto in self._goto_manager.gotos:
            goto_end_block = blocks_by_addr.get(goto.dst_addr, None)
            # skip gotos that don't exist
            if not goto_end_block:
                continue

            # if a goto end is an endnode, then this is good! Skip it!
            if goto_end_block in endnodes:
                continue

            connects_endnode = False
            for endnode in endnodes:
                if (
                    goto_end_block in self.out_graph
                    and endnode in self.out_graph
                    and nx.has_path(self.out_graph, goto_end_block, endnode)
                ):
                    try:
                        next(nx.all_simple_paths(self.out_graph, goto_end_block, endnode, cutoff=max_endpoint_distance))
                    except StopIteration:
                        continue

                    # if we are here, a path exists
                    connects_endnode = True
                    break

            # if goto is connected, great, skip it!
            if connects_endnode:
                continue

            # if we are here, this goto is non_reducible
            bad_gotos.add(goto)

        return bad_gotos

    def collect_conditions_between_nodes(self, graph, source: Block, sinks: list[Block], max_depth=15):
        graph_nodes = set(sinks)
        for sink in set(sinks):
            # we need to cutoff the maximum number of nodes that can be included in this search
            paths_between = nx.all_simple_paths(graph, source=source, target=sink, cutoff=max_depth)
            graph_nodes.update({node for path in paths_between for node in path})

        full_condition_graph: nx.DiGraph = nx.DiGraph(nx.subgraph(graph, graph_nodes))

        # destroy any edges which go to what is supposed to be the start node of the graph
        # which in effect removes loops (hopefully)
        while True:
            try:
                cycles = nx.find_cycle(full_condition_graph)
            except nx.NetworkXNoCycle:
                break

            full_condition_graph.remove_edge(*cycles[0])

        # now that we have a full target graph, we want to know the condensed conditions that allow
        # control flow to get to that target end. We get the reaching conditions to construct a guarding
        # node later
        self._ri.cond_proc.recover_reaching_conditions(None, graph=full_condition_graph)
        conditions_by_start = {}
        for sink in sinks:
            if sink in self._ri.cond_proc.guarding_conditions:
                condition = self._ri.cond_proc.guarding_conditions[sink]
            elif sink in self._ri.cond_proc.reaching_conditions:
                condition = self._ri.cond_proc.reaching_conditions[sink]
            else:
                # TODO: this should be better fixed
                self.candidate_blacklist.add(tuple(sinks))
                raise SAILRSemanticError(
                    f"Unable to find the conditions for target: {sink}. "
                    f"This is likely caused by unsupported statements, like Switches, being in the graph."
                )

            condition = self._ri.cond_proc.simplify_condition(condition)
            if condition.is_true() or condition.is_false():
                condition = self._ri.cond_proc.simplify_condition(self._ri.cond_proc.reaching_conditions[sink])

            conditions_by_start[sink] = self._ri.cond_proc.convert_claripy_bool_ast(condition)

        return conditions_by_start

    #
    # Search Stages
    #

    def _share_subregion(self, blocks: list[Block]) -> bool:
        return any(all(block.addr in region for block in blocks) for region in self._ri.regions_by_block_addrs)

    def _is_valid_candidate(self, b0, b1):
        # blocks must have statements
        if not b0.statements or not b1.statements:
            return False

        # blocks must share a region
        if not self._share_subregion([b0, b1]):
            return False

        # if not self.shared_common_conditional_dom([b0, b1], self.read_graph):
        #    return False

        stmt_in_common = False
        # special case: when we only have a single stmt
        if len(b0.statements) == len(b1.statements) == 1:
            # Case 1:
            # [if(a)] == [if(b)]
            #
            # we must use the more expensive `similar` function to tell on the graph if they are
            # stmts that result in the same successors
            stmt_is_similar = is_similar(b0, b1, graph=self.read_graph)

            # Case 2:
            # [if(a)] == [if(a)]
            # and at least one child for the correct target type matches
            # TODO: this not not yet supported

            # update ether we resolved in the above cases
            if stmt_is_similar:
                stmt_in_common = True
        else:
            # check if these nodes share any stmt in common
            for stmt0 in b0.statements:
                # jumps don't count
                if isinstance(stmt0, Jump):
                    continue

                # Most Assignments don't count just by themselves:
                # register = register
                # TOP = const | register
                if isinstance(stmt0, Assignment):
                    src = stmt0.src.operand if isinstance(stmt0.dst, Convert) else stmt0.src
                    if isinstance(src, Register) or (isinstance(src, Const) and src.bits > 2):
                        continue

                for stmt1 in b1.statements:
                    if is_similar(stmt0, stmt1, graph=self.write_graph):
                        stmt_in_common = True
                        break

                if stmt_in_common:
                    break

        # must share a common dominator
        return stmt_in_common and self.shared_common_conditional_dom((b0, b1), self.write_graph) is not None

    @staticmethod
    def _construct_goto_related_subgraph(base: Block, graph: nx.DiGraph, max_ancestors=5):
        """
        Creates a subgraph of the large graph starting from the base block and working upwards (predecessors)
        for max_ancestors amount of nodes
        """
        blocks = [base]
        level_blocks = [base]
        block_lvls = {base: 0}
        new_level_blocks = []
        for lvl in range(max_ancestors):
            new_level_blocks = []
            for lblock in level_blocks:
                block_lvls[lblock] = lvl + 1
                new_level_blocks += list(graph.predecessors(lblock))

            blocks += new_level_blocks
            level_blocks = new_level_blocks

        # collect last level blocks
        if new_level_blocks:
            for new_block in new_level_blocks:
                if new_block in block_lvls:
                    continue

                block_lvls[new_block] = max_ancestors + 1

        # construct the final subgraph
        g = nx.subgraph(graph, blocks)
        return g, block_lvls

    def _find_initial_candidates(self) -> list[tuple[Block, Block]]:
        """
        Here is how
        """
        # first, find all the goto edges, since these locations will always be the base of the merge
        # graph we create; therefore, we only need search around gotos
        goto_edges = self._goto_manager.find_goto_edges(self.read_graph)
        goto_edges = sorted(goto_edges, key=lambda x: x[0].addr + x[1].addr)

        candidates = []
        for goto_src, goto_dst in goto_edges:
            candidate_subgraph, dist_by_block = self._construct_goto_related_subgraph(goto_dst, self.read_graph)
            goto_candidates = []
            for b0, b1 in combinations(candidate_subgraph, 2):
                if self._is_valid_candidate(b0, b1):
                    pair = tuple(sorted([b0, b1], key=lambda x: x.addr))
                    goto_candidates.append(pair)

            # eliminate any that are already blacklisted
            goto_candidates = [c for c in goto_candidates if c not in self.candidate_blacklist]
            # re-sort candidates by address (for tiebreakers)
            goto_candidates = sorted(goto_candidates, key=lambda x: x[0].addr + x[1].addr, reverse=True)

            # choose only a single candidate for this goto, make it the one nearest to the head
            best = None
            best_dist = None
            for b0, b1 in goto_candidates:
                if best is None:
                    best = (b0, b1)
                    best_dist = dist_by_block[b0] + dist_by_block[b1]
                    continue

                total_dist = dist_by_block[b0] + dist_by_block[b1]
                if total_dist > best_dist:
                    best = (b0, b1)

            if best is not None:
                if best == (goto_src, goto_dst)[::-1]:
                    # just flip it to normalize
                    best = best[::-1]

                candidates.append(best)

        candidates = list(set(candidates))
        candidates.sort(key=lambda x: x[0].addr + x[1].addr)
        return candidates

    def _filter_candidates(self, candidates, merge_candidates=True):
        """
        Preform a series of filters on the candidates to reduce the fast set to an assured set of
        the duplication case we are searching for.
        """

        #
        # filter out bad candidates from the blacklist
        #

        filted_candidates = []
        id_blacklist = {((b0.addr, b0.idx), (b1.addr, b1.idx)) for b1, b0 in self.candidate_blacklist}
        for candidate in candidates:
            blk_id = ((candidate[0].addr, candidate[0].idx), (candidate[1].addr, candidate[1].idx))
            rev_blk_id = blk_id[::-1]
            if blk_id not in id_blacklist and rev_blk_id not in id_blacklist:
                filted_candidates.append(candidate)
        candidates = filted_candidates

        # when enabled, attempts to merge candidates
        if merge_candidates:
            #
            # Now, merge pairs that may actually be n-pairs. This will look like multiple pairs having a single
            # block in common, and have one or more statements in common.
            #

            not_fixed = True
            while not_fixed:
                not_fixed = False
                queued = set()
                merged_candidates = []

                # no merging needs to be done, there is only one candidate left
                if len(candidates) == 1:
                    break

                for can0 in candidates:
                    # skip candidates being merged
                    if can0 in queued:
                        continue

                    for can1 in candidates:
                        if can0 == can1 or can1 in queued:
                            continue

                        # only try a merge if candidates share a node in common
                        if not set(can0).intersection(set(can1)):
                            continue

                        lcs, _ = longest_ail_subseq([b.statements for b in set(can0 + can1)])
                        if not lcs:
                            continue

                        merged_candidates.append(tuple(set(can0 + can1)))
                        queued.add(can0)
                        queued.add(can1)
                        not_fixed |= True
                        break

                remaining_candidates = []
                for can in candidates:
                    for m_can in merged_candidates:
                        if not all(blk not in m_can for blk in can):
                            break
                    else:
                        remaining_candidates.append(can)

                candidates = merged_candidates + remaining_candidates

            candidates = list(set(candidates))
            candidates = [tuple(sorted(candidate, key=lambda x: x.addr)) for candidate in candidates]
            candidates = sorted(candidates, key=lambda x: sum(c.addr for c in x))

        return candidates

    def shared_common_conditional_dom(self, nodes, graph: nx.DiGraph):
        """
        Takes n nodes and returns True only if all the nodes are dominated by the same node, which must be
        a ConditionalJump

        @param nodes:
        @param graph:
        @return:
        """

        if graph not in self._entry_node_cache:
            entry_blocks = [node for node in graph.nodes if graph.in_degree(node) == 0]
            entry_block = None if len(entry_blocks) != 1 else entry_blocks[0]

            self._entry_node_cache[graph] = entry_block
            if entry_block is None:
                return None

        entry_blk = self._entry_node_cache[graph]

        if graph not in self._idom_cache:
            self._idom_cache[graph] = nx.algorithms.immediate_dominators(graph, entry_blk)

        idoms = self._idom_cache[graph]

        # first check if any of the node pairs could be a dominating loop
        b0, b1 = nodes[:]
        if dominates(idoms, b0, b1) or dominates(idoms, b1, b0):
            return None

        node = nodes[0]
        node_level = [node]
        seen_nodes = set()
        while node_level:
            # check if any of the nodes on the current level are dominators to all nodes
            for cnode in node_level:
                if not cnode.statements:
                    continue

                if (
                    isinstance(cnode.statements[-1], ConditionalJump)
                    and all(dominates(idoms, cnode, node) for node in nodes)
                    and cnode not in nodes
                ):
                    return cnode

            # if no dominators found, move up a level
            seen_nodes.update(set(node_level))
            next_level = list(itertools.chain.from_iterable([list(graph.predecessors(cnode)) for cnode in node_level]))
            # only add nodes we have never seen
            node_level = set(next_level).difference(seen_nodes)

        return None
