from collections import defaultdict
from copy import deepcopy
import logging
from itertools import combinations
import itertools

import networkx as nx

import ailment
from ailment.block import Block
from ailment.statement import ConditionalJump, Jump, Assignment, Return, Label
from ailment.expression import Const, Register, Convert, Expression

from .ail_merge_graph import AILMergeGraph, AILBlockSplit
from .errors import StructuringError, SAILRSemanticError
from .similarity import longest_ail_graph_subseq

from .utils import (
    replace_node_in_graph,
    shared_common_conditional_dom,
    find_block_in_successors_by_addr,
    copy_graph_and_nodes,
    correct_jump_targets,
    ail_block_from_stmts,
    deepcopy_ail_anyjump,
)
from angr.analyses.decompiler.counters.boolean_counter import BooleanCounter
from ..optimization_pass import OptimizationPass, OptimizationPassStage
from ...block_io_finder import BlockIOFinder
from ...block_similarity import is_similar, index_of_similar_stmts, longest_ail_subseq
from ...goto_manager import GotoManager
from ...region_identifier import RegionIdentifier
from ...structuring import RecursiveStructurer, PhoenixStructurer
from .....analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsAnalysis
from ...utils import to_ail_supergraph, remove_labels, add_labels
from .....knowledge_plugins.key_definitions.atoms import MemoryLocation

l = logging.getLogger(name=__name__)
_DEBUG = False
l.setLevel(logging.DEBUG)


class DuplicationReverter(OptimizationPass):
    """
    Reverts the duplication of statements
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Revert Statement Duplication Optimizations"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, region_identifier=None, reaching_definitions=None, max_guarding_conditions=4, **kwargs):
        self.ri: RegionIdentifier = region_identifier
        self.rd: ReachingDefinitionsAnalysis = reaching_definitions
        super().__init__(func, **kwargs)

        self.max_guarding_conditions = max_guarding_conditions
        self.goto_manager: GotoManager | None = None
        self.write_graph: nx.DiGraph | None = None
        self.candidate_blacklist = set()

        self._starting_goto_count = None
        self._unique_fake_addr = 0
        self._round = 0

        self.prev_graph = None
        self.func_name = self._func.name
        self.binary_name = self.project.loader.main_object.binary_basename
        self.target_name = f"{self.binary_name}.{self.func_name}"

        self.analyze()

    def _check(self):
        return True, {}

    #
    # Main Optimization Pass (after search)
    #

    def _analyze(self, cache=None, stop_if_more_goto=True):
        """
        Entry analysis routine that will trigger the other analysis stages
        XXX: when in evaluation: stop_if_more_goto=True so that we never emit more gotos than we originally had
        """
        try:
            self.deduplication_analysis(max_fix_attempts=30)
        except StructuringError:
            l.critical(f"Structuring failed! This function {self.target_name} is dead in the water!")

        if self.out_graph is not None:
            output_graph = True
            # if structuring failed
            if self.goto_manager is None:
                self.out_graph = self.prev_graph
                self.write_graph = self.prev_graph
                if not self._structure_graph():
                    output_graph = False

            if stop_if_more_goto and output_graph:
                future_irreducible_gotos = self._find_future_irreducible_gotos()
                targetable_goto_cnt = len(self.goto_manager.gotos) - len(future_irreducible_gotos)
                if targetable_goto_cnt > self._starting_goto_count:
                    l.info(
                        f"{self.__class__.__name__} generated >= gotos then it started with "
                        f"{self._starting_goto_count} -> {targetable_goto_cnt}. Reverting..."
                    )
                    output_graph = False

            self.out_graph = add_labels(self.remove_broken_jumps(self.out_graph)) if output_graph else None

    def deduplication_analysis(self, max_fix_attempts=30, max_guarding_conditions=10):
        self.write_graph = remove_labels(to_ail_supergraph(copy_graph_and_nodes(self._graph)))

        updates = True
        while self._round <= max_fix_attempts:
            self._round += 1

            if updates:
                no_gotos = self._pre_deduplication_round()
                if no_gotos:
                    l.info(f"There are no gotos in this function {self.target_name}")
                    return

            l.info(f"Running analysis round: {self._round} on {self.target_name}")
            try:
                fake_duplication, updates = self._deduplication_round(max_guarding_conditions=max_guarding_conditions)
            except SAILRSemanticError as e:
                l.info(f"Skipping this round because of {e}...")
                continue

            if fake_duplication:
                continue

            if not updates:
                return

            l.info(f"Round {self._round} successful on {self.target_name}. Writing to graph now...")
            self._post_deduplication_round()
        else:
            raise Exception(f"Max fix attempts of {max_fix_attempts} done on function {self.target_name}")

    def _structure_graph(self):
        # reset gotos
        self.goto_manager = None

        # do structuring
        self.write_graph = add_labels(self.write_graph)
        self.ri = self.project.analyses[RegionIdentifier].prep(kb=self.kb)(
            self._func,
            graph=self.write_graph,
            cond_proc=self.ri.cond_proc,
            force_loop_single_exit=False,
            complete_successors=True,
        )
        rs = self.project.analyses[RecursiveStructurer].prep(kb=self.kb)(
            deepcopy(self.ri.region), cond_proc=self.ri.cond_proc, func=self._func, structurer_cls=PhoenixStructurer
        )
        self.write_graph = remove_labels(self.write_graph)
        if not rs.result.nodes:
            l.critical(f"Failed to redo structuring on {self.target_name}")
            return False

        rs = self.project.analyses.RegionSimplifier(self._func, rs.result, kb=self.kb, variable_kb=self._variable_kb)
        self.goto_manager = rs.goto_manager

        return True

    def _pre_deduplication_round(self):
        success = self._structure_graph()

        # collect gotos
        if self._starting_goto_count is None:
            self._starting_goto_count = len(self.goto_manager.gotos)

        if not success:
            if not _DEBUG:
                # revert graph when not in DEBUG mode
                if self.prev_graph is not None:
                    self.out_graph = self.prev_graph

            raise StructuringError

        if not self.goto_manager:
            return True

        # optimize the graph?
        self.write_graph = self.simple_optimize_graph(self.write_graph)
        return False

    def _post_deduplication_round(self):
        self.prev_graph = self.out_graph.copy() if self.out_graph is not None else self._graph
        self.out_graph = self.simple_optimize_graph(self.write_graph)
        self.write_graph = self.simple_optimize_graph(self.write_graph)

    def _deduplication_round(self, max_guarding_conditions=10):
        #
        # 0: Find candidates with duplicated AIL statements
        #

        self.read_graph: nx.DiGraph = self.write_graph.copy()
        candidates = self._find_initial_candidates()
        if not candidates:
            l.info("There are no duplicate statements in this function, stopping analysis")
            return False, False

        # with merge_candidates=False, max size for a candidate is 2
        candidates = self._filter_candidates(candidates, merge_candidates=False)
        if not candidates:
            l.info("There are no duplicate blocks in this function, stopping analysis")
            return False, False

        candidates = sorted(candidates, key=lambda x: len(x))
        l.info(f"Located {len(candidates)} candidates for merging: {candidates}")

        candidate = sorted(candidates.pop(), key=lambda x: x.addr)
        l.info(f"Selecting the candidate: {candidate}")

        ail_merge_graph = self.create_merged_subgraph(candidate, self.write_graph)
        candidate = ail_merge_graph.starts
        for block in ail_merge_graph.original_ends:
            if self._block_has_goto_edge(
                block, [b for b in ail_merge_graph.original_ends if b is not block], graph=self.write_graph
            ):
                break
        else:
            self.candidate_blacklist.add(tuple(candidate))
            l.info(f"Candidate {candidate} had no connecting gotos...")
            return True, False

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
            if (
                (not isinstance(last_stmt, (ConditionalJump, Jump)) and len(curr_succs) == 1)
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
            if isinstance(last_stmt, Jump) or isinstance(last_stmt, ConditionalJump):
                if isinstance(last_stmt, Jump):
                    if not isinstance(last_stmt.target, Const):
                        self.candidate_blacklist.add(tuple(candidate))
                        l.info(f"Candidate {candidate} is a child of an indirect-jump, which is not supported")
                        self.write_graph = self.read_graph.copy()
                        return True, False

                    target_addrs = [last_stmt.target.value] if isinstance(last_stmt.target, Const) else []
                elif isinstance(last_stmt, ConditionalJump):
                    target_addrs = [last_stmt.true_target.value, last_stmt.false_target.value]
                else:
                    raise Exception("Encountered a last statement that was neither a jump nor if")

                replacement_map = {}
                for target_addr in target_addrs:
                    target_candidates = []
                    for mblock, oblocks in ail_merge_graph.merge_blocks_to_originals.items():
                        for oblock in oblocks:
                            if isinstance(oblock, AILBlockSplit) and oblock.original.addr == target_addr:
                                target_candidates.append(mblock)
                            elif isinstance(oblock, Block) and oblock.addr == target_addr:
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
                            raise Exception("Unable to correct a predecessor, this is a bug!")

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
                    raise Exception("Unable to find the successor for block with no jump or condition!")

                self.write_graph.add_edge(orig_pred, new_succ)

        return False, True

    def _construct_best_condition_block_for_merge(self, blocks, graph) -> tuple[Block, Block]:
        # find the conditions that block both of these blocks
        common_cond = shared_common_conditional_dom(blocks, graph)
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
        new_block1, new_block2 = block1.copy(), block2.copy()

        updates = True
        prev_moved = set()
        while updates:
            updates = False
            lcs, lcs_idxs = longest_ail_subseq([new_block1.statements, new_block2.statements])
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

    def create_merged_subgraph(self, blocks, graph: nx.DiGraph) -> AILMergeGraph:
        # Before creating a full graph LCS, optimize the common seq between the starting blocks
        blocks = list(self.maximize_similarity_of_blocks(blocks[0], blocks[1], graph))

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
            new_node = list(ail_merge_graph.graph.nodes)[0]
            base_successor = list(graph.successors(blocks[0]))[0]
            other_successor = list(graph.successors(blocks[1]))[0]
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

        # colect the true and false targets for the condition
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

        # check if at least one block in succesors match
        mismatched_blocks = {}
        for target_type in block_to_target_map[block1].keys():
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
        # other or the same block, AND they have a mistmatch block D & E. We want to make a new NOP
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
                    self._unique_fake_addr,
                    0,
                    statements=[Jump(0, Const(0, 0, 0, self.project.arch.bits), 0, ins_addr=self._unique_fake_addr)],
                )
                self._unique_fake_addr += 1
                # point src -> nop -> dst
                graph.add_edge(src, nop_blk)
                graph.add_edge(nop_blk, dst)
                # unlink src -X-> dst
                graph.remove_edge(src, dst)
                # correct the targets of the src
                target = getattr(src.statements[-1], target_type)
                setattr(target, "value", nop_blk.addr)

        return True

    def _has_single_successor_path(self, source, target, graph):
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

        gotos = self.goto_manager.gotos_in_block(block)
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
                    gotos = self.goto_manager.gotos_in_block(pred)
                    # TODO: this is only valid for duplication reverter, but it should be better
                    if gotos and block.idx is not None:
                        return True

                    for goto in gotos:
                        if goto.dst_addr in (block.addr, block.statements[0].ins_addr):
                            return True

            for succ in graph.successors(block):
                last_stmt = succ.statements[-1]
                if isinstance(last_stmt, ConditionalJump):
                    gotos = self.goto_manager.gotos_in_block(succ)
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
        for goto in self.goto_manager.gotos:
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

    def collect_conditions_between_nodes(self, graph, source: Block, sinks: list[Block]):
        graph_nodes = set(sinks)
        for sink in sinks:
            paths_between = nx.all_simple_paths(graph, source=source, target=sink)
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
        # control flow to get to that target end. We get the reaching conditions to construct a gaurding
        # node later
        self.ri.cond_proc.recover_reaching_conditions(None, graph=full_condition_graph)
        conditions_by_start = {}
        for sink in sinks:
            if sink in self.ri.cond_proc.guarding_conditions:
                condition = self.ri.cond_proc.guarding_conditions[sink]
            elif sink in self.ri.cond_proc.reaching_conditions:
                condition = self.ri.cond_proc.reaching_conditions[sink]
            else:
                raise Exception(f"Unable to find the conditions for target: {sink}")

            condition = self.ri.cond_proc.simplify_condition(condition)
            if condition.is_true() or condition.is_false():
                condition = self.ri.cond_proc.simplify_condition(self.ri.cond_proc.reaching_conditions[sink])

            conditions_by_start[sink] = self.ri.cond_proc.convert_claripy_bool_ast(condition)

        return conditions_by_start

    #
    # Search Stages
    #

    def copy_cond_graph(self, merge_start_nodes, graph, idx=1):
        # [merge_node, nx.DiGraph: pre_graph]
        pre_graphs_maps = {}
        # [merge_node, nx.DiGraph: full_graph]
        graph_maps = {}
        # [merge_node, removed_nodes]
        removed_node_map = defaultdict(list)

        # create a subgraph for every merge_start and the dom
        shared_conditional_dom = shared_common_conditional_dom(merge_start_nodes, graph)
        for merge_start in merge_start_nodes:
            paths_between = nx.all_simple_paths(graph, source=shared_conditional_dom, target=merge_start)
            nodes_between = {node for path in paths_between for node in path}
            graph_maps[merge_start] = nx.subgraph(graph, nodes_between)

        # create remove nodes for nodes that are shared among all graphs (conditional nodes)
        for block0, graph0 in graph_maps.items():
            for node in graph0.nodes:
                for block1, graph1 in graph_maps.items():
                    if block0 == block1:
                        continue

                    if node in graph1.nodes:
                        removed_node_map[block0].append(node)

        # make the pre-graph from removing the nodes
        for block, blocks_graph in graph_maps.items():
            pre_graph = blocks_graph.copy()
            pre_graph.remove_nodes_from(removed_node_map[block])
            pre_graphs_maps[block] = pre_graph

        # make a conditional graph from any remove_nodes map (no deepcopy)
        temp_cond_graph: nx.DiGraph = nx.subgraph(graph, removed_node_map[merge_start_nodes[0]])

        # deep copy the graph and remove instructions that are not control flow altering
        cond_graph = nx.DiGraph()

        block_to_insn_map = {node.addr: node.statements[-1].ins_addr for node in temp_cond_graph.nodes()}
        for merge_start in merge_start_nodes:
            for node in pre_graphs_maps[merge_start].nodes:
                block_to_insn_map[node.addr] = merge_start.addr

        # fix nodes that don't end in a jump
        for node in temp_cond_graph:
            successors = list(temp_cond_graph.successors(node))
            if not isinstance(node.statements[-1], (ConditionalJump, Jump)) and len(successors) == 1:
                node.statements += [
                    Jump(
                        None, Const(None, None, successors[0].addr, self.project.arch.bits), ins_addr=successors[0].addr
                    )
                ]

        # deepcopy every node in the conditional graph with a unique address
        crafted_blocks = {}
        for edge in temp_cond_graph.edges:
            new_edge = ()
            for block in edge:
                last_stmt = block.statements[-1]

                try:
                    new_block = crafted_blocks[block.addr]
                except KeyError:
                    new_block = ail_block_from_stmts([deepcopy_ail_anyjump(last_stmt, idx=idx)])
                    crafted_blocks[block.addr] = new_block

                new_edge += (new_block,)
            cond_graph.add_edge(*new_edge)

        # graphs with no edges but only nodes
        if len(list(cond_graph.nodes)) == 0:
            for node in temp_cond_graph.nodes:
                last_stmt = node.statements[-1]
                cond_graph.add_node(ail_block_from_stmts([deepcopy_ail_anyjump(last_stmt, idx=idx)]))

        # correct every jump target
        for node in cond_graph.nodes:
            node.statements[-1] = correct_jump_targets(node.statements[-1], block_to_insn_map)

        return cond_graph, pre_graphs_maps

    def _update_subregions(self, updated_addrs, new_addrs):
        # for region in self.ri.regions_by_block_addrs:
        #    if any(addr in region for addr in updated_addrs):
        #        for new_addr in new_addrs:
        #            region.append(new_addr)
        ## make each index has a list of unique addrs
        # for i in range(len(self.ri.regions_by_block_addrs)):
        #    self.ri.regions_by_block_addrs[i] = list(set(self.ri.regions_by_block_addrs[i]))

        # refresh RegionIdentifier
        self.ri = self.project.analyses.RegionIdentifier(
            self.ri.function, cond_proc=self.ri.cond_proc, graph=self.write_graph
        )

    def _share_subregion(self, blocks: list[Block]) -> bool:
        for region in self.ri.regions_by_block_addrs:
            if all(block.addr in region for block in blocks):
                return True
        else:
            return False

    def _find_initial_candidates(self) -> list[tuple[Block, Block]]:
        initial_candidates = []
        for b0, b1 in combinations(self.read_graph.nodes, 2):
            # TODO: find a better fix for this! Some duplicated nodes need destruction!
            # skip purposefully duplicated nodes
            # if any(isinstance(b.idx, int) and b.idx > 0 for b in [b0, b1]):
            #   continue

            # if all([b.addr in [0x40cc9a, 0x40cdb5] for b in (b0, b1)]):
            #    do a breakpoint

            # blocks must have statements
            if not b0.statements or not b1.statements:
                continue

            # blocks must share a region
            if not self._share_subregion([b0, b1]):
                continue

            # must share a common dominator
            if not shared_common_conditional_dom([b0, b1], self.read_graph):
                continue

            # special case: when we only have a single stmt
            if len(b0.statements) == len(b1.statements) == 1:
                # Case 1:
                # [if(a)] == [if(b)]
                #
                # we must use the more expensive `similar` function to tell on the graph if they are
                # stmts that result in the same successors
                try:
                    stmt_is_similar = is_similar(b0, b1, graph=self.read_graph)
                except Exception:
                    continue

                # Case 2:
                # [if(a)] == [if(a)]
                # and at least one child for the correct target type matches
                if not stmt_is_similar:
                    # TODO: fix this and add it back
                    # is_similar = self.similar_conditional_when_single_corrected(b0, b1, self.write_graph)
                    pass

                if stmt_is_similar:
                    initial_candidates.append((b0, b1))
                    continue

            # check if these nodes share any stmt in common
            stmt_in_common = False
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
                    """
                    elif isinstance(src, Const) and self.project.loader.proj.find_object_containing(src.value) is None:
                        continue
                    """

                for stmt1 in b1.statements:
                    # XXX: used to be just likes()
                    if is_similar(stmt0, stmt1, graph=self.write_graph):
                        stmt_in_common = True
                        break

                if stmt_in_common:
                    pair = (b0, b1)
                    # only append pairs that share a dominator
                    if shared_common_conditional_dom(pair, self.write_graph) is not None:
                        initial_candidates.append(pair)

                    break

        initial_candidates = list(set(initial_candidates))
        initial_candidates.sort(key=lambda x: x[0].addr + x[1].addr)

        return initial_candidates

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

        #
        # First locate all the pairs that may actually be in a merge-graph of one of the already existent
        # pairs. This will look like a graph diff having a block existent in its list of nodes.
        #

        blk_descendants = {
            (b0, b1): set(nx.descendants(self.read_graph, b0)).union(
                set(nx.descendants(self.read_graph, b1)).union({b0, b1})
            )
            for b0, b1 in candidates
        }

        while True:
            removal_queue = []
            for candidate in candidates:
                if candidate in removal_queue:
                    continue

                stop = False
                for candidate2 in candidates:
                    if candidate2 == candidate or candidate2 not in blk_descendants:
                        continue

                    descendants = blk_descendants[candidate2]
                    if all(c in descendants for c in candidate):
                        removal_queue.append(candidate)
                        del blk_descendants[candidate]
                        stop = True
                        break

                if stop:
                    break

            if len(removal_queue) == 0:
                break

            l.debug(f"Removing descendant pair in candidate search: {removal_queue}")
            for pair in set(removal_queue):
                candidates.remove(pair)

        if not merge_candidates:
            return candidates

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
        candidates = sorted(candidates, key=lambda x: sum([c.addr for c in x]))

        return candidates

    #
    # Simple Optimizations (for cleanup)
    #

    def remove_simple_similar_blocks(self, graph: nx.DiGraph):
        """
        Removes blocks that have all statements that are similar and the same successors
        @param graph:
        @return:
        """
        change = False
        not_fixed = True
        while not_fixed:
            not_fixed = False
            nodes = list(graph.nodes())
            remove_queue = []

            for b0, b1 in itertools.combinations(nodes, 2):
                if not self._share_subregion([b0, b1]):
                    continue

                b0_suc, b1_suc = set(graph.successors(b0)), set(graph.successors(b1))

                # blocks should have the same successors
                if b0_suc != b1_suc:
                    continue

                # special case: when we only have a single stmt
                if len(b0.statements) == len(b1.statements) == 1:
                    try:
                        stmt_is_similar = is_similar(b0, b1, graph=graph)
                    except Exception:
                        continue

                    if not stmt_is_similar:
                        continue

                elif not b0.likes(b1):
                    continue

                remove_queue.append((b0, b1))
                break

            if not remove_queue:
                break

            l.debug(f"REMOVING IN SIMPLE_DUP: {remove_queue}")
            for b0, b1 in remove_queue:
                if not (graph.has_node(b0) or graph.has_node(b1)):
                    continue

                for suc in graph.successors(b1):
                    graph.add_edge(b0, suc)

                for pred in graph.predecessors(b1):
                    last_statement = pred.statements[-1]
                    pred.statements[-1] = correct_jump_targets(last_statement, {b1.addr: b0.addr})
                    graph.add_edge(pred, b0)

                graph.remove_node(b1)
                not_fixed = True
                change |= True

        return graph, change

    @staticmethod
    def remove_redundant_jumps(graph: nx.DiGraph):
        """
        This can destroy ConditionalJumps with 2 successors but only one is a real target

        @param graph:
        @return:
        """
        change = False
        while True:
            for target_blk in graph.nodes:
                if not target_blk.statements:
                    continue

                # must end in a jump of some sort
                last_stmt = target_blk.statements[-1]
                if not isinstance(last_stmt, (Jump, ConditionalJump)):
                    continue

                # never remove jumps that could have statements that are executed before them
                # OR
                # stmts that have a non-const jump (like a switch statement)
                if isinstance(last_stmt, Jump) and (
                    len(target_blk.statements) > 1 or not isinstance(last_stmt.target, ailment.expression.Const)
                ):
                    continue

                # must have successors otherwise we could be removing a final jump out of the function
                target_successors = list(graph.successors(target_blk))
                if not target_successors:
                    continue

                if isinstance(last_stmt, ConditionalJump):
                    if len(target_successors) > 2:
                        continue

                    if len(target_successors) == 2:
                        # skip real ConditionalJumps (ones with two different true/false target)
                        if last_stmt.true_target.value != last_stmt.false_target.value:
                            continue
                        # XXX: removed for now
                        # two successors, verify one is outdated and one matches the true_target value
                        # which gauntnees we can remove the other
                        if last_stmt.true_target.value not in [succ.addr for succ in target_successors]:
                            continue

                        # remove the outdated successor edge
                        outdated_blks = [blk for blk in target_successors if blk.addr != last_stmt.true_target.value]
                        if len(outdated_blks) != 1:
                            continue

                        outdated_blk = outdated_blks[0]
                        graph.remove_edge(target_blk, outdated_blk)
                        l.info(f"Removing simple redundant jump/cond: {(target_blk, outdated_blk)}")
                        # restart the search because we fixed edges
                        change |= True
                        break

                # At this point we have two situation:
                # - a single stmt node ending in a Jump
                # - a (possibly) multi-stmt node ending in a conditional Jump w/ 1 successor
                successor = target_successors[0]

                # In the case of the conditional jump with multiple statements before the jump, we just transfer this
                # block's statements over to the next block, excluding the jump
                if len(target_blk.statements) > 1:
                    successor.statements = target_blk.statements[:-1] + successor.statements

                # All the predecessors need to now point to the successor of the node that is about to be removed
                for pred in graph.predecessors(target_blk):
                    last_pred_stmt = pred.statements[-1]
                    pred.statements[-1] = correct_jump_targets(last_pred_stmt, {target_blk.addr: successor.addr})
                    graph.add_edge(pred, successor)

                graph.remove_node(target_blk)
                l.debug(f"removing node in simple redundant: {target_blk}")
                change |= True
                break
            else:
                # Finishing the loop without every breaking out of the loop means we did not change
                # anything in this iteration, which means we hit the Fixedpoint
                break

        return graph, change

    @staticmethod
    def remove_broken_jumps(graph: nx.DiGraph):
        """
        Removes jumps found in the middle of nodes from merging them into a single node
        """
        new_graph = nx.DiGraph()
        nodes_map = {}
        for node in graph:
            node_copy = node.copy()
            # remove Jumps from everything except the last node in the statements list
            node_copy.statements = [
                stmt for stmt in node_copy.statements[:-1] if not isinstance(stmt, Jump)
            ] + node_copy.statements[-1:]
            nodes_map[node] = node_copy

        new_graph.add_nodes_from(nodes_map.values())
        for src, dst in graph.edges:
            new_graph.add_edge(nodes_map[src], nodes_map[dst])

        return new_graph

    def simple_optimize_graph(self, graph):
        def _to_ail_supergraph(graph_):
            # make supergraph conversion always say no change
            return to_ail_supergraph(graph_), False

        new_graph = graph.copy()
        opts = [
            self.remove_redundant_jumps,
            _to_ail_supergraph,
        ]

        change = True
        while change:
            change = False
            for opt in opts:
                new_graph, has_changed = opt(new_graph)
                change |= has_changed

        return new_graph
