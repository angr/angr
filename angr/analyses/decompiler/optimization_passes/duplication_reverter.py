from collections import defaultdict
from copy import deepcopy
from typing import Optional
import logging
from itertools import combinations
import itertools

import networkx
import networkx as nx

import ailment
from ailment import AILBlockWalkerBase
from ailment.block import Block
from ailment.statement import Statement, ConditionalJump, Jump, Assignment
from ailment.expression import Const, Register, Convert, BinaryOp, Expression

from .optimization_pass import OptimizationPass, OptimizationPassStage
from ..block_io_finder import BlockIOFinder
from ..goto_manager import GotoManager
from ..region_identifier import RegionIdentifier
from ..structuring import RecursiveStructurer, PhoenixStructurer
from ..structuring.structurer_nodes import IncompleteSwitchCaseHeadStatement
from ....analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsAnalysis
from ..utils import to_ail_supergraph, remove_labels
from ....knowledge_plugins.key_definitions.atoms import MemoryLocation
from ....utils.graph import dominates

l = logging.getLogger(name=__name__)
_DEBUG = False
l.setLevel(logging.DEBUG)

#
# Exception Types
#


class StructuringError(Exception):
    """
    These types of errors are fatal and prevent any future working from structuring in this pass
    """

    pass


class SAILRSemanticError(Exception):
    """
    These types of errors may not kill the entire analysis, but they do kill the current working round.
    """

    pass


class UnsupportedAILNodeError(SAILRSemanticError):
    pass


#
# Util Classes
#


class ConditionBooleanWalker(AILBlockWalkerBase):
    """
    This class counts the number of Boolean operators an expression has.
    In the case of: `if (a || (b && c))`, it will count 2 Boolean operators.

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

    def __init__(self):
        super().__init__()
        self.boolean_cnt = 0

    def _handle_BinaryOp(
        self, expr_idx: int, expr: "BinaryOp", stmt_idx: int, stmt: "Statement", block: Optional["Block"]
    ):
        if expr.op == "LogicalAnd" or expr.op == "LogicalOr":
            self.boolean_cnt += 1

        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)


class AILMergeGraph:
    def __init__(
        self, graph=None, original_graph=None, conditional_block=None, original_blocks=None, original_split_blocks=None
    ):
        self.graph = graph or nx.DiGraph()
        self.original_graph = original_graph or nx.DiGraph()
        self.conditional_block = conditional_block

        # All the original blocks in both graphs that are going to be merged into a single
        # graph that is self.graph
        self.original_blocks: dict[Block, list[Block]] = original_blocks or {}

        # The mapping from an original_block in original_blocks to an AILBlockSplit,
        # which can have an up, match, and down split. This happens when only partial
        # blocks match from the original blocks
        self.original_split_blocks: dict[Block, list[AILBlockSplit]] = original_split_blocks or {}

        # The mapping from each block in the self.graph to the original blocks that
        # are contained in the larger CFG
        self.merge_blocks_to_originals: dict[Block, set[Block | AILBlockSplit]] = defaultdict(set)
        self.merge_end_to_start: dict[Block, Block] = {}
        self.starts = []
        self.original_ends = []

    def create_conditionless_graph(self, starting_blocks: list[Block], graph_lcs):
        # get all the original blocks (reverted from the LCS) and their split blocks.
        # split-blocks are blocks that need to be split at some stmt index to make the two blocks
        # equal across both graphs. At a highlevel, the first block in both matching graphs either need
        # to be a full match or a spilt block with a None up-split (since the up-split represent a starting
        # stmt that mismatches).
        self.starts = starting_blocks.copy()
        merge_base, other_base = self.starts[:]
        for block in self.starts:
            og_blks_bfs_order, split_blks = ail_similarity_to_orig_blocks(block, graph_lcs, self.original_graph)
            self.original_blocks[block] = og_blks_bfs_order
            self.original_split_blocks[block] = [
                AILBlockSplit.from_block_lcs(og, idx, len(lcs)) for og, (lcs, idx) in split_blks.items()
            ]

        # eliminate shared blocks that are the same in original blocks
        shared_blocks = set(self.original_blocks[merge_base]).intersection(set(self.original_blocks[other_base]))
        for shared_block in shared_blocks:
            for block in self.starts:
                if shared_block not in self.original_blocks[block]:
                    continue

                self.original_blocks[block].remove(shared_block)
                if shared_block in self.original_split_blocks[block]:
                    self.original_split_blocks[block].remove(shared_block)

        # we now know all the original blocks that will be merged, in order of BFS
        # so let's create the graph that will be the final output merged graph
        #
        # we start by finding all the blocks that are about to be split, i.e., blocks that
        # have at least one stmt mismatching from each other
        base_to_split = {
            split_block.original: split_block.match_split
            for split_block in self.original_split_blocks[merge_base]
            if split_block.match_split is not None
        }

        # we create a new graph, full of the original blocks of the base, with blocks
        # that should be split replaced.
        # this graph is only the initial merge_graph needed, where only the blocks
        self.graph, update_blocks = clone_graph_replace_splits(
            nx.subgraph(self.original_graph, self.original_blocks[merge_base]), base_to_split
        )
        self._update_all_split_refs(update_blocks)
        for update_block, new_block in update_blocks.items():
            if update_block in starting_blocks:
                idx = self.starts.index(update_block)
                self.starts[idx] = new_block
        merge_base, other_base = self.starts[:]

        # Add all the blocks that start the graph that may have been split
        # (i.e., only blocks in the blocks list for this function)
        for block in self.starts:
            for split_block in self.original_split_blocks[block]:
                if split_block.up_split:
                    merge_base_split = self._find_split_block_by_original(merge_base) or merge_base
                    merge_base_split = (
                        merge_base_split.match_split
                        if isinstance(merge_base_split, AILBlockSplit)
                        else merge_base_split
                    )

                    self.graph.add_edge(split_block.up_split, merge_base_split)

        return update_blocks

    def add_edges_to_condition(self, conditional_block, true_target, merge_end_pairs):
        for match_node, merge_end_pair in merge_end_pairs.items():
            cond_copy = conditional_block.copy()
            cond_copy.statements = [deepcopy_ail_anyjump(cond_copy.statements[0])]
            cond_copy.idx += 1

            # fix the condition edges
            cond_jump_stmt: ConditionalJump = cond_copy.statements[-1]
            if not merge_end_pair:
                l.info(f"Encountered a conditional jump that has no successors on {self.starts}!")
                raise SAILRSemanticError("Encountered a conditional jump that has no successors! This can be bad!")
            elif len(merge_end_pair) == 1:
                b0 = merge_end_pair[0]
                b0_og = list(self.merge_blocks_to_originals[b0])[0]
                if isinstance(b0_og, AILBlockSplit):
                    b0_og = b0_og.original

                b1_og = self._find_block_pair_in_originals(b0_og)
                if b1_og is None:
                    l.info(f"Encountered a conditional jump that has only 1 successor on {self.starts}!")
                    raise SAILRSemanticError(
                        f"Encountered a conditional jump that has only 1 successor on {self.starts}!"
                    )

                b1_og_succs = list(self.original_graph.successors(b1_og))
                assert len(b1_og_succs) == 1
                b1 = b1_og_succs[0]
            else:
                b0, b1 = merge_end_pair

            if true_target == self._find_og_start_by_merge_end(b0):
                cond_jump_stmt.true_target.value = b0.addr
                cond_jump_stmt.false_target.value = b1.addr
            else:
                cond_jump_stmt.false_target.value = b0.addr
                cond_jump_stmt.true_target.value = b1.addr

            self.graph.add_edge(match_node, cond_copy)
            self.graph.add_edge(cond_copy, b0)
            self.graph.add_edge(cond_copy, b1)

    def create_mapping_to_merge_graph(self, updated_blocks: dict[Block, Block], start_blocks: list[Block]):
        merge_base, other_base = self.starts[:]

        # collect all the normal blocks, which should be easy to pair
        for base, other in zip(self.original_blocks[merge_base], self.original_blocks[other_base]):
            if base in updated_blocks:
                base = updated_blocks[base]
            self.merge_blocks_to_originals[base] = {base, other}

        # collect all the split blocks, which have new addrs, and match them to merge_base
        for sblock in self.original_split_blocks[merge_base]:
            attrs = ("up_split", "match_split", "down_split")
            for attr in attrs:
                sblock_split = getattr(sblock, attr)
                if not sblock_split:
                    continue
                self.merge_blocks_to_originals[sblock_split].add(sblock)

        # finally, use the info from merge_base mapping to add to the mapping for other_base
        for sblock in self.original_split_blocks[other_base]:
            attrs = ("up_split", "match_split", "down_split")
            base_original = self._find_merge_block_by_original(sblock.original)
            for attr in attrs:
                sblock_split = getattr(sblock, attr)
                if not sblock_split:
                    continue

                if attr != "match_split":
                    self.merge_blocks_to_originals[sblock_split].add(sblock)
                    continue

                for base_split, base_sblocks in self.merge_blocks_to_originals.items():
                    # this split block must have only one pair right now
                    if len(base_sblocks) > 1:
                        continue

                    base_sblock = list(base_sblocks)[0]
                    # the original base must match
                    if base_sblock.original != base_original:
                        continue

                    # this split block must also be the right split (up, match, down)
                    if base_split != getattr(base_sblock, attr):
                        continue

                    self.merge_blocks_to_originals[base_split].add(sblock)

        # remove any extra block that will not be in the graph because it was split up
        deletable_blocks = set()
        end_pair_map = {}
        end_pairs = set()
        merge_to_end_pair = {}
        for split, sblocks in self.merge_blocks_to_originals.items():
            for sblock in sblocks:
                if isinstance(sblock, AILBlockSplit) and sblock.original in self.merge_blocks_to_originals:
                    deletable_blocks.add(sblock.original)
        for del_block in deletable_blocks:
            b0, b1 = self.merge_blocks_to_originals[del_block]
            end_pair_map[b0] = b1
            end_pair_map[b1] = b0
            end_pairs.add((b0, b1))
            merge_to_end_pair[del_block] = (b0, b1)
            del self.merge_blocks_to_originals[del_block]

        # mappings are collected, now we need to connect the merge ends of the graph to the upper parts with
        # the conditions that blocked the original
        merge_ends = {
            block: split for block, split in self.merge_blocks_to_originals.items() if block not in self.graph
        }
        assert all(len(bs) == 1 for block, bs in self.merge_blocks_to_originals.items() if block in merge_ends)
        self.merge_end_to_start = {merge_end: self._find_og_start_by_merge_end(merge_end) for merge_end in merge_ends}
        merge_end_pairs = defaultdict(list)
        for merge_end, split_blocks in merge_ends.items():
            split_block = list(split_blocks)[0]
            if split_block.original in self.original_blocks[merge_base]:
                merge_end_pairs[split_block.match_split].append(merge_end)
                continue

            merge_original = end_pair_map.get(split_block.original, None) or split_block.original
            base_split = self._find_split_block_by_original(merge_original)
            merge_end_pairs[base_split.match_split].append(merge_end)

        for pair in end_pairs:
            for block in pair:
                self.original_ends.append(block)
        # the case of single block merges
        if not self.original_ends:
            self.original_ends = start_blocks

        # moved here
        for unsplit_block, pair in merge_to_end_pair.items():
            for block in pair:
                other_block = pair[0] if pair[1] is block else pair[1]
                while True:
                    for merge, originals in self.merge_blocks_to_originals.items():
                        if self._block_in_originals(merge, other_block):
                            continue

                        if len(originals) == 1:
                            og = list(originals)[0]
                            if isinstance(og, Block) and og == block:
                                self.merge_blocks_to_originals[merge].add(other_block)
                                break

                        found = False
                        for og in originals:
                            if isinstance(og, AILBlockSplit) and og.original == block and merge == og.match_split:
                                self.merge_blocks_to_originals[merge].add(other_block)
                                found = True
                                break

                        if found:
                            break

                    else:
                        break

        return merge_end_pairs

    def merged_is_split_type(self, merge_block: Block, split_type: str):
        if split_type not in ["up_split", "down_split", "match_split"]:
            raise Exception("Can't call like this!")

        for oblock in self.merge_blocks_to_originals[merge_block]:
            if not isinstance(oblock, AILBlockSplit):
                continue

            if getattr(oblock, split_type) == merge_block:
                return True
        else:
            return False

    #
    # Private Functions
    #

    def _find_block_pair_in_originals(self, block: Block):
        for merge, originals in self.merge_blocks_to_originals.items():
            # need at least 2 for a pair
            if len(originals) < 2:
                continue

            # the block we are searching for a pair for should exist in the originals
            for og in originals:
                if isinstance(og, Block) and og == block:
                    break
                elif isinstance(og, AILBlockSplit) and og.original == block:
                    break
            else:
                return None

            # we now know that our target block is in this originals set
            # now we just need to find any other block that is not itself
            for other_block in originals:
                if isinstance(other_block, Block) and other_block != block:
                    return other_block
                elif isinstance(other_block, AILBlockSplit) and other_block.original != block:
                    return other_block.original

        return None

    def _block_in_any_blocks(self, block: Block, any_blocks):
        for any_block in any_blocks:
            if block == any_block:
                return True

            if isinstance(block, AILBlockSplit) and (
                block.up_split == block or block.match_split == block or block.down_split == block
            ):
                return True

        return False

    def _block_in_originals(self, merge_block: Block, target_block: Block):
        for original in self.merge_blocks_to_originals[merge_block]:
            if isinstance(original, Block):
                if original == target_block:
                    return True
            elif isinstance(original, AILBlockSplit):
                if original.original == target_block:
                    return True

        return False

    def _update_all_split_refs(self, update_map: dict[Block, Block]):
        for original, updated in update_map.items():
            for k in list(self.original_split_blocks.keys()):
                if k == original:
                    self.original_split_blocks[updated] = self.original_split_blocks[k]
                    del self.original_split_blocks[k]

            for k, v in self.original_split_blocks.items():
                for sblock in v:
                    for attr in ["up_split", "match_split", "down_split"]:
                        if getattr(sblock, attr) == original:
                            setattr(sblock, attr, updated)

            for k in list(self.original_blocks.keys()):
                if k == original:
                    self.original_blocks[updated] = self.original_blocks[k]
                    del self.original_blocks[k]

    def _find_merge_block_by_original(self, block: Block):
        for merge_block, originals in self.merge_blocks_to_originals.items():
            for og in originals:
                if isinstance(og, AILBlockSplit) and og.original == block:
                    return merge_block

                if isinstance(og, Block) and og == block:
                    return merge_block
        else:
            l.warning(f"Error in finding the merge block from the original block on {block}")
            return None

    def _find_split_block_by_original(self, block: Block):
        for _, split_blocks in self.original_split_blocks.items():
            for split_block in split_blocks:
                if split_block.original == block:
                    return split_block
        else:
            l.warning(f"Error in finding split block by original on {block}")
            return None

    def _find_og_start_by_merge_end(self, merge_end: Block):
        original = list(self.merge_blocks_to_originals[merge_end])[0]
        if isinstance(original, AILBlockSplit):
            original = original.original

        for og_start, og_blocks in self.original_blocks.items():
            if original in og_blocks:
                return og_start


class AILBlockSplit:
    def __init__(self, original=None, up_split=None, match_split=None, down_split=None):
        """

        :param original:
        :param up_split:   The block split above the matched LCS
        :param match_split:   The block containing only the matched LCS
        :param down_split:  The block split below the matched LCS
        """
        self.original = original
        self.up_split = up_split
        self.match_split = match_split
        self.down_split = down_split

    @classmethod
    def from_block_lcs(cls, original_block: Block, idx, len_):
        pre, mid, post = cls.split_ail_block(original_block, idx, len_)
        return cls(
            original=original_block,
            up_split=pre,
            match_split=mid,
            down_split=post,
        )

    @staticmethod
    def split_ail_block(block, split_idx, split_len) -> tuple[Block | None, Block | None, Block | None]:
        if split_len == len(block.statements):
            return None, block, None

        up_split = ail_block_from_stmts(block.statements[:split_idx], block_addr=block.addr)
        match_split = ail_block_from_stmts(
            block.statements[split_idx : split_idx + split_len], block_addr=None if up_split else block.addr
        )
        down_split = ail_block_from_stmts(block.statements[split_idx + split_len :])

        return up_split, match_split, down_split

    def __str__(self):
        return f"<AILBlockSplit: OG: {self.original.__repr__()} | Up: {self.up_split.__repr__()} | Match: {self.match_split.__repr__()} | Down: {self.down_split.__repr__()}>"

    def __repr__(self):
        return self.__str__()


#
# Graph Utils
#


def add_labels(graph: nx.DiGraph):
    new_graph = nx.DiGraph()
    nodes_map = {}
    for node in graph:
        lbl = ailment.Stmt.Label(None, f"LABEL_{node.addr:x}", node.addr, block_idx=node.idx)
        node_copy = node.copy()
        node_copy.statements = [lbl] + node_copy.statements
        nodes_map[node] = node_copy

    new_graph.add_nodes_from(nodes_map.values())
    for src, dst in graph.edges:
        new_graph.add_edge(nodes_map[src], nodes_map[dst])

    return new_graph


def remove_useless_gotos(graph: nx.DiGraph):
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


def find_block_by_similarity(block, graph, node_list=None):
    nodes = node_list if node_list else list(graph.nodes())
    similar_blocks = []
    for other_block in nodes:
        if similar(block, other_block, graph=graph):
            similar_blocks.append(other_block)

    if len(similar_blocks) > 1:
        l.warning("found multiple similar blocks")

    return similar_blocks[0]


def find_block_in_successors_by_addr(addr: int, block: ailment.Block, graph: nx.DiGraph):
    for succ in graph.successors(block):
        if succ.addr == addr or succ.statements[0].ins_addr == addr:
            return succ
    else:
        return None


def find_block_by_addr(graph: networkx.DiGraph, addr, insn_addr=False):
    if insn_addr:

        def _get_addr(b):
            return b.statements[0].ins_addr

    else:

        def _get_addr(b):
            return b.addr

    for block in graph.nodes():
        if _get_addr(block) == addr:
            break
    else:
        block = None
        raise Exception("The block is not in the graph!")

    return block


def clone_graph_replace_splits(graph: nx.DiGraph, split_map: dict[Block, Block]):
    # do a deepcopy, so we don't edit the original graph
    graph = copy_graph_and_nodes(graph)

    # replace every block that has been split
    updated_blocks = {}
    for original_node, new_node in split_map.items():
        graph.add_node(new_node)
        # correct every in_edge to this node, with new targets for jumps
        for pred in list(graph.predecessors(original_node)):
            new_pred = pred.copy()
            new_pred.statements[-1] = correct_jump_targets(
                new_pred.statements[-1], {original_node.addr: new_node.addr}, new_stmt=True
            )
            updated_blocks[pred] = new_pred
            replace_node_in_graph(graph, pred, new_pred)
            graph.add_edge(new_pred, new_node)

        # re-add every out_edge
        for succ in graph.successors(original_node):
            graph.add_edge(new_node, succ)

        # finally, kill the original
        if original_node in graph:
            graph.remove_node(original_node)

    return graph, updated_blocks


def clone_graph_with_splits(graph_param: nx.DiGraph, split_map_param):
    split_map = {(block.addr, block.idx): new_node for block, new_node in split_map_param.items()}
    graph = copy_graph_and_nodes(graph_param)
    # this loop will continue to iterate until there are no more
    # nodes found in the split_map to change
    while True:
        for node in graph.nodes():
            try:
                new_node = split_map[(node.addr, node.idx)]
                del split_map[(node.addr, node.idx)]
            except KeyError:
                continue

            break
        else:
            break

        graph.add_node(new_node)
        for pred in graph.predecessors(node):
            last_stmt = pred.statements[-1]
            pred.statements[-1] = correct_jump_targets(last_stmt, {node.addr: new_node.addr}, new_stmt=True)

            graph.add_edge(pred, new_node)

        for succ in graph.successors(node):
            graph.add_edge(new_node, succ)

        graph.remove_node(node)

    for node in graph.nodes():
        last_stmt = node.statements[-1]
        node.statements[-1] = correct_jump_targets(
            last_stmt, {orig_addr: new.addr for orig_addr, new in split_map.items()}, new_stmt=True
        )

    return graph


def replace_node_in_graph(graph: networkx.DiGraph, node, replace_with):
    in_edges = list(graph.in_edges(node))
    out_edges = list(graph.out_edges(node))

    graph.remove_node(node)
    graph.add_node(replace_with)

    for src, _ in in_edges:
        if src is node:
            graph.add_edge(replace_with, replace_with)
        else:
            graph.add_edge(src, replace_with)

    for _, dst in out_edges:
        if dst is node:
            graph.add_edge(replace_with, replace_with)
        else:
            graph.add_edge(replace_with, dst)

    assert node not in graph


def bfs_list_blocks(start_block: Block, graph: nx.DiGraph):
    blocks = []
    bfs = list(nx.bfs_successors(graph, start_block, depth_limit=10))
    for blk_tree in bfs:
        source, children = blk_tree
        last_src_stmt = source.statements[-1] if source.statements else None
        if (
            last_src_stmt is None
            or not isinstance(last_src_stmt, Statement)
            or isinstance(last_src_stmt, IncompleteSwitchCaseHeadStatement)
        ):
            raise UnsupportedAILNodeError(f"Stmt {last_src_stmt} is unsupported")

        if len(children) == 1:
            blocks += children
        elif len(children) == 2:
            if_stmt: ConditionalJump = source.statements[-1]
            if children[0].addr == if_stmt.true_target.value:
                blocks += [children[0], children[1]]
            else:
                blocks += [children[1], children[0]]

    blocks = [start_block] + blocks
    return blocks


def copy_graph_and_nodes(graph: nx.DiGraph, new_idx=False):
    """
    TODO: the function below this that does the same need to be deprecated
    """
    new_graph = nx.DiGraph()
    nodes_map = {}
    for node in graph.nodes:
        node_copy = node.copy()
        node_copy.statements = [stmt for stmt in node_copy.statements]
        if new_idx:
            node_copy.idx = node_copy.idx + 1 if isinstance(node_copy.idx, int) else 1
        nodes_map[node] = node_copy

    new_graph.add_nodes_from(nodes_map.values())
    for src, dst in graph.edges:
        new_graph.add_edge(nodes_map[src], nodes_map[dst])

    return new_graph


def shared_common_conditional_dom(nodes, graph: nx.DiGraph):
    """
    Takes n nodes and returns True only if all the nodes are dominated by the same node, which must be
    a ConditionalJump

    @param nodes:
    @param graph:
    @return:
    """
    try:
        entry_blk = [node for node in graph.nodes if graph.in_degree(node) == 0][0]
    except IndexError:
        return None

    idoms = nx.algorithms.immediate_dominators(graph, entry_blk)
    """
    ancestors = {
        node: list(nx.ancestors(graph, node)) for node in nodes
    }

    # no node for merging can be an ancestor to the other
    for node in nodes:
        other_ancestors = itertools.chain.from_iterable([ances for n, ances in ancestors.items() if n != node])
        if node in other_ancestors:
          return None
    """

    # first check if any of the node pairs could be a dominating loop
    b0, b1 = nodes[:]
    if dominates(idoms, b0, b1) or dominates(idoms, b1, b0):
        return None

    node = nodes[0]
    node_level = [node]
    seen_nodes = set()
    while node_level:
        # check if any of the nodes on the current level are dominaters to all nodes
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

    else:
        return None


#
# AIL Helpers
#


def similar(ail_obj1, ail_obj2, graph: nx.DiGraph = None, partial=True):
    if type(ail_obj1) is not type(ail_obj2):
        return False

    if ail_obj1 is ail_obj2:
        return True

    # AIL Blocks
    if isinstance(ail_obj1, Block):
        if len(ail_obj1.statements) != len(ail_obj2.statements):
            return False

        for stmt1, stmt2 in zip(ail_obj1.statements, ail_obj2.statements):
            if not similar(stmt1, stmt2, graph=graph):
                return False
        else:
            return True

    # AIL Statements
    elif isinstance(ail_obj1, Statement):
        # if all(barr in [0x404530, 0x404573] for barr in [ail_obj1.ins_addr, ail_obj2.ins_addr]):
        #    do a breakpoint

        # ConditionalJump Handler
        if isinstance(ail_obj1, ConditionalJump):
            # try a simple compare
            liked = ail_obj1.likes(ail_obj2)
            if liked or not graph:
                return liked

            # even in partial matching, the condition must at least match
            if not ail_obj1.condition.likes(ail_obj2.condition):
                return False

            # must use graph to know
            for attr in ["true_target", "false_target"]:
                t1, t2 = getattr(ail_obj1, attr).value, getattr(ail_obj2, attr).value
                try:
                    t1_blk, t2_blk = find_block_by_addr(graph, t1), find_block_by_addr(graph, t2)
                except Exception:
                    return False

                # special checks for when a node is empty:
                if not t1_blk.statements or not t2_blk.statements:
                    # when both are empty, they are similar
                    if len(t1_blk.statements) == len(t2_blk.statements):
                        continue

                    # TODO: implement a check for when one is empty and other is jump.
                    # this will require a recursive call into similar() to check if a jump and empty are equal
                    #
                    # when one block has a jump but the other is empty, they are possibly similar
                    # larger_blk = t1_blk if not t2_blk.statements else t2_blk
                    # if len(larger_blk.statements) == 1 and isinstance(larger_blk.statements[-1], Jump):
                    #    continue
                    return False

                # skip full checks when partial checking is on
                if partial and t1_blk.statements[0].likes(t2_blk.statements[0]):
                    continue

                if not similar(t1_blk, t2_blk, graph=graph):
                    return False
            else:
                return True

        # Generic Statement Handler
        else:
            return ail_obj1.likes(ail_obj2)
    else:
        return False


def ail_block_from_stmts(stmts, idx=None, block_addr=None) -> Block | None:
    if not stmts:
        return None

    first_stmt = stmts[0]

    return Block(
        first_stmt.ins_addr if not block_addr else block_addr,
        0,
        statements=[stmt for stmt in stmts],
        idx=idx or 1,
    )


def deepcopy_ail_jump(stmt: Jump, idx=1):
    target: Const = stmt.target
    tags = stmt.tags.copy()

    return Jump(idx, Const(1, target.variable, target.value, target.bits, **target.tags.copy()), **tags)


def deepcopy_ail_condjump(stmt: ConditionalJump, idx=1):
    true_target: Const = stmt.true_target
    false_target: Const = stmt.false_target
    tags = stmt.tags.copy()

    return ConditionalJump(
        idx,
        stmt.condition.copy(),
        Const(1, true_target.variable, true_target.value, true_target.bits, **true_target.tags.copy()),
        Const(1, false_target.variable, false_target.value, false_target.bits, **false_target.tags.copy()),
        **tags,
    )


def deepcopy_ail_anyjump(stmt: Jump | ConditionalJump, idx=1):
    if isinstance(stmt, Jump):
        return deepcopy_ail_jump(stmt, idx=idx)
    elif isinstance(stmt, ConditionalJump):
        return deepcopy_ail_condjump(stmt, idx=idx)
    else:
        raise Exception(
            "Attempting to deepcopy non-jump stmt, likely happen to a "
            "block ending in no jump. Place a jump there to fix it."
        )


def correct_jump_targets(stmt, replacement_map: dict[int, int], new_stmt=True):
    if not replacement_map or not isinstance(stmt, Statement):
        return stmt

    if isinstance(stmt, ConditionalJump):
        cond_stmt = deepcopy_ail_condjump(stmt) if new_stmt else stmt
        true_target, false_target = cond_stmt.true_target, cond_stmt.false_target

        if isinstance(true_target, Const) and true_target.value in replacement_map:
            true_target.value = replacement_map[true_target.value]

        if isinstance(false_target, Const) and false_target.value in replacement_map:
            false_target.value = replacement_map[false_target.value]

        return cond_stmt
    elif isinstance(stmt, Jump) and isinstance(stmt.target, Const):
        jump_stmt = deepcopy_ail_jump(stmt) if new_stmt else stmt
        target = jump_stmt.target

        if isinstance(target, Const) and target.value in replacement_map:
            target.value = replacement_map[target.value]

        return jump_stmt
    else:
        return stmt


#
# Longest Common Substring Search Helpers/Functions
#


def _kmp_search_ail_obj(search_pattern, stmt_seq, graph=None, partial=True):
    """
    Uses the Knuth-Morris-Pratt algorithm for searching.
    Found: https://code.activestate.com/recipes/117214/.

    Returns a generator of positions, which will be empty if its not found.
    """
    # allow indexing into pattern and protect against change during yield
    search_pattern = list(search_pattern)

    # build table of shift amounts
    shifts = [1] * (len(search_pattern) + 1)
    shift = 1
    for pos in range(len(search_pattern)):
        while shift <= pos and not similar(
            search_pattern[pos], search_pattern[pos - shift], graph=graph, partial=partial
        ):
            shift += shifts[pos - shift]
        shifts[pos + 1] = shift

    # do the actual search
    start_pos = 0
    match_len = 0
    for c in stmt_seq:
        while (
            match_len == len(search_pattern)
            or match_len >= 0
            and not similar(search_pattern[match_len], c, graph=graph, partial=partial)
        ):
            start_pos += shifts[match_len]
            match_len -= shifts[match_len]
        match_len += 1
        if match_len == len(search_pattern):
            yield start_pos


def stmts_pos_in_other(stmts, other, graph=None, all_positions=False):
    """
    Equivalent to asking:
    stmts in other

    @return: None or int (position start in other)
    """
    positions = list(_kmp_search_ail_obj(stmts, other, graph=graph))

    if len(positions) == 0:
        return None

    return positions.pop() if not all_positions else positions


def stmts_in_other(stmts, other, graph=None):
    """
    Returns True if the stmts (a list of Statement) is found as a subsequence in other

    @return:
    """

    if stmts_pos_in_other(stmts, other, graph=graph) is not None:
        return True

    return False


def longest_ail_subseq(stmts_list, graph=None):
    """
    Returns the LCS (a list of Statement) of the list of stmts (list of Statement).
    Returns LCS, [LCS_POS_IN_0, LCS_POS_IN_1, ..., LCS_POS_IN_N]

    @param stmts_list:
    @param graph:
    @return:
    """

    # find the longest sequence in all stmts
    subseq = []
    if len(stmts_list) <= 1:
        return stmts_list[0], 0

    if len(stmts_list[0]) > 0:
        for i in range(len(stmts_list[0])):
            for j in range(len(stmts_list[0]) - i + 1):
                if j > len(subseq) and all(
                    stmts_in_other(stmts_list[0][i : i + j], stmts, graph=graph) for stmts in stmts_list
                ):
                    subseq = stmts_list[0][i : i + j]

    if not subseq:
        return None, [None] * len(stmts_list)

    return subseq, [stmts_pos_in_other(subseq, stmts, graph=graph) for stmts in stmts_list]


def longest_ail_graph_subseq(block_list, graph):
    # generate a graph similarity for each pair in the provided blocks
    all_sims = [ail_graph_similarity(pair[0], pair[1], graph) for pair in itertools.combinations(block_list, 2)]

    lcs, _ = longest_ail_subseq(all_sims, graph=graph)
    return lcs


def ail_graph_similarity(block0: Block, block1: Block, graph: nx.DiGraph, only_blocks=False):
    b0_blocks = bfs_list_blocks(block0, graph)
    b1_blocks = bfs_list_blocks(block1, graph)
    similarity = []

    discontinuity_blocks = set()
    for i, b0 in enumerate(b0_blocks):
        # getting to a block with no matching index is grounds to stop cmp
        try:
            b1 = b1_blocks[i]
        except IndexError:
            break

        # if a block in the chain before did not end in LCS, don't follow it.
        if b0 in discontinuity_blocks or b1 in discontinuity_blocks:
            continue

        # SPECIAL CASE: 1
        # ┌─┐         ┌─┐
        # │A├─┐     ┌─┤A│
        # └─┘ │     │ └─┘
        #     ▼     ▼
        #    ┌──┐ ┌──┐
        #    │C'│ │C'│
        #    └┬─┘ └┬─┘
        #     │    │
        #     ▼    ▼
        #       ...
        #
        # Both similar blocks end in a block that is actually the same block. In this case, we don't
        # want to count this since we will create a N blocks long similarity that continues from C' all
        # the way to the end of the graph. This is only true if C' is not the end block of the graph.
        if b0 is b1:
            preds = list(graph.predecessors(b0))
            all_match = True
            for pred1 in preds:
                for pred2 in preds:
                    if set(list(graph.successors(pred1))) != set(list(graph.successors(pred2))):
                        all_match = False
                        break

                if not all_match:
                    break

            # CASE 1 confirmed, all edges in look the same. Now we check a special subset to see if the
            # matching node has any edges out. If this node has no edges out, we are no longer ture for 1A
            if all_match and len(list(graph.successors(b0))) != 0:
                continue

        lcs, lcs_idxs = longest_ail_subseq([b0.statements, b1.statements], graph=graph)
        if not lcs:
            break

        # verify all the blocks end in that statement or exclude its children
        for idx, b in enumerate([b0, b1]):
            if len(lcs) + lcs_idxs[idx] != len(b.statements):
                discontinuity_blocks.update(set(list(graph.successors(b))))

        # can output blocks only if needed
        similarity += lcs if not only_blocks else [(b0, b1)]

    return similarity


def ail_similarity_to_orig_blocks(orig_block, graph_similarity, graph):
    traversal_blocks = bfs_list_blocks(orig_block, graph)

    graph_sim = graph_similarity.copy()
    orig_blocks = []
    split_blocks = {}  # [block] = (lcs, idx)
    for block in traversal_blocks:
        if not graph_sim:
            break

        lcs, lcs_idxs = longest_ail_subseq([block.statements, graph_sim[: len(block.statements)]], graph=graph)
        if block is orig_block:
            lcs_1, lcs_idxs_1 = longest_ail_subseq([graph_sim[: len(block.statements)], block.statements], graph=graph)
            if lcs_idxs_1[1] > lcs_idxs[0]:
                lcs, lcs_idxs = lcs_1, lcs_idxs_1[::-1]

        if not lcs:
            break

        orig_blocks.append(block)

        if len(lcs) != len(block.statements):
            split_blocks[block] = (lcs, lcs_idxs[0])

        graph_sim = graph_sim[len(lcs) :]

    return orig_blocks, split_blocks


#
# Simple Optimizations
#


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
                    outdated_blk = [blk for blk in target_successors if blk.addr != last_stmt.true_target.value][0]

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


#
# Main Analysis
#


def all_has_path_to(sources: list[Block], sinks: list[Block], graph):
    for source in sources:
        for sink in sinks:
            has_path = False
            try:
                has_path = nx.has_path(graph, source, sink)
            except Exception:
                pass

            if not has_path:
                return False
    return True


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
        if _DEBUG:
            try:
                self.deduplication_analysis(max_fix_attempts=30)
            except StructuringError:
                l.critical(f"Structuring failed! This function {self.target_name} is dead in the water!")
        else:
            try:
                self.deduplication_analysis(max_fix_attempts=30)
            except StructuringError:
                l.critical(f"Structuring failed! This function {self.target_name} is dead in the water!")
            except Exception as e:
                l.critical(f"Encountered an error while de-duplicating on {self.target_name}: {e}")
                self.out_graph = None

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

            self.out_graph = add_labels(remove_useless_gotos(self.out_graph)) if output_graph else None

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
        walker = ConditionBooleanWalker()
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

                    unmatched_b2_positions = stmts_pos_in_other([b1_unmatched], b2.statements, all_positions=True)
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
            if not similar(t1_blk, t2_blk, partial=True):
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
                    is_similar = similar(b0, b1, graph=self.read_graph)
                except Exception:
                    continue

                # Case 2:
                # [if(a)] == [if(a)]
                # and at least one child for the correct target type matches
                if not is_similar:
                    # TODO: fix this and add it back
                    # is_similar = self.similar_conditional_when_single_corrected(b0, b1, self.write_graph)
                    pass

                if is_similar:
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
                    if similar(stmt0, stmt1, graph=self.write_graph):
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
                        is_similar = similar(b0, b1, graph=graph)
                    except Exception:
                        continue

                    if not is_similar:
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

    def simple_optimize_graph(self, graph):
        def _to_ail_supergraph(graph_):
            # make supergraph conversion always say no change
            return to_ail_supergraph(graph_), False

        new_graph = graph.copy()
        opts = [
            remove_redundant_jumps,
            _to_ail_supergraph,
        ]

        change = True
        while change:
            change = False
            for opt in opts:
                new_graph, has_changed = opt(new_graph)
                change |= has_changed

        return new_graph
