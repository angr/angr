from __future__ import annotations
import logging
from collections import defaultdict

import networkx as nx

from ailment.block import Block
from ailment.statement import ConditionalJump

from .errors import SAILRSemanticError
from .similarity import ail_similarity_to_orig_blocks
from .utils import (
    copy_graph_and_nodes,
    replace_node_in_graph,
    ail_block_from_stmts,
    correct_jump_targets,
    deepcopy_ail_anyjump,
)

_l = logging.getLogger(name=__name__)


class AILBlockSplit:
    """
    This class represents a block that has been split into three parts, which is best explained in the
    AILMergeGraph class example. See that class for more information.

    The up_split, is all statements above the matched Longest Common Sequence (LCS), the match_split is the LCS,
    and the down_split is all statements below the matched LCS. This class should only be used in the context of
    the AILMergeGraph class.
    """

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
        return (
            f"<AILBlockSplit: OG: {self.original.__repr__()} | Up: {self.up_split.__repr__()} | "
            f"Match: {self.match_split.__repr__()} | Down: {self.down_split.__repr__()}>"
        )

    def __repr__(self):
        return self.__str__()


class AILMergeGraph:
    """
    This class represents the merged results of two AIL graphs that have been found to be similar. We can reference
    these graphs as G1 and G2. The two graphs are of the following form, where any node other than D can be empty:

        A
       / \
      B   C
      \\  /
       D
      / \
     E   F

    The D node can be a subgraph, but in both G1 and G2, this D-subgraph are exact duplicates of each
    other, except their top and bottom statements. This class is the result of merging those two D subgraphs.

    To explain that last part about statements differing at the ends, see this example:

    D1:
    -----
    a = 10;
    puts(a);
    puts("bye");
    -----

    D2:
    -----
    a = 11;
    puts(a);
    puts("cya");
    -----

    In this case, the merged D would contain just `puts(a)`. The statements above it, referred to as up_split in
    the code, and the statements below it, referred to as down_split in the code, would be moved out of the block
    and bounded by the conditions that lead to those statements. This creates a graph even in the case of a single
    block being the original D.

    Lastly, since this class will deal a lot with splitting blocks into pieces, we keep a mapping of how the original
    blocks turned into the new ones and vice versa.
    """

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
        self.graph, update_blocks = self.clone_graph_replace_splits(
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
                raise SAILRSemanticError("Encountered a conditional jump that has no successors! This can be bad!")
            if len(merge_end_pair) == 1:
                b0 = merge_end_pair[0]
                b0_og = next(iter(self.merge_blocks_to_originals[b0]))
                if isinstance(b0_og, AILBlockSplit):
                    b0_og = b0_og.original

                b1_og = self._find_block_pair_in_originals(b0_og)
                if b1_og is None:
                    raise SAILRSemanticError(
                        f"Encountered a conditional jump that has only 1 successor on {self.starts}!"
                    )

                b1_og_succs = list(self.original_graph.successors(b1_og))
                if len(b1_og_succs) != 1:
                    raise SAILRSemanticError(
                        "Encountered a merge-end pair which ends in a return, this should be skipped!"
                    )

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

                    base_sblock = next(iter(base_sblocks))
                    # the original base must match
                    if base_sblock.original != base_original:
                        continue

                    # this split block must also be the right split (up, match, down)
                    if base_split != getattr(base_sblock, attr):
                        continue

                    base_sblocks.add(sblock)

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
            split_block = next(iter(split_blocks))
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
        for _, pair in merge_to_end_pair.items():
            for block in pair:
                other_block = pair[0] if pair[1] is block else pair[1]
                while True:
                    for merge, originals in self.merge_blocks_to_originals.items():
                        if self._block_in_originals(merge, other_block):
                            continue

                        if len(originals) == 1:
                            og = next(iter(originals))
                            if isinstance(og, Block) and og == block:
                                originals.add(other_block)
                                break

                        found = False
                        for og in originals:
                            if isinstance(og, AILBlockSplit) and og.original == block and merge == og.match_split:
                                originals.add(other_block)
                                found = True
                                break

                        if found:
                            break

                    else:
                        break

        return merge_end_pairs

    def merged_is_split_type(self, merge_block: Block, split_type: str):
        if split_type not in ["up_split", "down_split", "match_split"]:
            raise ValueError("Must use a supported split type (up_split, down_split, match_split)")

        for oblock in self.merge_blocks_to_originals[merge_block]:
            if not isinstance(oblock, AILBlockSplit):
                continue

            if getattr(oblock, split_type) == merge_block:
                return True

        return False

    #
    # Private Functions
    #

    def _find_block_pair_in_originals(self, block: Block):
        for _, originals in self.merge_blocks_to_originals.items():
            # need at least 2 for a pair
            if len(originals) < 2:
                continue

            # the block we are searching for a pair for should exist in the originals
            for og in originals:
                if isinstance(og, Block) and og == block:
                    break
                if isinstance(og, AILBlockSplit) and og.original == block:
                    break
            else:
                return None

            # we now know that our target block is in this originals set
            # now we just need to find any other block that is not itself
            for other_block in originals:
                if isinstance(other_block, Block) and other_block != block:
                    return other_block
                if isinstance(other_block, AILBlockSplit) and other_block.original != block:
                    return other_block.original

        return None

    def _block_in_originals(self, merge_block: Block, target_block: Block):
        for original in self.merge_blocks_to_originals[merge_block]:
            if (isinstance(original, Block) and original == target_block) or (
                isinstance(original, AILBlockSplit) and original.original == target_block
            ):
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

        _l.warning("Error in finding the merge block from the original block on %s", block)
        return None

    def _find_split_block_by_original(self, block: Block) -> AILBlockSplit | None:
        for _, split_blocks in self.original_split_blocks.items():
            for split_block in split_blocks:
                if split_block.original == block:
                    return split_block

        _l.warning("Error in finding split block by original on %s", block)
        return None

    def _find_og_start_by_merge_end(self, merge_end: Block) -> Block | None:
        original = next(iter(self.merge_blocks_to_originals[merge_end]))
        if isinstance(original, AILBlockSplit):
            original = original.original

        for og_start, og_blocks in self.original_blocks.items():
            if original in og_blocks:
                return og_start

        return None

    @staticmethod
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
            blk = updated_blocks.get(original_node, original_node)
            for succ in graph.successors(blk):
                graph.add_edge(new_node, succ)

            # finally, kill the original
            if original_node in graph:
                graph.remove_node(original_node)

        return graph, updated_blocks
