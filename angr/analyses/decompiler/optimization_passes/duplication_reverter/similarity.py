from __future__ import annotations
import itertools
import logging

import networkx as nx

from ailment.block import Block

from .utils import bfs_list_blocks
from ...block_similarity import longest_ail_subseq, is_similar

_l = logging.getLogger(name=__name__)


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
                    if set(graph.successors(pred1)) != set(graph.successors(pred2)):
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
                discontinuity_blocks.update(set(graph.successors(b)))

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


def find_block_by_similarity(block, graph, node_list=None):
    nodes = node_list if node_list else list(graph.nodes())
    similar_blocks = []
    for other_block in nodes:
        if is_similar(block, other_block, graph=graph):
            similar_blocks.append(other_block)

    if len(similar_blocks) > 1:
        _l.warning("found multiple similar blocks")

    return similar_blocks[0]
