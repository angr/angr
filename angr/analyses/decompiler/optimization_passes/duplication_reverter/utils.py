from __future__ import annotations
import logging

import networkx as nx

import ailment
from ailment import Const
from ailment.block import Block
from ailment.statement import Statement, ConditionalJump, Jump

from .errors import UnsupportedAILNodeError
from ...structuring.structurer_nodes import IncompleteSwitchCaseHeadStatement


_l = logging.getLogger(name=__name__)


#
# Graph Utilities
#


def find_block_in_successors_by_addr(addr: int, block: ailment.Block, graph: nx.DiGraph) -> Block | None:
    for succ in graph.successors(block):
        if addr in (succ.addr, succ.statements[0].ins_addr):
            return succ

    return None


def replace_node_in_graph(graph: nx.DiGraph, node, replace_with):
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

    return [start_block, *blocks]


def copy_graph_and_nodes(graph: nx.DiGraph, new_idx=False):
    new_graph = nx.DiGraph()
    nodes_map = {}
    for node in graph.nodes:
        node_copy = node.copy()
        node_copy.statements = list(node_copy.statements)
        if new_idx:
            node_copy.idx = node_copy.idx + 1 if isinstance(node_copy.idx, int) else 1
        nodes_map[node] = node_copy

    new_graph.add_nodes_from(nodes_map.values())
    for src, dst in graph.edges:
        new_graph.add_edge(nodes_map[src], nodes_map[dst])

    return new_graph


#
# AIL Modification Utilities
#


def ail_block_from_stmts(stmts, idx=None, block_addr=None) -> Block | None:
    if not stmts:
        return None

    first_stmt = stmts[0]

    return Block(
        block_addr if block_addr else first_stmt.ins_addr,
        0,
        statements=list(stmts),
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
    if isinstance(stmt, ConditionalJump):
        return deepcopy_ail_condjump(stmt, idx=idx)
    raise ValueError(
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
    if isinstance(stmt, Jump) and isinstance(stmt.target, Const):
        jump_stmt = deepcopy_ail_jump(stmt) if new_stmt else stmt
        target = jump_stmt.target

        if isinstance(target, Const) and target.value in replacement_map:
            target.value = replacement_map[target.value]

        return jump_stmt
    return stmt
