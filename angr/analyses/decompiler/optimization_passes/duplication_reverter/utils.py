import itertools
import logging

import networkx
import networkx as nx

import ailment
from ailment import Const
from ailment.block import Block
from ailment.statement import Statement, ConditionalJump, Jump

from .errors import UnsupportedAILNodeError
from ...structuring.structurer_nodes import IncompleteSwitchCaseHeadStatement
from .....utils.graph import dominates


_l = logging.getLogger(name=__name__)


#
# Graph Utilities
#


def find_block_in_successors_by_addr(addr: int, block: ailment.Block, graph: nx.DiGraph):
    for succ in graph.successors(block):
        if succ.addr == addr or succ.statements[0].ins_addr == addr:
            return succ
    else:
        return None


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
# AIL Modification Utilities
#


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
