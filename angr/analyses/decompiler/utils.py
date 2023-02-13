# pylint:disable=wrong-import-position
from typing import Optional, Tuple, Any, Union

import networkx

import ailment


def remove_last_statement(node):
    stmt = None

    if type(node) is CodeNode:
        stmt = remove_last_statement(node.node)
    elif type(node) is ailment.Block:
        stmt = node.statements[-1]
        node.statements = node.statements[:-1]
    elif type(node) is MultiNode:
        if node.nodes:
            stmt = remove_last_statement(node.nodes[-1])
            if BaseNode.test_empty_node(node.nodes[-1]):
                node.nodes = node.nodes[:-1]
    elif type(node) is SequenceNode:
        if node.nodes:
            stmt = remove_last_statement(node.nodes[-1])
            if BaseNode.test_empty_node(node.nodes[-1]):
                node.nodes = node.nodes[:-1]
    elif type(node) is ConditionNode:
        if node.true_node is None and node.false_node is not None:
            stmt = remove_last_statement(node.false_node)
        elif node.true_node is not None and node.false_node is None:
            stmt = remove_last_statement(node.true_node)
        else:
            raise NotImplementedError("More than one last statement exist")
    else:
        raise NotImplementedError()

    return stmt


def append_statement(node, stmt):
    if type(node) is CodeNode:
        append_statement(node.node, stmt)
        return
    if type(node) is ailment.Block:
        node.statements.append(stmt)
        return
    if type(node) is MultiNode:
        if node.nodes:
            append_statement(node.nodes[-1], stmt)
        else:
            raise NotImplementedError()
        return
    if type(node) is SequenceNode:
        if node.nodes:
            append_statement(node.nodes[-1], stmt)
        else:
            raise NotImplementedError()
        return

    raise NotImplementedError()


def replace_last_statement(node, old_stmt, new_stmt):
    if type(node) is CodeNode:
        replace_last_statement(node.node, old_stmt, new_stmt)
        return
    if type(node) is ailment.Block:
        if node.statements[-1] is old_stmt:
            node.statements[-1] = new_stmt
        return
    if type(node) is MultiNode:
        if node.nodes:
            replace_last_statement(node.nodes[-1], old_stmt, new_stmt)
        return
    if type(node) is SequenceNode:
        if node.nodes:
            replace_last_statement(node.nodes[-1], old_stmt, new_stmt)
        return
    if type(node) is ConditionNode:
        if node.true_node is not None:
            replace_last_statement(node.true_node, old_stmt, new_stmt)
        if node.false_node is not None:
            replace_last_statement(node.false_node, old_stmt, new_stmt)
        return

    raise NotImplementedError()


def extract_jump_targets(stmt):
    """
    Extract concrete goto targets from a Jump or a ConditionalJump statement.

    :param stmt:    The statement to analyze.
    :return:        A list of known concrete jump targets.
    :rtype:         list
    """

    targets = []

    if isinstance(stmt, ailment.Stmt.Jump):
        if isinstance(stmt.target, ailment.Expr.Const):
            targets.append(stmt.target.value)
    elif isinstance(stmt, ailment.Stmt.ConditionalJump):
        if isinstance(stmt.true_target, ailment.Expr.Const):
            targets.append(stmt.true_target.value)
        if isinstance(stmt.false_target, ailment.Expr.Const):
            targets.append(stmt.false_target.value)

    return targets


def switch_extract_cmp_bounds(last_stmt: ailment.Stmt.ConditionalJump) -> Optional[Tuple[Any, int, int]]:
    """
    Check the last statement of the switch-case header node, and extract lower+upper bounds for the comparison.

    :param last_stmt:   The last statement of the switch-case header node.
    :return:            A tuple of (comparison expression, lower bound, upper bound), or None
    """

    if not isinstance(last_stmt, ailment.Stmt.ConditionalJump):
        return None

    # TODO: Add more operations
    if isinstance(last_stmt.condition, ailment.Expr.BinaryOp) and last_stmt.condition.op == "CmpLE":
        if not isinstance(last_stmt.condition.operands[1], ailment.Expr.Const):
            return None
        cmp_ub = last_stmt.condition.operands[1].value
        cmp_lb = 0
        cmp = last_stmt.condition.operands[0]
        if (
            isinstance(cmp, ailment.Expr.BinaryOp)
            and cmp.op == "Sub"
            and isinstance(cmp.operands[1], ailment.Expr.Const)
        ):
            cmp_ub += cmp.operands[1].value
            cmp_lb += cmp.operands[1].value
            cmp = cmp.operands[0]
        return cmp, cmp_lb, cmp_ub

    return None


def get_ast_subexprs(claripy_ast):
    queue = [claripy_ast]
    while queue:
        ast = queue.pop(0)
        if ast.op == "And":
            queue += ast.args[1:]
            yield ast.args[0]
        else:
            yield ast


def insert_node(parent, insert_location: str, node, node_idx: Optional[Union[int, Tuple[int]]], label=None):
    if insert_location not in {"before", "after"}:
        raise ValueError('"insert_location" must be either "before" or "after"')

    if isinstance(parent, SequenceNode):
        if insert_location == "before":
            parent.nodes.insert(node_idx, node)
        else:  # if insert_location == "after":
            parent.nodes.insert(node_idx + 1, node)
    elif isinstance(parent, CodeNode):
        # Make a new sequence node
        if insert_location == "before":
            seq = SequenceNode(parent.addr, nodes=[node, parent.node])
        else:  # if insert_location == "after":
            seq = SequenceNode(parent.addr, nodes=[parent.node, node])
        parent.node = seq
    elif isinstance(parent, MultiNode):
        if insert_location == "before":
            parent.nodes.insert(node_idx, node)
        else:
            parent.nodes.insert(node_idx + 1, node)
    elif isinstance(parent, ConditionNode):
        if node_idx == 0:
            # true node
            if not isinstance(parent.true_node, SequenceNode):
                if parent.true_node is None:
                    parent.true_node = SequenceNode(parent.addr, nodes=[])
                else:
                    parent.true_node = SequenceNode(parent.true_node.addr, nodes=[parent.true_node])
            insert_node(parent.true_node, insert_location, node, 0)
        else:
            # false node
            if not isinstance(parent.false_node, SequenceNode):
                if parent.false_node is None:
                    parent.false_node = SequenceNode(parent.addr, nodes=[])
                else:
                    parent.false_node = SequenceNode(parent.false_node.addr, nodes=[parent.false_node])
            insert_node(parent.false_node, insert_location, node, 0)
    elif isinstance(parent, CascadingConditionNode):
        cond, child_node = parent.condition_and_nodes[node_idx]
        if not isinstance(child_node, SequenceNode):
            child_node = SequenceNode(child_node.addr, nodes=[child_node])
            parent.condition_and_nodes[node_idx] = (cond, child_node)
        insert_node(child_node, insert_location, node, 0)
    elif isinstance(parent, SwitchCaseNode):
        # note that this case will be hit only when the parent node is not a container, such as SequenceNode or
        # MultiNode. we always need to create a new SequenceNode and replace the original node in place.

        if label == "switch_expr":
            raise TypeError("You cannot insert a node after an expression.")
        if label == "case":
            # node_idx is the case number.
            if insert_location == "after":
                new_nodes = [parent.cases[node_idx], node]
            elif insert_location == "before":
                new_nodes = [node, parent.cases[node_idx]]
            else:
                raise TypeError(f'Unsupported insert_location value "{insert_location}".')
            seq = SequenceNode(new_nodes[0].addr, nodes=new_nodes)
            parent.cases[node_idx] = seq
        elif label == "default":
            if insert_location == "after":
                new_nodes = [parent.default_node, node]
            elif insert_location == "before":
                new_nodes = [node, parent.default_node]
            else:
                raise TypeError("Unsupported 'insert_location' value %r." % insert_location)
            seq = SequenceNode(new_nodes[0].addr, nodes=new_nodes)
            parent.default_node = seq
        else:
            raise TypeError(
                f'Unsupported label value "{label}". Must be one of the following: switch_expr, case, ' f"default."
            )
    else:
        raise NotImplementedError()


def _merge_ail_nodes(graph, node_a: ailment.Block, node_b: ailment.Block) -> ailment.Block:
    in_edges = list(graph.in_edges(node_a, data=True))
    out_edges = list(graph.out_edges(node_b, data=True))

    new_node = node_a.copy() if node_a.addr <= node_b.addr else node_b.copy()
    old_node = node_b if new_node == node_a else node_a
    new_node.statements += old_node.statements
    new_node.original_size += old_node.original_size

    graph.remove_node(node_a)
    graph.remove_node(node_b)

    if new_node is not None:
        graph.add_node(new_node)

        for src, _, data in in_edges:
            if src is node_b:
                src = new_node
            graph.add_edge(src, new_node, **data)

        for _, dst, data in out_edges:
            if dst is node_a:
                dst = new_node
            graph.add_edge(new_node, dst, **data)

    return new_node


def to_ail_supergraph(transition_graph: networkx.DiGraph) -> networkx.DiGraph:
    """
    Takes an AIL graph and converts it into a AIL graph that treats calls and redundant jumps
    as parts of a bigger block instead of transitions. Calls to returning functions do not terminate basic blocks.

    Based on region_identifier super_graph

    :return: A converted super transition graph
    """
    # make a copy of the graph
    transition_graph = networkx.DiGraph(transition_graph)

    while True:
        for src, dst, data in transition_graph.edges(data=True):
            type_ = data.get("type", None)

            if len(list(transition_graph.successors(src))) == 1 and len(list(transition_graph.predecessors(dst))) == 1:
                # calls in the middle of blocks OR boring jumps
                if (type_ == "fake_return") or (src.addr + src.original_size == dst.addr):
                    _merge_ail_nodes(transition_graph, src, dst)
                    break

            # calls to functions with no return
            elif type_ == "call":
                transition_graph.remove_node(dst)
                break
        else:
            break

    return transition_graph


def is_empty_node(node) -> bool:
    if isinstance(node, ailment.Block):
        return not node.statements
    if isinstance(node, MultiNode):
        return all(is_empty_node(n) for n in node.nodes)
    if isinstance(node, SequenceNode):
        return all(is_empty_node(n) for n in node.nodes)
    return False


def is_empty_or_label_only_node(node) -> bool:
    if isinstance(node, ailment.Block):
        return not has_nonlabel_statements(node)
    if isinstance(node, MultiNode):
        return all(is_empty_or_label_only_node(n) for n in node.nodes)
    if isinstance(node, SequenceNode):
        return all(is_empty_or_label_only_node(n) for n in node.nodes)
    return False


def has_nonlabel_statements(block: ailment.Block) -> bool:
    return block.statements and any(not isinstance(stmt, ailment.Stmt.Label) for stmt in block.statements)


def first_nonlabel_statement(block: ailment.Block) -> Optional[ailment.Stmt.Statement]:
    for stmt in block.statements:
        if not isinstance(stmt, ailment.Stmt.Label):
            return stmt
    return None


def last_nonlabel_statement(block: ailment.Block) -> Optional[ailment.Stmt.Statement]:
    for stmt in reversed(block.statements):
        if not isinstance(stmt, ailment.Stmt.Label):
            return stmt
    return None


def first_nonlabel_node(seq: "SequenceNode") -> Optional[Union["BaseNode", ailment.Block]]:
    for node in seq.nodes:
        if isinstance(node, CodeNode):
            inner_node = node.node
        else:
            inner_node = node
        if isinstance(inner_node, ailment.Block) and not has_nonlabel_statements(inner_node):
            continue
        return node
    return None


def remove_labels(graph: networkx.DiGraph):
    new_graph = networkx.DiGraph()
    nodes_map = {}
    for node in graph:
        node_copy = node.copy()
        node_copy.statements = [stmt for stmt in node_copy.statements if not isinstance(stmt, ailment.Stmt.Label)]
        nodes_map[node] = node_copy

    new_graph.add_nodes_from(nodes_map.values())
    for src, dst in graph.edges:
        new_graph.add_edge(nodes_map[src], nodes_map[dst])

    return new_graph


# delayed import
from .structuring.structurer_nodes import (
    MultiNode,
    BaseNode,
    CodeNode,
    SequenceNode,
    ConditionNode,
    SwitchCaseNode,
    CascadingConditionNode,
)
