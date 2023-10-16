# pylint:disable=wrong-import-position
from typing import Optional, Tuple, Any, Union, List

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
    elif type(node) is LoopNode:
        stmt = remove_last_statement(node.sequence_node)
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
    elif isinstance(parent, LoopNode):
        if label == "condition":
            raise ValueError("Cannot insert nodes into a condition expression.")
        if label == "body":
            if not isinstance(parent.sequence_node, SequenceNode):
                parent.sequence_node = SequenceNode(parent.sequence_node.addr, nodes=[parent.sequence_node])
            insert_node(parent.sequence_node, insert_location, node, node_idx)
        else:
            raise NotImplementedError()
    else:
        raise NotImplementedError()


def _merge_ail_nodes(graph, node_a: ailment.Block, node_b: ailment.Block) -> ailment.Block:
    in_edges = list(graph.in_edges(node_a, data=True))
    out_edges = list(graph.out_edges(node_b, data=True))

    new_node = node_a.copy() if node_a.addr <= node_b.addr else node_b.copy()
    old_node = node_b if new_node == node_a else node_a
    # remove jumps in the middle of nodes when merging
    if new_node.statements and isinstance(new_node.statements[-1], ailment.Stmt.Jump):
        new_node.statements = new_node.statements[:-1]
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


def first_nonlabel_statement(block: Union[ailment.Block, "MultiNode"]) -> Optional[ailment.Stmt.Statement]:
    if isinstance(block, MultiNode):
        for n in block.nodes:
            stmt = first_nonlabel_statement(n)
            if stmt is not None:
                return stmt
        return None

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
    for src, dst, data in graph.edges(data=True):
        new_graph.add_edge(nodes_map[src], nodes_map[dst], **data)

    return new_graph


def structured_node_is_simple_return(node: Union["SequenceNode", "MultiNode"], graph: networkx.DiGraph) -> bool:
    """
    Will check if a "simple return" is contained within the node a simple returns looks like this:
    if (cond) {
      // simple return
      ...
      return 0;
    }
    ...

    Returns true on any block ending in linear statements and a return.
    """

    def _flatten_structured_node(packed_node: Union["SequenceNode", "MultiNode"]) -> List[ailment.Block]:
        if not packed_node or not packed_node.nodes:
            return []

        blocks = []
        if packed_node.nodes is not None:
            for _node in packed_node.nodes:
                if isinstance(_node, (SequenceNode, MultiNode)):
                    blocks += _flatten_structured_node(_node)
                else:
                    blocks.append(_node)

        return blocks

    # sanity check: we need a graph to understand returning blocks
    if graph is None:
        return False

    last_block = None
    if isinstance(node, (SequenceNode, MultiNode)) and node.nodes:
        flat_blocks = _flatten_structured_node(node)
        if all(isinstance(block, ailment.Block) for block in flat_blocks):
            last_block = flat_blocks[-1]
    elif isinstance(node, ailment.Block):
        last_block = node

    valid_last_stmt = last_block is not None
    if valid_last_stmt and last_block.statements:
        valid_last_stmt = not isinstance(last_block.statements[-1], (ailment.Stmt.ConditionalJump, ailment.Stmt.Jump))

    return valid_last_stmt and last_block in graph and not list(graph.successors(last_block))


def is_statement_terminating(stmt: ailment.statement.Statement, functions) -> bool:
    if isinstance(stmt, ailment.Stmt.Return):
        return True
    if isinstance(stmt, ailment.Stmt.Call) and isinstance(stmt.target, ailment.Expr.Const):
        # is it calling a non-returning function?
        target_func_addr = stmt.target.value
        try:
            func = functions.get_by_addr(target_func_addr)
            return func.returning is False
        except KeyError:
            pass
    return False


def peephole_optimize_exprs(block, expr_opts):
    class _any_update:
        """
        Local temporary class used as a container for variable `v`.
        """

        v = False

    def _handle_expr(
        expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int, stmt: Optional[ailment.Stmt.Statement], block
    ) -> Optional[ailment.Expr.Expression]:
        old_expr = expr

        redo = True
        while redo:
            redo = False
            for expr_opt in expr_opts:
                if isinstance(expr, expr_opt.expr_classes):
                    r = expr_opt.optimize(expr, stmt_idx=stmt_idx, block=block)
                    if r is not None and r is not expr:
                        expr = r
                        redo = True
                        break

        if expr is not old_expr:
            _any_update.v = True
            # continue to process the expr
            r = ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)
            return expr if r is None else r

        return ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

    # run expression optimizers
    walker = ailment.AILBlockWalker()
    walker._handle_expr = _handle_expr
    walker.walk(block)

    return _any_update.v


def peephole_optimize_expr(expr, expr_opts):
    def _handle_expr(
        expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int, stmt: Optional[ailment.Stmt.Statement], block
    ) -> Optional[ailment.Expr.Expression]:
        old_expr = expr

        redo = True
        while redo:
            redo = False
            for expr_opt in expr_opts:
                if isinstance(expr, expr_opt.expr_classes):
                    r = expr_opt.optimize(expr)
                    if r is not None and r is not expr:
                        expr = r
                        redo = True
                        break

        if expr is not old_expr:
            # continue to process the expr
            r = ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)
            return expr if r is None else r

        return ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

    # run expression optimizers
    walker = ailment.AILBlockWalker()
    walker._handle_expr = _handle_expr
    new_expr = walker._handle_expr(0, expr, 0, None, None)

    return new_expr


def peephole_optimize_stmts(block, stmt_opts):
    any_update = False
    statements = []

    # run statement optimizers
    for stmt_idx, stmt in enumerate(block.statements):
        old_stmt = stmt
        redo = True
        while redo:
            redo = False
            for opt in stmt_opts:
                if isinstance(stmt, opt.stmt_classes):
                    r = opt.optimize(stmt, stmt_idx=stmt_idx, block=block)
                    if r is not None and r is not stmt:
                        stmt = r
                        redo = True
                        break

        if stmt is not None and stmt is not old_stmt:
            statements.append(stmt)
            any_update = True
        else:
            statements.append(old_stmt)

    return statements, any_update


# delayed import
from .structuring.structurer_nodes import (
    MultiNode,
    BaseNode,
    CodeNode,
    SequenceNode,
    ConditionNode,
    SwitchCaseNode,
    CascadingConditionNode,
    LoopNode,
)
