from typing import Optional, Tuple, Any

import ailment

from .structurer_nodes import MultiNode, BaseNode, CodeNode, SequenceNode, ConditionNode, SwitchCaseNode


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

    targets = [ ]

    if isinstance(stmt, ailment.Stmt.Jump):
        if isinstance(stmt.target, ailment.Expr.Const):
            targets.append(stmt.target.value)
    elif isinstance(stmt, ailment.Stmt.ConditionalJump):
        if isinstance(stmt.true_target, ailment.Expr.Const):
            targets.append(stmt.true_target.value)
        if isinstance(stmt.false_target, ailment.Expr.Const):
            targets.append(stmt.false_target.value)

    return targets


def switch_extract_cmp_bounds(last_stmt: ailment.Stmt.ConditionalJump) -> Optional[Tuple[Any,int,int]]:
    """
    Check the last statement of the switch-case header node, and extract lower+upper bounds for the comparison.

    :param last_stmt:   The last statement of the switch-case header node.
    :return:            A tuple of (comparison expression, lower bound, upper bound), or None
    """

    if not isinstance(last_stmt, ailment.Stmt.ConditionalJump):
        return None

    # TODO: Add more operations
    if last_stmt.condition.op == 'CmpLE':
        if not isinstance(last_stmt.condition.operands[1], ailment.Expr.Const):
            return None
        cmp_ub = last_stmt.condition.operands[1].value
        cmp_lb = 0
        cmp = last_stmt.condition.operands[0]
        if isinstance(cmp, ailment.Expr.BinaryOp) and \
                cmp.op == 'Sub' and \
                isinstance(cmp.operands[1], ailment.Expr.Const):
            cmp_ub += cmp.operands[1].value
            cmp_lb += cmp.operands[1].value
            cmp = cmp.operands[0]
        return cmp, cmp_lb, cmp_ub

    return None


def get_ast_subexprs(claripy_ast):

    queue = [ claripy_ast ]
    while queue:
        ast = queue.pop(0)
        if ast.op == "And":
            queue += ast.args[1:]
            yield ast.args[0]
        elif ast.op == "Or":
            # get the common subexpr of all operands
            common = None
            for arg in ast.args:
                subexprs = get_ast_subexprs(arg)
                if common is None:
                    common = set(subexprs)
                else:
                    common = common.intersection(subexprs)
                if len(common) == 0:
                    break
            for expr in common:
                yield expr
        else:
            yield ast


def insert_node(parent, insert_idx, node, node_idx, label=None, insert_location=None):

    if isinstance(parent, SequenceNode):
        parent.nodes.insert(insert_idx, node)
    elif isinstance(parent, CodeNode):
        # Make a new sequence node
        seq = SequenceNode(nodes=[parent.node, node])
        parent.node = seq
    elif isinstance(parent, MultiNode):
        parent.nodes.insert(insert_idx, node)
    elif isinstance(parent, ConditionNode):
        if node_idx == 0:
            # true node
            parent.true_node = SequenceNode(nodes=[parent.true_node])
            insert_node(parent.true_node, insert_idx - node_idx, node, 0)
        else:
            # false node
            parent.false_node = SequenceNode(nodes=[parent.false_node])
            insert_node(parent.false_node, insert_idx - node_idx, node, 0)
    elif isinstance(parent, SwitchCaseNode):
        # note that this case will be hit only when the parent node is not a container, such as SequenceNode or
        # MultiNode. we always need to create a new SequenceNode and replace the original node in place.
        if label == 'switch_expr':
            raise TypeError("You cannot insert a node after an expression.")
        if label == 'case':
            # node_idx is the case number
            if insert_location == 'after':
                new_nodes = [ parent.cases[node_idx], node ]
            elif insert_location == 'before':
                new_nodes = [ node, parent.cases[node_idx] ]
            else:
                raise TypeError("Unsupported 'insert_location' value %r." % insert_location)
            seq = SequenceNode(nodes=new_nodes)
            parent.cases[node_idx] = seq
        elif label == 'default':
            if insert_location == 'after':
                new_nodes = [ parent.default_node, node ]
            elif insert_location == 'before':
                new_nodes = [ node, parent.default_node ]
            else:
                raise TypeError("Unsupported 'insert_location' value %r." % insert_location)
            seq = SequenceNode(nodes=new_nodes)
            parent.default_node = seq
    else:
        raise NotImplementedError()
