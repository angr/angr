
import ailment

from .structurer_nodes import MultiNode, BaseNode, CodeNode, SequenceNode


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


def switch_extract_cmp_bounds(last_stmt):
    """
    Check the last statement of the switch-case header node, and extract lower+upper bounds for the comparison.

    :param ailment.Stmt last_stmt:  The last statement of the switch-case header node.
    :return:                        A tuple of (comparison expression, lower bound, upper bound), or None
    :rtype:                         tuple|None
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


def insert_node(parent, idx, node):

    if isinstance(parent, SequenceNode):
        parent.nodes.insert(idx, node)
    elif isinstance(parent, CodeNode):
        # Make a new sequence node
        seq = SequenceNode(nodes=[parent.node, node])
        parent.node = seq
    elif isinstance(parent, MultiNode):
        parent.nodes.insert(idx, node)
    else:
        raise NotImplementedError()
