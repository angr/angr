
import logging

import networkx

import claripy
import ailment

from ...utils.graph import dominates
from ...block import Block, BlockNode
from ..cfg.cfg_utils import CFGUtils
from .structurer_nodes import (EmptyBlockNotice, SequenceNode, CodeNode, SwitchCaseNode, BreakNode,
                               ConditionalBreakNode, LoopNode, ConditionNode, ContinueNode)
from .utils import extract_jump_targets, switch_extract_cmp_bounds

l = logging.getLogger(__name__)


class ConditionProcessor:
    """
    Convert between claripy AST and AIL expressions. Also calculates reaching conditions of all nodes on a graph.
    """
    def __init__(self, condition_mapping=None):
        self._condition_mapping = {} if condition_mapping is None else condition_mapping
        self.reaching_conditions = {}

    def clear(self):
        self._condition_mapping.clear()
        self.reaching_conditions.clear()

    def recover_reaching_conditions(self, region, with_successors=False, jump_tables=None):

        def _strictly_postdominates(inv_idoms, node_a, node_b):
            """
            Does node A strictly post-dominate node B on the graph?
            """
            return dominates(inv_idoms, node_a, node_b)

        edge_conditions = {}
        predicate_mapping = {}
        # traverse the graph to recover the condition for each edge
        for src in region.graph.nodes():
            nodes = list(region.graph[src])
            if len(nodes) >= 1:
                for dst in nodes:
                    edge = src, dst
                    predicate = self._extract_predicate(src, dst)
                    edge_conditions[edge] = predicate
                    predicate_mapping[predicate] = dst

        if jump_tables:
            self.recover_reaching_conditions_for_jumptables(region, jump_tables, edge_conditions)

        if with_successors:
            _g = region.graph_with_successors
        else:
            _g = region.graph
        end_nodes = {n for n in _g.nodes() if _g.out_degree(n) == 0}
        if end_nodes:
            inverted_graph = networkx.reverse(_g)
            if len(end_nodes) > 1:
                # make sure there is only one end node
                dummy_node = "DUMMY_NODE"
                for end_node in end_nodes:
                    inverted_graph.add_edge(dummy_node, end_node)
                endnode = dummy_node
            else:
                endnode = next(iter(end_nodes))  # pick the end node

            idoms = networkx.immediate_dominators(inverted_graph, endnode)
        else:
            idoms = None

        reaching_conditions = {}
        # recover the reaching condition for each node
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(_g)
        for node in sorted_nodes:
            preds = _g.predecessors(node)
            reaching_condition = None

            if node is region.head:
                # the head is always reachable
                reaching_condition = claripy.true
            elif idoms is not None and _strictly_postdominates(idoms, node, region.head):
                # the node that post dominates the head is always reachable
                reaching_conditions[node] = claripy.true
            else:
                for pred in preds:
                    edge = (pred, node)
                    pred_condition = reaching_conditions.get(pred, claripy.true)
                    edge_condition = edge_conditions.get(edge, claripy.true)

                    if reaching_condition is None:
                        reaching_condition = claripy.And(pred_condition, edge_condition)
                    else:
                        reaching_condition = claripy.Or(claripy.And(pred_condition, edge_condition), reaching_condition)

            if reaching_condition is not None:
                reaching_conditions[node] = self.simplify_condition(reaching_condition)

        self.reaching_conditions = reaching_conditions

    def recover_reaching_conditions_for_jumptables(self, region, jump_tables, edge_conditions):

        addr2nodes = dict((node.addr, node) for node in region.graph.nodes())

        # special handling for jump tables
        for src in region.graph.nodes():
            try:
                last_stmt = self.get_last_statement(src)
            except EmptyBlockNotice:
                continue
            successor_addrs = extract_jump_targets(last_stmt)
            if len(successor_addrs) != 2:
                continue

            for t in successor_addrs:
                if t in addr2nodes and t in jump_tables:
                    # this is a candidate!
                    target = t
                    break
            else:
                continue

            cmp = switch_extract_cmp_bounds(last_stmt)
            if not cmp:
                continue

            cmp_expr, cmp_lb, cmp_ub = cmp  # pylint:disable=unused-variable

            jump_table = jump_tables[target]
            node_a = addr2nodes[target]

            # edge conditions
            for i, entry_addr in enumerate(jump_table.jumptable_entries):
                cond = self.claripy_ast_from_ail_condition(cmp_expr) == i + cmp_lb
                edge = node_a, addr2nodes[entry_addr]
                edge_conditions[edge] = cond

    def remove_claripy_bool_asts(self, node):

        # Convert claripy Bool ASTs to AIL expressions

        if isinstance(node, SequenceNode):
            new_nodes = [ ]
            for n in node.nodes:
                new_node = self.remove_claripy_bool_asts(n)
                new_nodes.append(new_node)
            new_seq_node = SequenceNode(new_nodes)
            return new_seq_node

        elif isinstance(node, MultiNode):
            new_nodes = [ ]
            for n in node.nodes:
                new_node = self.remove_claripy_bool_asts(n)
                new_nodes.append(new_node)
            new_multinode = MultiNode(nodes=new_nodes)
            return new_multinode

        elif isinstance(node, CodeNode):
            node = CodeNode(self.remove_claripy_bool_asts(node.node),
                            None if node.reaching_condition is None
                            else self.convert_claripy_bool_ast(node.reaching_condition))
            return node

        elif isinstance(node, ConditionalBreakNode):

            return ConditionalBreakNode(node.addr,
                                        self.convert_claripy_bool_ast(node.condition),
                                        node.target,
                                        )

        elif isinstance(node, ConditionNode):

            return ConditionNode(node.addr,
                                 None if node.reaching_condition is None else
                                    self.convert_claripy_bool_ast(node.reaching_condition),
                                 self.convert_claripy_bool_ast(node.condition),
                                 self.remove_claripy_bool_asts(node.true_node),
                                 self.remove_claripy_bool_asts(node.false_node),
                                 )

        elif isinstance(node, LoopNode):

            return LoopNode(node.sort,
                            self.convert_claripy_bool_ast(node.condition) if node.condition is not None else None,
                            self.remove_claripy_bool_asts(node.sequence_node),
                            addr=node.addr,
                            )

        elif isinstance(node, SwitchCaseNode):
            return SwitchCaseNode(self.convert_claripy_bool_ast(node.switch_expr),
                                  dict((idx, self.remove_claripy_bool_asts(case_node))
                                       for idx, case_node in node.cases.items()),
                                  self.remove_claripy_bool_asts(node.default_node),
                                  addr=node.addr)

        else:
            return node

    def get_last_statement(self, block):
        if type(block) is SequenceNode:
            if block.nodes:
                return self.get_last_statement(block.nodes[-1])
        elif type(block) is CodeNode:
            return self.get_last_statement(block.node)
        elif type(block) is ailment.Block:
            if not block.statements:
                raise EmptyBlockNotice()
            return block.statements[-1]
        elif type(block) is Block:
            raise NotImplementedError()
        elif type(block) is BlockNode:
            raise NotImplementedError()
        elif type(block) is MultiNode:
            # get the last node
            for the_block in reversed(block.nodes):
                try:
                    last_stmt = self.get_last_statement(the_block)
                    return last_stmt
                except EmptyBlockNotice:
                    continue
        elif type(block) is LoopNode:
            return self.get_last_statement(block.sequence_node)
        elif type(block) is ConditionalBreakNode:
            return None
        elif type(block) is ConditionNode:
            s = None
            if block.true_node:
                s = self.get_last_statement(block.true_node)
            if s is None and block.false_node:
                s = self.get_last_statement(block.false_node)
            return s
        elif type(block) is BreakNode:
            return None
        elif type(block) is ContinueNode:
            return None
        elif type(block) is SwitchCaseNode:
            return None
        elif type(block) is GraphRegion:
            # normally this should not happen. however, we have test cases that trigger this case.
            return None

        raise NotImplementedError()

    #
    # Path predicate
    #

    def _extract_predicate(self, src_block, dst_block):

        if type(src_block) is ConditionalBreakNode:
            # at this point ConditionalBreakNode stores a claripy AST
            bool_var = src_block.condition
            if src_block.target == dst_block.addr:
                return bool_var
            else:
                return claripy.Not(bool_var)

        if type(src_block) is GraphRegion:
            return claripy.true

        last_stmt = self.get_last_statement(src_block)

        if last_stmt is None:
            return claripy.true
        if type(last_stmt) is ailment.Stmt.Jump:
            if isinstance(last_stmt.target, ailment.Expr.Const):
                return claripy.true
            # indirect jump
            target_ast = self.claripy_ast_from_ail_condition(last_stmt.target)
            return target_ast == dst_block.addr
        if type(last_stmt) is ailment.Stmt.ConditionalJump:
            bool_var = self.claripy_ast_from_ail_condition(last_stmt.condition)
            if last_stmt.true_target.value == dst_block.addr:
                return bool_var
            else:
                return claripy.Not(bool_var)

        return claripy.true

    #
    # Expression conversion
    #

    def convert_claripy_bool_ast(self, cond):
        """
        Convert recovered reaching conditions from claripy ASTs to ailment Expressions

        :return: None
        """

        if isinstance(cond, ailment.Expr.Expression):
            return cond

        if cond.op == "BoolS" and claripy.is_true(cond):
            return cond
        if cond in self._condition_mapping:
            return self._condition_mapping[cond]

        def _binary_op_reduce(op, args, signed=False):
            r = None
            for arg in args:
                if r is None:
                    r = self.convert_claripy_bool_ast(arg)
                else:
                    r = ailment.Expr.BinaryOp(None, op, (r, self.convert_claripy_bool_ast(arg)), signed)
            return r

        _mapping = {
            'Not': lambda cond_: ailment.Expr.UnaryOp(None, 'Not', self.convert_claripy_bool_ast(cond_.args[0])),
            'And': lambda cond_: _binary_op_reduce('LogicalAnd', cond_.args),
            'Or': lambda cond_: _binary_op_reduce('LogicalOr', cond_.args),
            '__le__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLE',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          True),
            'SLE': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLE',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       True),
            '__lt__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLT',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          True),
            'SLT': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLT',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       True),
            'UGT': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGT',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       False),
            'UGE': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGE',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       False),
            '__gt__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGT',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          True),
            '__ge__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGE',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          True),
            'SGT': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGT',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       True),
            'SGE': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGE',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       True),
            'ULT': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLT',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       False),
            'ULE': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLE',
                                                       tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                       False),
            '__eq__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpEQ',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          False),
            '__ne__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpNE',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          False),
            '__add__': lambda cond_: ailment.Expr.BinaryOp(None, 'Add',
                                                           tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                           False),
            '__sub__': lambda cond_: ailment.Expr.BinaryOp(None, 'Sub',
                                                           tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                           False),
            '__xor__': lambda cond_: ailment.Expr.BinaryOp(None, 'Xor',
                                                           tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                           False),
            '__or__': lambda cond_: ailment.Expr.BinaryOp(None, 'Or',
                                                          tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                          False),
            '__and__': lambda cond_: ailment.Expr.BinaryOp(None, 'And',
                                                           tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                           False),
            'LShR': lambda cond_: ailment.Expr.BinaryOp(None, 'Shr',
                                                        tuple(map(self.convert_claripy_bool_ast, cond_.args)),
                                                        False),
            'BVV': lambda cond_: ailment.Expr.Const(None, None, cond_.args[0], cond_.size()),
            'BoolV': lambda cond_: ailment.Expr.Const(None, None, True, 1) if cond_.args[0] is True
                                                                        else ailment.Expr.Const(None, None, False, 1),
        }

        if cond.op in _mapping:
            return _mapping[cond.op](cond)
        raise NotImplementedError(("Condition variable %s has an unsupported operator %s. "
                                   "Consider implementing.") % (cond, cond.op))

    def claripy_ast_from_ail_condition(self, condition):

        # Unpack a condition all the way to the leaves
        if isinstance(condition, claripy.ast.Base):
            return condition

        _mapping = {
            'LogicalAnd': lambda expr, conv: claripy.And(conv(expr.operands[0]), conv(expr.operands[1])),
            'LogicalOr': lambda expr, conv: claripy.Or(conv(expr.operands[0]), conv(expr.operands[1])),
            'CmpEQ': lambda expr, conv: conv(expr.operands[0]) == conv(expr.operands[1]),
            'CmpNE': lambda expr, conv: conv(expr.operands[0]) != conv(expr.operands[1]),
            'CmpLE': lambda expr, conv: conv(expr.operands[0]) <= conv(expr.operands[1]),
            'CmpLEs': lambda expr, conv: claripy.SLE(conv(expr.operands[0]), conv(expr.operands[1])),
            'CmpLT': lambda expr, conv: conv(expr.operands[0]) < conv(expr.operands[1]),
            'CmpLTs': lambda expr, conv: claripy.SLT(conv(expr.operands[0]), conv(expr.operands[1])),
            'CmpGE': lambda expr, conv: conv(expr.operands[0]) >= conv(expr.operands[1]),
            'CmpGEs': lambda expr, conv: claripy.SGE(conv(expr.operands[0]), conv(expr.operands[1])),
            'CmpGT': lambda expr, conv: conv(expr.operands[0]) > conv(expr.operands[1]),
            'CmpGTs': lambda expr, conv: claripy.SGT(conv(expr.operands[0]), conv(expr.operands[1])),
            'Add': lambda expr, conv: conv(expr.operands[0]) + conv(expr.operands[1]),
            'Sub': lambda expr, conv: conv(expr.operands[0]) - conv(expr.operands[1]),
            'Not': lambda expr, conv: claripy.Not(conv(expr.operand)),
            'Xor': lambda expr, conv: conv(expr.operands[0]) ^ conv(expr.operands[1]),
            'And': lambda expr, conv: conv(expr.operands[0]) & conv(expr.operands[1]),
            'Or': lambda expr, conv: conv(expr.operands[0]) | conv(expr.operands[1]),
            'Shr': lambda expr, conv: claripy.LShR(conv(expr.operands[0]), expr.operands[1].value)
        }

        if isinstance(condition, (ailment.Expr.Load, ailment.Expr.DirtyExpression, ailment.Expr.BasePointerOffset)):
            var = claripy.BVS('ailexpr_%s' % repr(condition), condition.bits, explicit_name=True)
            self._condition_mapping[var] = condition
            return var
        elif isinstance(condition, ailment.Expr.Register):
            var = claripy.BVS('ailexpr_%s-%d' % (repr(condition), condition.idx), condition.bits, explicit_name=True)
            self._condition_mapping[var] = condition
            return var
        elif isinstance(condition, ailment.Expr.Convert):
            # convert is special. if it generates a 1-bit variable, it should be treated as a BVS
            if condition.to_bits == 1:
                var_ = self.claripy_ast_from_ail_condition(condition.operands[0])
                name = 'ailcond_Conv(%d->%d, %s)' % (condition.from_bits, condition.to_bits, repr(var_))
                var = claripy.BoolS(name, explicit_name=True)
            else:
                var_ = self.claripy_ast_from_ail_condition(condition.operands[0])
                name = 'ailexpr_Conv(%d->%d, %s)' % (condition.from_bits, condition.to_bits, repr(var_))
                var = claripy.BVS(name, condition.to_bits, explicit_name=True)
            self._condition_mapping[var] = condition
            return var
        elif isinstance(condition, ailment.Expr.Const):
            var = claripy.BVV(condition.value, condition.bits)
            return var
        elif isinstance(condition, ailment.Expr.Tmp):
            l.warning("Left-over ailment.Tmp variable %s.", condition)
            if condition.bits == 1:
                var = claripy.BoolV('ailtmp_%d' % condition.tmp_idx)
            else:
                var = claripy.BVS('ailtmp_%d' % condition.tmp_idx, condition.bits)
            self._condition_mapping[var] = condition
            return var

        lambda_expr = _mapping.get(condition.verbose_op, None)
        if lambda_expr is None:
            raise NotImplementedError("Unsupported AIL expression operation %s. Consider implementing." % condition.op)
        r = lambda_expr(condition, self.claripy_ast_from_ail_condition)
        if r is NotImplemented:
            r = claripy.BVS("ailexpr_%r" % condition, condition.bits, explicit_name=True)
            self._condition_mapping[r] = condition
        return r

    #
    # Expression simplification
    #

    @staticmethod
    def simplify_condition(cond):

        # Z3's simplification may yield weird and unreadable results
        # hence we mostly rely on our own simplification. we only use Z3's simplification results when it returns a
        # concrete value.
        claripy_simplified = claripy.simplify(cond)
        if not claripy_simplified.symbolic:
            return claripy_simplified

        simplified = ConditionProcessor._fold_double_negations(cond)
        cond = simplified if simplified is not None else cond
        simplified = ConditionProcessor._revert_short_circuit_conditions(cond)
        cond = simplified if simplified is not None else cond
        return cond

    @staticmethod
    def _revert_short_circuit_conditions(cond):

        # revert short-circuit conditions
        # !A||(A&&!B) ==> !(A&&B)

        if cond.op != "Or":
            return cond

        or_arg0, or_arg1 = cond.args[:2]
        if or_arg1.op == 'And':
            pass
        elif or_arg0.op == 'And':
            or_arg0, or_arg1 = or_arg1, or_arg0
        else:
            return cond

        not_a = or_arg0
        solver = claripy.SolverCacheless()

        if not_a.variables == or_arg1.args[0].variables:
            solver.add(not_a == or_arg1.args[0])
            not_b = or_arg1.args[1]
        elif not_a.variables == or_arg1.args[1].variables:
            solver.add(not_a == or_arg1.args[1])
            not_b = or_arg1.args[0]
        else:
            return cond

        if not solver.satisfiable():
            # found it!
            b = claripy.Not(not_b)
            a = claripy.Not(not_a)
            if len(cond.args) <= 2:
                return claripy.Not(claripy.And(a, b))
            else:
                return claripy.Or(claripy.Not(claripy.And(a, b)), *cond.args[2:])
        else:
            return cond

    @staticmethod
    def _fold_double_negations(cond):

        # !(!A) ==> A
        # !((!A) && (!B)) ==> A || B
        # !((!A) && B) ==> A || !B
        # !(A || B) ==> (!A && !B)

        if cond.op != "Not":
            return None
        if cond.args[0].op == "Not":
            return cond.args[0]

        if cond.args[0].op == "And" and len(cond.args[0].args) == 2:
            and_0, and_1 = cond.args[0].args
            if and_0.op == "Not" and and_1.op == "Not":
                expr = claripy.Or(and_0.args[0], and_1.args[0])
                return expr

            if and_0.op == "Not":  # and_1.op != "Not"
                expr = claripy.Or(
                    and_0.args[0],
                    ConditionProcessor.simplify_condition(
                        claripy.Not(and_1)
                    )
                )
                return expr

        if cond.args[0].op == "Or" and len(cond.args[0].args) == 2:
            or_0, or_1 = cond.args[0].args
            expr = claripy.And(
                ConditionProcessor.simplify_condition(claripy.Not(or_0)),
                ConditionProcessor.simplify_condition(claripy.Not(or_1)),
            )
            return expr

        return None


# delayed import
from .region_identifier import GraphRegion, MultiNode
