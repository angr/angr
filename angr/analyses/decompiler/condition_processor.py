import operator
import logging

import networkx

import claripy
import ailment

from ...utils.graph import dominates, shallow_reverse
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
                    edge_data = region.graph.get_edge_data(*edge)
                    edge_type = edge_data.get('type', 'transition')
                    try:
                        predicate = self._extract_predicate(src, dst, edge_type)
                    except EmptyBlockNotice:
                        # catch empty block notice - although this should not really happen
                        predicate = claripy.true
                    edge_conditions[edge] = predicate
                    predicate_mapping[predicate] = dst

        if jump_tables:
            self.recover_reaching_conditions_for_jumptables(region, jump_tables, edge_conditions)

        if with_successors and region.graph_with_successors is not None:
            _g = region.graph_with_successors
        else:
            _g = region.graph
        end_nodes = {n for n in _g.nodes() if _g.out_degree(n) == 0}
        if end_nodes:
            inverted_graph = shallow_reverse(_g)
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

    def remove_claripy_bool_asts(self, node, memo=None):

        # Convert claripy Bool ASTs to AIL expressions

        if memo is None:
            memo = {}

        if isinstance(node, SequenceNode):
            new_nodes = [ ]
            for n in node.nodes:
                new_node = self.remove_claripy_bool_asts(n, memo=memo)
                new_nodes.append(new_node)
            new_seq_node = SequenceNode(new_nodes)
            return new_seq_node

        elif isinstance(node, MultiNode):
            new_nodes = [ ]
            for n in node.nodes:
                new_node = self.remove_claripy_bool_asts(n, memo=memo)
                new_nodes.append(new_node)
            new_multinode = MultiNode(nodes=new_nodes)
            return new_multinode

        elif isinstance(node, CodeNode):
            node = CodeNode(self.remove_claripy_bool_asts(node.node, memo=memo),
                            None if node.reaching_condition is None
                            else self.convert_claripy_bool_ast(node.reaching_condition, memo=memo))
            return node

        elif isinstance(node, ConditionalBreakNode):

            return ConditionalBreakNode(node.addr,
                                        self.convert_claripy_bool_ast(node.condition, memo=memo),
                                        node.target,
                                        )

        elif isinstance(node, ConditionNode):

            return ConditionNode(node.addr,
                                 None if node.reaching_condition is None else
                                    self.convert_claripy_bool_ast(node.reaching_condition, memo=memo),
                                 self.convert_claripy_bool_ast(node.condition, memo=memo),
                                 self.remove_claripy_bool_asts(node.true_node, memo=memo),
                                 self.remove_claripy_bool_asts(node.false_node, memo=memo),
                                 )

        elif isinstance(node, LoopNode):

            return LoopNode(node.sort,
                            self.convert_claripy_bool_ast(node.condition, memo=memo) if node.condition is not None else None,
                            self.remove_claripy_bool_asts(node.sequence_node, memo=memo),
                            addr=node.addr,
                            )

        elif isinstance(node, SwitchCaseNode):
            return SwitchCaseNode(self.convert_claripy_bool_ast(node.switch_expr, memo=memo),
                                  dict((idx, self.remove_claripy_bool_asts(case_node, memo=memo))
                                       for idx, case_node in node.cases.items()),
                                  self.remove_claripy_bool_asts(node.default_node, memo=memo),
                                  addr=node.addr)

        else:
            return node

    @classmethod
    def get_last_statement(cls, block):
        """
        This is the buggy version of get_last_statements, because, you know, there can always be more than one last
        statement due to the existence of branching statements (like, If-then-else). All methods using
        get_last_statement() should switch to get_last_statements() and properly handle multiple last statements.
        """
        if type(block) is SequenceNode:
            if block.nodes:
                return cls.get_last_statement(block.nodes[-1])
            raise EmptyBlockNotice()
        if type(block) is CodeNode:
            return cls.get_last_statement(block.node)
        if type(block) is ailment.Block:
            if not block.statements:
                raise EmptyBlockNotice()
            return block.statements[-1]
        if type(block) is Block:
            raise NotImplementedError()
        if type(block) is BlockNode:
            raise NotImplementedError()
        if type(block) is MultiNode:
            # get the last node
            for the_block in reversed(block.nodes):
                try:
                    last_stmt = cls.get_last_statement(the_block)
                    return last_stmt
                except EmptyBlockNotice:
                    continue
            raise EmptyBlockNotice()
        if type(block) is LoopNode:
            return cls.get_last_statement(block.sequence_node)
        if type(block) is ConditionalBreakNode:
            return None
        if type(block) is ConditionNode:
            s = None
            if block.true_node:
                try:
                    s = cls.get_last_statement(block.true_node)
                except EmptyBlockNotice:
                    s = None
            if s is None and block.false_node:
                s = cls.get_last_statement(block.false_node)
            return s
        if type(block) is BreakNode:
            return None
        if type(block) is ContinueNode:
            return None
        if type(block) is SwitchCaseNode:
            return None
        if type(block) is GraphRegion:
            # normally this should not happen. however, we have test cases that trigger this case.
            return None

        raise NotImplementedError()

    @classmethod
    def get_last_statements(cls, block):
        if type(block) is SequenceNode:
            for last_node in reversed(block.nodes):
                try:
                    last_stmts = cls.get_last_statements(last_node)
                    return last_stmts
                except EmptyBlockNotice:
                    # the node is empty. try the next one
                    continue

            raise EmptyBlockNotice()

        if type(block) is CodeNode:
            return cls.get_last_statements(block.node)
        if type(block) is ailment.Block:
            if not block.statements:
                raise EmptyBlockNotice()
            return [ block.statements[-1] ]
        if type(block) is Block:
            raise NotImplementedError()
        if type(block) is BlockNode:
            raise NotImplementedError()
        if type(block) is MultiNode:
            # get the last node
            for the_block in reversed(block.nodes):
                try:
                    last_stmts = cls.get_last_statements(the_block)
                    return last_stmts
                except EmptyBlockNotice:
                    continue
            raise EmptyBlockNotice()
        if type(block) is LoopNode:
            return cls.get_last_statements(block.sequence_node)
        if type(block) is ConditionalBreakNode:
            return [ block ]
        if type(block) is ConditionNode:
            s = [ ]
            if block.true_node:
                try:
                    last_stmts = cls.get_last_statements(block.true_node)
                    s.extend(last_stmts)
                except EmptyBlockNotice:
                    pass
            if block.false_node:
                last_stmts = cls.get_last_statements(block.false_node)
                s.extend(last_stmts)
            return s
        if type(block) is BreakNode:
            return [ block ]
        if type(block) is ContinueNode:
            return [ block ]
        if type(block) is SwitchCaseNode:
            s = [ ]
            for case in block.cases.values():
                s.extend(cls.get_last_statements(case))
            if block.default_node is not None:
                s.extend(cls.get_last_statements(block.default_node))
            return s
        if type(block) is GraphRegion:
            # normally this should not happen. however, we have test cases that trigger this case.
            return [ ]

        raise NotImplementedError()

    #
    # Path predicate
    #

    EXC_COUNTER = 1000

    def _extract_predicate(self, src_block, dst_block, edge_type):

        if edge_type == 'exception':
            # TODO: THIS IS ABSOLUTELY A HACK. AT THIS MOMENT YOU SHOULD NOT ATTEMPT TO MAKE SENSE OF EXCEPTION EDGES.
            self.EXC_COUNTER += 1
            return self.claripy_ast_from_ail_condition(
                ailment.Expr.BinaryOp(None, 'CmpEQ', (ailment.Expr.Register(0x400000 + self.EXC_COUNTER, None, self.EXC_COUNTER, 64),
                                                      ailment.Expr.Const(None, None, self.EXC_COUNTER, 64)), False)
            )

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
            if isinstance(last_stmt.true_target, ailment.Expr.Const) and last_stmt.true_target.value == dst_block.addr:
                return bool_var
            else:
                return claripy.Not(bool_var)

        return claripy.true

    #
    # Expression conversion
    #

    def convert_claripy_bool_ast(self, cond, memo=None):
        """
        Convert recovered reaching conditions from claripy ASTs to ailment Expressions

        :return: None
        """

        if memo is None:
            memo = {}
        if cond in memo:
            return memo[cond]
        r = self.convert_claripy_bool_ast_core(cond, memo)
        memo[cond] = r
        return r

    def convert_claripy_bool_ast_core(self, cond, memo):
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
                    r = self.convert_claripy_bool_ast(arg, memo=memo)
                else:
                    r = ailment.Expr.BinaryOp(None, op, (r, self.convert_claripy_bool_ast(arg, memo=memo)), signed)
            return r

        _mapping = {
            'Not': lambda cond_: _binary_op_reduce('Not', cond_.args),
            'And': lambda cond_: _binary_op_reduce('LogicalAnd', cond_.args),
            'Or': lambda cond_: _binary_op_reduce('LogicalOr', cond_.args),
            '__le__': lambda cond_: _binary_op_reduce('CmpLE', cond_.args, signed=True),
            'SLE': lambda cond_: _binary_op_reduce('CmpLE', cond_.args, signed=True),
            '__lt__': lambda cond_: _binary_op_reduce('CmpLT', cond_.args, signed=True),
            'SLT': lambda cond_: _binary_op_reduce('CmpLT', cond_.args, signed=True),
            'UGT': lambda cond_: _binary_op_reduce('CmpGT', cond_.args),
            'UGE': lambda cond_: _binary_op_reduce('CmpGE', cond_.args),
            '__gt__': lambda cond_: _binary_op_reduce('CmpGT', cond_.args, signed=True),
            '__ge__': lambda cond_: _binary_op_reduce('CmpGE', cond_.args, signed=True),
            'SGT': lambda cond_: _binary_op_reduce('CmpGT', cond_.args, signed=True),
            'SGE': lambda cond_: _binary_op_reduce('CmpGE', cond_.args, signed=True),
            'ULT': lambda cond_: _binary_op_reduce('CmpLT', cond_.args),
            'ULE': lambda cond_: _binary_op_reduce('CmpLE', cond_.args),
            '__eq__': lambda cond_: _binary_op_reduce('CmpEQ', cond_.args),
            '__ne__': lambda cond_: _binary_op_reduce('CmpNE', cond_.args),
            '__add__': lambda cond_: _binary_op_reduce('Add', cond_.args, signed=False),
            '__sub__': lambda cond_: _binary_op_reduce('Sub', cond_.args),
            '__mul__': lambda cond_: _binary_op_reduce('Mul', cond_.args),
            '__xor__': lambda cond_: _binary_op_reduce('Xor', cond_.args),
            '__or__': lambda cond_: _binary_op_reduce('Or', cond_.args, signed=False),
            '__and__': lambda cond_: _binary_op_reduce('And', cond_.args),
            '__lshift__': lambda cond_: _binary_op_reduce('Shl', cond_.args),
            '__rshift__': lambda cond_: _binary_op_reduce('Sar', cond_.args),
            'LShR': lambda cond_: _binary_op_reduce('Shr', cond_.args),
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

        def _op_with_unified_size(op, conv, operand0, operand1):
            # ensure operand1 is of the same size as operand0
            if isinstance(operand1, ailment.Expr.Const):
                # amazing - we do the eazy thing here
                return op(conv(operand0), operand1.value)
            if operand1.bits == operand0.bits:
                return op(conv(operand0), conv(operand1))
            # extension is required
            assert operand1.bits < operand0.bits
            operand1 = ailment.Expr.Convert(None, operand1.bits, operand0.bits, False, operand1)
            return op(conv(operand0), conv(operand1))

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
            'Mul': lambda expr, conv: conv(expr.operands[0]) * conv(expr.operands[1]),
            'Not': lambda expr, conv: claripy.Not(conv(expr.operand)),
            'Xor': lambda expr, conv: conv(expr.operands[0]) ^ conv(expr.operands[1]),
            'And': lambda expr, conv: conv(expr.operands[0]) & conv(expr.operands[1]),
            'Or': lambda expr, conv: conv(expr.operands[0]) | conv(expr.operands[1]),
            'Shr': lambda expr, conv: _op_with_unified_size(claripy.LShR, conv, expr.operands[0], expr.operands[1]),
            'Shl': lambda expr, conv: _op_with_unified_size(operator.lshift, conv, expr.operands[0], expr.operands[1]),
            'Sar': lambda expr, conv: _op_with_unified_size(operator.rshift, conv, expr.operands[0], expr.operands[1]),
        }

        if isinstance(condition, (ailment.Expr.Load, ailment.Expr.DirtyExpression, ailment.Expr.BasePointerOffset,
                                  ailment.Expr.ITE)):
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

        if len(cond.args) == 1:
            # redundant operator. get rid of it
            return cond.args[0]

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
