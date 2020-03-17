
import logging
from collections import defaultdict

import networkx

import claripy
import ailment

from ...block import Block, BlockNode
from .. import Analysis, register_analysis
from ..cfg.cfg_utils import CFGUtils
from .region_identifier import MultiNode, GraphRegion

l = logging.getLogger(name=__name__)

INDENT_DELTA = 2


class EmptyBlockNotice(Exception):
    pass


class SequenceNode:
    def __init__(self, nodes=None):
        self.nodes = nodes if nodes is not None else [ ]

    def __repr__(self):
        return "<SequenceNode %#x, %d nodes>" % (self.addr, len(self.nodes))

    @property
    def addr(self):
        if self.nodes:
            return self.nodes[0].addr
        else:
            return None

    def add_node(self, node):
        self.nodes.append(node)

    def insert_node(self, pos, node):
        self.nodes.insert(pos, node)

    def remove_node(self, node):
        self.nodes.remove(node)

    def node_position(self, node):
        return self.nodes.index(node)

    def remove_empty_node(self):

        new_nodes = [ ]

        for node in self.nodes:
            if type(node) is ConditionNode and self._test_empty_condition_node(node):
                continue
            if type(node) is CodeNode and self.test_empty_node(node.node):
                continue
            if self.test_empty_node(node):
                continue
            new_nodes.append(node)

        self.nodes = new_nodes

    def _test_empty_condition_node(self, cond_node):

        for node in [ cond_node.true_node, cond_node.false_node ]:
            if node is None:
                continue
            if type(node) is CodeNode and self.test_empty_node(node.node):
                continue
            if self.test_empty_node(node):
                continue
            return False

        return True

    @staticmethod
    def test_empty_node(node):
        # pylint:disable=simplifiable-if-statement
        if type(node) is ailment.Block:
            if not node.statements:
                return True
            if len(node.statements) == 1 and type(node.statements[0]) is ailment.Stmt.ConditionalJump:
                # conditional jumps have been taken care of during reaching condition recovery
                return True
            else:
                # not empty
                return False
        elif type(node) is CodeNode:
            return SequenceNode.test_empty_node(node.node)
        # unsupported node type. probably not empty?
        return False

    def copy(self):
        return SequenceNode(nodes=self.nodes[::])

    def dbg_repr(self, indent=0):
        s = ""
        for node in self.nodes:
            s += (node.dbg_repr(indent=indent + INDENT_DELTA))
            s += "\n"

        return s


class CodeNode:
    def __init__(self, node, reaching_condition):
        self.node = node
        self.reaching_condition = reaching_condition

    def __repr__(self):
        if self.addr is not None:
            return "<CodeNode %#x>" % self.addr
        else:
            return "<CodeNode %s>" % repr(self.node)

    @property
    def addr(self):
        if hasattr(self.node, 'addr'):
            return self.node.addr
        else:
            return None

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = ""
        if self.reaching_condition is not None and not claripy.is_true(self.reaching_condition):
            s += (indent_str + "if (<block-missing>; %s)\n" +
                 indent_str + "{\n" +
                 indent_str + "  %s\n" +
                 indent_str + "}") % \
                              (self.reaching_condition, self.node)
        else:
            s += indent_str + str(self.node)

        return s

    def copy(self):
        return CodeNode(self.node, self.reaching_condition)


class ConditionNode:
    def __init__(self, addr, reaching_condition, condition, true_node, false_node=None):
        self.addr = addr
        self.reaching_condition = reaching_condition
        self.condition = condition
        self.true_node = true_node
        self.false_node = false_node

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = ""
        s += (indent_str + "if (<block-missing>; %s)\n" +
              indent_str + "{\n" +
              indent_str + "%s\n" +
              indent_str + "}\n") % (
            self.condition, self.true_node.dbg_repr(indent+2),
        )
        if self.false_node is not None:
            s += (indent_str + "else\n" +
              indent_str + "{\n" +
              indent_str + "%s\n" +
              indent_str + "}") % \
             self.false_node.dbg_repr(indent+2)

        return s


class LoopNode:
    def __init__(self, sort, condition, sequence_node, addr=None):
        self.sort = sort
        self.condition = condition
        self.sequence_node = sequence_node
        self._addr = addr

    @property
    def addr(self):
        if self._addr is None:
            return self.sequence_node.addr
        else:
            return self._addr


class BreakNode:
    def __init__(self, addr, target):
        self.addr = addr
        self.target = target


class ConditionalBreakNode(BreakNode):
    def __init__(self, addr, condition, target):
        super(ConditionalBreakNode, self).__init__(addr, target)
        self.condition = condition

    def __repr__(self):
        return "<ConditionalBreakNode %#x target:%#x>" % (self.addr, self.target)


class SwitchCaseNode:
    def __init__(self, switch_expr, cases, default_node, addr=None):
        self.switch_expr = switch_expr
        self.cases = cases
        self.default_node = default_node
        self.addr = addr

#
# The main analysis
#


class RecursiveStructurer(Analysis):
    """
    Recursively structure a region and all of its subregions.
    """
    def __init__(self, region):
        self._region = region

        self.result = None

        self._analyze()

    def _analyze(self):

        region = self._region.recursive_copy()

        # visit the region in post-order DFS
        parent_map = { }
        stack = [ region ]

        while stack:
            current_region = stack[-1]

            has_region = False
            for node in networkx.dfs_postorder_nodes(current_region.graph, current_region.head):
                if type(node) is GraphRegion:
                    stack.append(node)
                    parent_map[node] = current_region
                    has_region = True

            if not has_region:
                # pop this region from the stack
                stack.pop()

                # Get the parent region
                parent_region = parent_map.get(current_region, None)
                # structure this region
                st = self.project.analyses.Structurer(current_region, parent_map=parent_map)
                # replace this region with the resulting node in its parent region... if it's not an orphan
                if not parent_region:
                    # this is the top-level region. we are done!
                    self.result = st.result
                    break

                self._replace_region(parent_region, current_region, st.result)

    @staticmethod
    def _replace_region(parent_region, sub_region, node):

        parent_region.replace_region(sub_region, node)


class Structurer(Analysis):
    """
    Structure a region.
    """
    def __init__(self, region, parent_map=None, condition_mapping=None):

        self._region = region
        self._parent_map = parent_map

        self._reaching_conditions = None
        # self._predicate_mapping = None
        # self._edge_conditions = None
        self._condition_mapping = {} if condition_mapping is None else condition_mapping

        # intermediate states
        self._new_sequences = [ ]

        self.result = None

        self._analyze()

    def _analyze(self):

        if self._has_cycle():
            self._analyze_cyclic()
        else:
            self._analyze_acyclic()

    def _analyze_cyclic(self):

        loop_head = self._region.head

        # determine loop nodes and successors
        loop_subgraph, successors = self._find_loop_nodes_and_successors()

        # refine loop successors
        if len(successors) > 1:
            _, _ = self._refine_loop_successors(loop_subgraph, successors)
            loop_subgraph, successors = self._find_loop_nodes_and_successors()

        assert len(successors) <= 1

        loop_node = self._make_endless_loop(loop_head, loop_subgraph, successors)

        loop_node = self._refine_loop(loop_node)

        seq = SequenceNode(nodes=[ loop_node ] + [ succ for succ in successors if succ in self._region.graph ])

        seq = self._remove_claripy_bool_asts(seq)

        self.result = seq

    def _analyze_acyclic(self):

        # let's generate conditions first
        self._recover_reaching_conditions()

        # make the sequence node
        seq = self._make_sequence()

        self._new_sequences.append(seq)

        while self._new_sequences:
            seq_ = self._new_sequences.pop(0)
            self._structure_sequence(seq_)

        self._make_condition_nodes(seq)

        seq = self._merge_conditional_breaks(seq)

        seq = self._remove_claripy_bool_asts(seq)

        self.result = seq

    def _has_cycle(self):
        """
        Test if the region contains a cycle.

        :return: True if the region contains a cycle, False otherwise.
        :rtype: bool
        """

        return not networkx.is_directed_acyclic_graph(self._region.graph)

    def _find_loop_nodes_and_successors(self):

        graph = self._region.graph
        head = self._region.head

        # find initial loop nodes
        loop_nodes = None
        components = networkx.strongly_connected_components(graph)
        for component in components:
            if head in component:
                loop_nodes = component
                break
        if loop_nodes is None:
            # this should never happen - loop head always forms a cycle
            raise TypeError("A bug (impossible case) in the algorithm is triggered.")

        # extend loop nodes
        while True:
            loop_nodes_updated = False
            for loop_node in loop_nodes:
                for succ in graph.successors(loop_node):
                    if succ not in loop_nodes:
                        # determine if this successor's all predecessors are in the loop
                        predecessors = graph.predecessors(succ)
                        if all(pred in loop_nodes for pred in predecessors):
                            # yes!
                            loop_nodes.add(succ)
                            loop_nodes_updated = True
                            break
                if loop_nodes_updated:
                    break
            if not loop_nodes_updated:
                break

        # find loop nodes and successors
        loop_subgraph = networkx.subgraph(graph, loop_nodes)
        loop_node_addrs = set( node.addr for node in loop_subgraph )

        # Case A: The loop successor is inside the current region (does it happen at all?)
        loop_successors = set()

        for node, successors in networkx.bfs_successors(graph, head):
            if node.addr in loop_node_addrs:
                for suc in successors:
                    if suc not in loop_subgraph:
                        loop_successors.add(suc)

        # Case B: The loop successor is the successor to this region in the parent graph
        if not loop_successors and self._parent_map is not None:
            current_region = self._region
            parent_region = self._parent_map.get(current_region, None)
            while parent_region and not loop_successors:
                parent_graph = parent_region.graph
                for node, successors in networkx.bfs_successors(parent_graph, current_region):
                    if node.addr == current_region.addr:
                        for suc in successors:
                            if suc not in loop_subgraph:
                                loop_successors.add(suc)
                current_region = parent_region
                parent_region = self._parent_map.get(current_region, None)

        return loop_subgraph, loop_successors

    def _refine_loop_successors(self, loop_subgraph, loop_successors):  # pylint:disable=no-self-use
        """
        If there are multiple successors of a loop, convert them into conditional gotos. Eventually there should be
        only one loop successor.

        :param networkx.DiGraph loop_subgraph:  The subgraph of the loop.
        :param set loop_successors:             A list of current successors.
        :return:                                None
        """
        if len(loop_successors) <= 1:
            return loop_subgraph, loop_successors

        # recover reaching conditions
        self._recover_reaching_conditions()

        successors = list(loop_successors)

        # create a new successor
        cond = ConditionNode(
            -1,
            None,
            self._reaching_conditions[successors[0]],
            successors[0],
            false_node=None,
        )
        for succ in successors[1:]:
            cond = ConditionNode(-1,
                                 None,
                                 self._reaching_conditions[succ],
                                 succ,
                                 false_node=cond,
                                 )

        # modify self._region in place
        for succ in successors:
            for src, _, data in list(self._region.graph.in_edges(succ, data=True)):
                removed_edges = [ ]
                for src2src, _, data_ in list(self._region.graph.in_edges(src, data=True)):
                    removed_edges.append((src2src, src, data_))
                    self._region.graph.remove_edge(src2src, src)
                self._region.graph.remove_edge(src, succ)

                # modify the last statement of src so that it jumps to cond
                last_stmt = self._get_last_statement(src)
                if isinstance(last_stmt, ailment.Stmt.ConditionalJump):
                    if last_stmt.true_target.value == succ.addr:
                        new_last_stmt = ailment.Stmt.ConditionalJump(
                            last_stmt.idx,
                            last_stmt.condition,
                            ailment.Expr.Const(None, None, -1, self.project.arch.bits),
                            last_stmt.false_target,
                            ins_addr=last_stmt.ins_addr,
                        )
                    elif last_stmt.false_target.value == succ.addr:
                        new_last_stmt = ailment.Stmt.ConditionalJump(
                            last_stmt.idx,
                            last_stmt.condition,
                            last_stmt.true_target,
                            ailment.Expr.Const(None, None, -1, self.project.arch.bits),
                            ins_addr=last_stmt.ins_addr,
                        )
                    else:
                        l.warning("I'm not sure which branch is jumping out of the loop...")
                        raise Exception()
                else:
                    raise NotImplementedError()
                self._remove_last_statement(src)
                self._append_statement(src, new_last_stmt)

                # add src back
                for src2src, _, data_ in removed_edges:
                    self._region.graph.add_edge(src2src, src, **data_)

                self._region.graph.add_edge(src, cond, **data)

        return loop_subgraph, [ cond ]

    def _make_endless_loop(self, loop_head, loop_subgraph, loop_successors):

        loop_body = self._to_loop_body_sequence(loop_head, loop_subgraph, loop_successors)

        # create a while(true) loop with sequence node being the loop body
        loop_node = LoopNode('while', None, loop_body, addr=loop_head.addr)

        return loop_node

    def _refine_loop(self, loop_node):

        while True:
            # while
            r, loop_node = self._refine_loop_while(loop_node)
            if r: continue

            # do-while
            r, loop_node = self._refine_loop_dowhile(loop_node)
            if r: continue

            # no more changes
            break

        return loop_node

    @staticmethod
    def _refine_loop_while(loop_node):

        if loop_node.sort == 'while' and loop_node.condition is None:
            # it's an endless loop
            first_node = loop_node.sequence_node.nodes[0]
            if type(first_node) is CodeNode:
                first_node = first_node.node
            if type(first_node) is ConditionalBreakNode:
                while_cond = Structurer._negate_cond(first_node.condition)
                new_seq = loop_node.sequence_node.copy()
                new_seq.nodes = new_seq.nodes[1:]
                new_loop_node = LoopNode('while', while_cond, new_seq, addr=loop_node.addr)

                return True, new_loop_node

        return False, loop_node

    @staticmethod
    def _refine_loop_dowhile(loop_node):

        if loop_node.sort == 'while' and loop_node.condition is None:
            # it's an endless loop
            last_node = loop_node.sequence_node.nodes[-1]
            if type(last_node) is ConditionalBreakNode:
                while_cond = Structurer._negate_cond(last_node.condition)
                new_seq = loop_node.sequence_node.copy()
                new_seq.nodes = new_seq.nodes[:-1]
                new_loop_node = LoopNode('do-while', while_cond, new_seq)

                return True, new_loop_node

        return False, loop_node

    def _to_loop_body_sequence(self, loop_head, loop_subgraph, loop_successors):

        graph = self._region.graph
        loop_nodes = set(s.addr for s in graph.nodes)
        loop_region_graph = networkx.DiGraph()

        # TODO: Make sure the loop body has been structured

        queue = [ loop_head ]
        traversed = set()
        loop_successor_addrs = set(succ.addr for succ in loop_successors)
        replaced_nodes = {}

        while queue:
            node = queue[0]
            queue = queue[1:]

            loop_region_graph.add_node(node)

            traversed.add(node)

            successors = list(graph.successors(node))  # successors are all inside the current region

            last_stmt = self._get_last_statement(node)
            real_successor_addrs = self._extract_jump_targets(last_stmt)

            if any(succ_addr in loop_successor_addrs for succ_addr in real_successor_addrs):
                # This node has an exit to the outside of the loop
                # add a break or a conditional break node
                new_node = None
                if type(last_stmt) is ailment.Stmt.Jump:
                    # shrink the block to remove the last statement
                    self._remove_last_statement(node)
                    # add a break
                    new_node = BreakNode(last_stmt.ins_addr, last_stmt.target.value)
                elif type(last_stmt) is ailment.Stmt.ConditionalJump:
                    # add a conditional break
                    if last_stmt.true_target.value in loop_successor_addrs and \
                                last_stmt.false_target.value in loop_nodes:
                        cond = last_stmt.condition
                        target = last_stmt.true_target.value
                    elif last_stmt.false_target.value in loop_successor_addrs and \
                                last_stmt.true_target.value in loop_nodes:
                        cond = ailment.Expr.UnaryOp(last_stmt.condition.idx, 'Not', (last_stmt.condition))
                        target = last_stmt.false_target.value
                    else:
                        l.warning("I'm not sure which branch is jumping out of the loop...")
                        raise Exception()
                    # remove the last statement from the node
                    self._remove_last_statement(node)
                    new_node = ConditionalBreakNode(
                        last_stmt.ins_addr,
                        self._claripy_ast_from_ail_condition(cond),
                        target
                    )

                if new_node is not None:
                    # special checks if node goes empty
                    if isinstance(node, ailment.Block) and not node.statements:
                        # new_node will replace node
                        new_node.addr = node.addr
                        replaced_nodes[node] = new_node
                        if loop_head is node:
                            loop_head = new_node

                        preds = list(loop_region_graph.predecessors(node))
                        loop_region_graph.remove_node(node)
                        for pred in preds:
                            loop_region_graph.add_edge(pred, new_node)
                    else:
                        loop_region_graph.add_edge(node, new_node)
                    # update node
                    node = new_node

            for dst in successors:
                # sanity check
                if dst in loop_successors:
                    continue
                if dst not in loop_subgraph and dst not in loop_successors:
                    # what's this node?
                    l.error("Found a node that belongs to neither loop body nor loop successors. Something is wrong.")
                    # raise Exception()
                if dst is not loop_head:
                    loop_region_graph.add_edge(node, replaced_nodes.get(dst, dst))
                if dst in traversed or dst in queue:
                    continue
                queue.append(dst)

        # Create a graph region and structure it
        region = GraphRegion(loop_head, loop_region_graph)
        structurer = self.project.analyses.Structurer(region, condition_mapping=self._condition_mapping.copy())
        seq = structurer.result

        last_stmt = self._get_last_statement(seq)
        if type(last_stmt) is ailment.Stmt.Jump:
            target = last_stmt.target
            if target.value != loop_head.addr:
                l.error('The last Goto in the loop body does not jump to the loop head. Why?')
                raise Exception()
            # we want to remove this Jump as it is not necessary anymore
            self._remove_last_statement(seq)

        seq.remove_empty_node()

        return seq

    def _recover_reaching_conditions(self):

        def _immediately_postdominates(node_a, node_b):
            """
            Does node A immediately post-dominate node B on the graph?

            :param node_a:
            :param node_b:
            :return:
            """
            inverted_graph = networkx.reverse(self._region.graph)
            idoms = networkx.immediate_dominators(inverted_graph, node_a)
            return idoms[node_b] is node_a

        edge_conditions = { }
        predicate_mapping = { }
        end_nodes = set()
        # traverse the graph to recover the condition for each edge
        # also figure out the end nodes
        for src in self._region.graph.nodes():
            nodes = list(self._region.graph[src])
            if len(nodes) >= 1:
                for dst in nodes:
                    edge = src, dst
                    predicate = self._extract_predicate(src, dst)
                    edge_conditions[edge] = predicate
                    predicate_mapping[predicate] = dst
            elif not nodes:
                # no successors
                end_nodes.add(src)

        reaching_conditions = { }
        # recover the reaching condition for each node
        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self._region.graph)
        for node in sorted_nodes:
            preds = self._region.graph.predecessors(node)
            reaching_condition = None

            if node is self._region.head:
                # the head is always reachable
                reaching_condition = claripy.true
            elif len(end_nodes) == 1 and node in end_nodes and _immediately_postdominates(node, self._region.head):
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
                reaching_conditions[node] = self._simplify_condition(reaching_condition)

        self._reaching_conditions = reaching_conditions
        # self._predicate_mapping = predicate_mapping
        # self._edge_conditions = edge_conditions

    def _convert_claripy_bool_ast(self, cond):
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

        _mapping = {
            'Not': lambda cond_: ailment.Expr.UnaryOp(None, 'Not', self._convert_claripy_bool_ast(cond_.args[0])),
            'And': lambda cond_: ailment.Expr.BinaryOp(None, 'LogicalAnd', (
                self._convert_claripy_bool_ast(cond_.args[0]),
                self._convert_claripy_bool_ast(cond_.args[1]),
            )),
            'Or': lambda cond_: ailment.Expr.BinaryOp(None, 'LogicalOr', (
                self._convert_claripy_bool_ast(cond_.args[0]),
                self._convert_claripy_bool_ast(cond_.args[1]),
            )),
            'ULE': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpULE',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__le__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLE',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__lt__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpLT',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            'UGT': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpUGT',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__gt__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGT',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__ge__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGE',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__eq__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpEQ',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__ne__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpNE',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__add__': lambda cond_: ailment.Expr.BinaryOp(None, 'Add',
                                                           tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                           ),
            '__sub__': lambda cond_: ailment.Expr.BinaryOp(None, 'Sub',
                                                           tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                           ),
            '__xor__': lambda cond_: ailment.Expr.BinaryOp(None, 'Xor',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__and__': lambda cond_: ailment.Expr.BinaryOp(None, 'And',
                                                           tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                           ),
            'LShR': lambda cond_: ailment.Expr.BinaryOp(None, 'Shr',
                                                        tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                        ),
            'BVV': lambda cond_: ailment.Expr.Const(None, None, cond_.args[0], cond_.size()),
            'BoolV': lambda cond_: ailment.Expr.Const(None, None, True, 1) if cond_.args[0] is True
                                                                        else ailment.Expr.Const(None, None, False, 1),
        }

        if cond.op in _mapping:
            return _mapping[cond.op](cond)
        raise NotImplementedError(("Condition variable %s has an unsupported operator %s. "
                                   "Consider implementing.") % (cond, cond.op))

    def _make_sequence(self):

        seq = SequenceNode()

        for node in networkx.topological_sort(self._region.graph):
            seq.add_node(CodeNode(node, self._reaching_conditions.get(node, None)))

        return seq

    def _structure_sequence(self, seq):

        self._make_switch_cases(seq)
        self._merge_same_conditioned_nodes(seq)
        self._make_ites(seq)
        self._structure_common_subexpression_conditions(seq)

    def _merge_same_conditioned_nodes(self, seq):

        # search for nodes with the same reaching condition and then merge them into one sequence node
        i = 0
        while i < len(seq.nodes) - 1:
            node_0 = seq.nodes[i]
            if not type(node_0) is CodeNode:
                i += 1
                continue
            rcond_0 = node_0.reaching_condition
            if rcond_0 is None:
                i += 1
                continue
            node_1 = seq.nodes[i + 1]
            rcond_1 = node_1.reaching_condition
            if rcond_1 is None:
                i += 1
                continue
            r = claripy.simplify(rcond_0 == rcond_1)
            if claripy.is_true(r):
                # node_0 and node_1 should be put into the same sequence node
                new_node = CodeNode(
                    self._merge_nodes(node_0.node, node_1.node),
                    node_0.reaching_condition,
                )
                seq.nodes = seq.nodes[:i] + [new_node] + seq.nodes[i + 2:]
                continue
            i += 1

    #
    # Dealing with switch-case structures
    #

    def _make_switch_cases(self, seq):
        """
        Search for nodes that look like switch-cases and convert them to switch cases.

        A typical jump table involves multiple nodes, which look like the following:

        Head:  s_50 = Conv(32->64, (Load(addr=stack_base-28, size=4, endness=Iend_LE) - 0x3f<32>))<8>
               if (((Load(addr=stack_base-28, size=4, endness=Iend_LE) - 0x3f<32>) <= 0x36<32>))
                    { Goto A<64> } else { Goto B<64> }

        A:     (with an indirect jump)
               Goto((Conv(32->64, Load(addr=(0x40964c<64> + (Load(addr=stack_base-80, size=8, endness=Iend_LE) Mul 0x4<8>)), size=4, endness=Iend_LE)) + 0x40964c<64>))

        B:     (the default case)

        :param seq:     The Sequence node.
        :return:        None
        """

        jump_tables = self.kb.cfgs['CFGFast'].jump_tables

        addr2nodes = dict((node.addr, node) for node in seq.nodes)

        while True:
            for i in range(len(seq.nodes)):

                node = seq.nodes[i]

                try:
                    last_stmt = self._get_last_statement(node)
                except EmptyBlockNotice:
                    continue
                successor_addrs = self._extract_jump_targets(last_stmt)
                if len(successor_addrs) != 2:
                    continue

                for t in successor_addrs:
                    if t in addr2nodes and t in jump_tables:
                        # this is a candidate!
                        target = t
                        break
                else:
                    continue

                # extract the comparison expression, lower-, and upper-bounds from the last statement
                cmp = self._switch_extract_cmp_bounds(last_stmt)
                if not cmp:
                    continue
                cmp_expr, cmp_lb, cmp_ub = cmp  # pylint:disable=unused-variable

                jump_table = jump_tables[target]
                # the real indirect jump
                node_a = addr2nodes[target]
                # the default case
                node_b_addr = next(iter(t for t in successor_addrs if t != target))

                # Node A might have been structured. Un-structure it if that is the case.
                r, node_a = self._switch_unpack_sequence_node(seq, node_a, jump_table.jumptable_entries, addr2nodes)
                if not r:
                    continue

                # build switch-cases
                cases, node_default, to_remove = self._switch_build_cases(seq, i, cmp_lb, jump_table.jumptable_entries,
                                                                          node_b_addr, addr2nodes)
                if node_default is None:
                    switch_end_addr = node_b_addr
                else:
                    # we don't know what the end address of this switch-case structure is. let's figure it out
                    switch_end_addr = None
                self._switch_handle_gotos(cases, node_default, switch_end_addr)

                scnode = SwitchCaseNode(cmp_expr, cases, node_default, addr=last_stmt.ins_addr)
                scnode = CodeNode(scnode, node.reaching_condition)

                # insert the switch-case node
                seq.insert_node(i + 1, scnode)
                # remove all those entry nodes
                if node_default is not None:
                    to_remove.add(node_default)
                for node_ in to_remove:
                    seq.remove_node(node_)
                    del addr2nodes[node_.addr]
                # remove the last statement in node
                self._remove_last_statement(node)
                if SequenceNode.test_empty_node(node):
                    seq.remove_node(node)
                # remove the last statement in node_a
                self._remove_last_statement(node_a)
                if SequenceNode.test_empty_node(node_a):
                    seq.remove_node(node_a)

                # we found a node that looks like a switch-case. seq.nodes are changed. resume to find the next such
                # case
                break
            else:
                # we did not find any node that looks like a switch-case. exit.
                break

    @staticmethod
    def _switch_extract_cmp_bounds(last_stmt):
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

    @staticmethod
    def _switch_unpack_sequence_node(seq, node_a, jumptable_entries, addr2nodes):
        """
        We might have already structured the actual body of the switch-case structure into a single Sequence node (node
        A). If that is the case, we un-structure the sequence node in this method.

        :param seq:                 The original Sequence node.
        :param node_a:              Node A.
        :param jumptable_entries:   Addresses of indirect jump targets in the jump table.
        :param dict addr2nodes:     A dict of addresses to their corresponding nodes in `seq`.
        :return:                    A boolean value indicating the result and an updated node_a. The boolean value is
                                    True if unpacking is not necessary or we successfully unpacked the sequence node,
                                    False otherwise.
        :rtype:                     bool
        """

        if isinstance(node_a.node, SequenceNode):
            node_a_block_addrs = {n.addr for n in node_a.node.nodes}
        else:
            node_a_block_addrs = set()
        #
        # if that is the case, we un-structure it here
        if all(entry_addr in addr2nodes for entry_addr in jumptable_entries):
            return True, node_a
        elif all(entry_addr in node_a_block_addrs | addr2nodes.keys() for entry_addr in jumptable_entries):
            # unpack is needed
            if node_a_block_addrs.issubset(set(jumptable_entries) | {node_a.addr}):
                for n in node_a.node.nodes:
                    if isinstance(n, ConditionNode):
                        if n.true_node is not None and n.false_node is None:
                            the_node = CodeNode(n.true_node, n.condition)
                            addr2nodes[n.addr] = the_node
                            seq.add_node(the_node)
                        elif n.false_node is not None and n.true_node is None:
                            the_node = CodeNode(n.false_node, n.condition)
                            addr2nodes[n.addr] = the_node
                            seq.add_node(the_node)
                        else:
                            # unsupported. bail
                            return False, None
                    else:
                        the_node = CodeNode(n, None)
                        addr2nodes[n.addr] = the_node
                        seq.add_node(the_node)
                if node_a != addr2nodes[node_a.addr]:
                    # update node_a
                    seq.remove_node(node_a)
                    node_a = addr2nodes[node_a.addr]
                return True, node_a

        # not sure what's going on... give up on this case
        return False, None

    def _switch_build_cases(self, seq, header_idx, cmp_lb, jumptable_entries, node_b_addr, addr2nodes):
        """
        Discover all cases for the switch-case structure and build the switch-cases dict.

        :param seq:                 The original Sequence node.
        :param int header_idx:      Position of the header node in `seq.nodes`.
        :param int cmp_lb:          The lower bound of the jump table comparison.
        :param list jumptable_entries:  Addresses of indirect jump targets in the jump table.
        :param int node_b_addr:     Address of node B. Potentially, node B is the default node.
        :param dict addr2nodes:     A dict of addresses to their corresponding nodes in `seq`.
        :return:
        """

        cases = { }
        to_remove = set()
        node_default = addr2nodes[node_b_addr]

        entry_addrs_set = set(jumptable_entries)
        for j, entry_addr in enumerate(jumptable_entries):
            cases_idx = cmp_lb + j
            if entry_addr == node_b_addr:
                # jump to default or end of the switch-case structure - ignore this case
                continue

            entry_node = addr2nodes[entry_addr]
            case_node = SequenceNode(nodes=[entry_node])
            to_remove.add(entry_node)

            # find nodes that this entry node dominates
            cond_subexprs = list(self._get_reaching_condition_subexprs(entry_node.reaching_condition))
            guarded_nodes = None
            for subexpr in cond_subexprs:
                guarded_node_candidates = self._nodes_guarded_by_common_subexpr(seq, subexpr, header_idx + 1)
                if guarded_nodes is None:
                    guarded_nodes = set(node_ for _, node_, _ in guarded_node_candidates)
                else:
                    guarded_nodes = guarded_nodes.intersection(set(node_ for _, node_, _ in guarded_node_candidates))

            if guarded_nodes is not None:
                for node_ in guarded_nodes:
                    if node_ is not entry_node and node_.addr not in entry_addrs_set:
                        case_node.add_node(node_)
                        to_remove.add(node_)

            # do we have a default node?
            case_last_stmt = self._get_last_statement(case_node)
            if isinstance(case_last_stmt, ailment.Stmt.Jump):
                targets = self._extract_jump_targets(case_last_stmt)
                if len(targets) == 1 and targets[0] == node_b_addr:
                    # jump to the default case is rare - it's more likely that there is no default for this
                    # switch-case struct
                    node_default = None

            self._new_sequences.append(case_node)
            cases[cases_idx] = case_node

        return cases, node_default, to_remove

    def _switch_handle_gotos(self, cases, default, switch_end_addr):
        """
        For each case, convert the goto that goes to

        :param dict cases:              A dict of switch-cases.
        :param default:                 The default node.
        :param int|None node_b_addr:    Address of the end of the switch.
        :return:                        None
        """

        goto_addrs = defaultdict(int)

        def _find_gotos(block, **kwargs):  # pylint:disable=unused-argument
            if block.statements:
                stmt = block.statements[-1]
                if isinstance(stmt, ailment.Stmt.Jump):
                    targets = self._extract_jump_targets(stmt)
                    for t in targets:
                        goto_addrs[t] += 1

        if switch_end_addr is None:
            # we need to figure this out
            handlers = {
                ailment.Block: _find_gotos
            }

            walker = SequenceWalker(handlers=handlers)
            for case_node in cases.values():
                walker.walk(case_node)

            try:
                switch_end_addr = sorted(goto_addrs.items(), key=lambda x: x[1], reverse=True)[0][0]
            except StopIteration:
                # there is no Goto statement - perfect
                return

        # rewrite all _goto switch_end_addr_ to _break_

        def _rewrite_gotos(block, parent=None, index=0, label=None):  # pylint:disable=unused-argument
            if block.statements and parent is not None:
                stmt = block.statements[-1]
                if isinstance(stmt, ailment.Stmt.Jump):
                    targets = self._extract_jump_targets(stmt)
                    if len(targets) == 1 and next(iter(targets)) == switch_end_addr:
                        # add a new a break statement to its parent
                        break_node = BreakNode(stmt.ins_addr, switch_end_addr)
                        if isinstance(parent, SequenceNode):
                            parent.insert_node(index + 1, break_node)
                            self._remove_last_statement(block)
                        elif isinstance(parent, MultiNode):
                            parent.nodes.insert(index + 1, break_node)
                            self._remove_last_statement(block)
                        else:
                            # TODO: Figure out what types of node there are and support them
                            l.error("Cannot insert the break node to the parent node. Unsupported node type %s.",
                                    type(parent))

        handlers = {
            ailment.Block: _rewrite_gotos,
        }

        walker = SequenceWalker(handlers=handlers)
        for case_node in cases.values():
            walker.walk(case_node)

        if default is not None:
            walker.walk(default)

    #
    # Dealing with If-Then-Else structures
    #

    def _make_ites(self, seq):

        # search for a == ^a pairs

        while True:
            break_hard = False
            for node_0 in seq.nodes:
                if not type(node_0) is CodeNode:
                    continue
                rcond_0 = node_0.reaching_condition
                if rcond_0 is None:
                    continue
                if claripy.is_true(rcond_0) or claripy.is_false(rcond_0):
                    continue
                for node_1 in seq.nodes:
                    if not type(node_1) is CodeNode:
                        continue
                    if node_0 is node_1:
                        continue
                    rcond_1 = node_1.reaching_condition
                    if rcond_1 is None:
                        continue
                    cond_ = claripy.simplify(claripy.Not(rcond_0) == rcond_1)
                    if claripy.is_true(cond_):
                        # node_0 and node_1 should be structured using an if-then-else
                        self._make_ite(seq, node_0, node_1)
                        break_hard = True
                        break
                if break_hard:
                    break
            else:
                break

    def _structure_common_subexpression_conditions(self, seq):

        # use common subexpressions to structure nodes and create more if-then-else instances

        i = 0
        while i < len(seq.nodes) - 1:
            structured = False
            node_0 = seq.nodes[i]
            rcond_0 = node_0.reaching_condition
            if rcond_0 is None:
                i += 1
                continue
            subexprs_0 = list(self._get_reaching_condition_subexprs(rcond_0))

            for common_subexpr in subexprs_0:
                candidates = self._nodes_guarded_by_common_subexpr(seq, common_subexpr, i + 1)
                if candidates:
                    candidates.insert(0,
                                      (i, node_0, subexprs_0))
                    new_node = self._create_seq_node_guarded_by_common_subexpr(common_subexpr, candidates)
                    self._new_sequences.append(new_node.node)

                    # remove all old nodes and replace them with the new node
                    for idx, _, _ in candidates:
                        seq.nodes[idx] = None
                    seq.nodes[i] = new_node
                    seq.nodes = [ n for n in seq.nodes if n is not None ]
                    structured = True
                    break

            if not structured:
                i += 1

    def _nodes_guarded_by_common_subexpr(self, seq, common_subexpr, starting_idx):

        candidates = []

        if common_subexpr is claripy.true:
            return [ ]
        for j, node_1 in enumerate(seq.nodes[starting_idx:]):
            rcond_1 = node_1.reaching_condition
            if rcond_1 is None:
                continue
            subexprs_1 = list(self._get_reaching_condition_subexprs(rcond_1))
            if any(subexpr_1 is common_subexpr for subexpr_1 in subexprs_1):
                # we found one!
                candidates.append((starting_idx + j, node_1, subexprs_1))

        return candidates

    @staticmethod
    def _create_seq_node_guarded_by_common_subexpr(common_subexpr, candidates):

        new_nodes = [ ]

        for _, node, subexprs in candidates:
            # :)
            new_subexprs = [ex for ex in subexprs if ex is not common_subexpr]
            new_node = CodeNode(
                node.node,
                claripy.And(*new_subexprs),
            )
            new_nodes.append(new_node)

        new_node = CodeNode(SequenceNode(nodes=new_nodes), common_subexpr)
        return new_node

    def _make_condition_nodes(self, seq):

        # make all conditionally-reachable nodes ConditionNodes
        for i in range(len(seq.nodes)):
            node = seq.nodes[i]

            if isinstance(node, CodeNode):
                if isinstance(node.node, SequenceNode):
                    self._make_condition_nodes(node.node)

                if node.reaching_condition is not None and not claripy.is_true(node.reaching_condition):
                    if isinstance(node.node, ConditionalBreakNode):
                        # Put conditions together and simplify them
                        cond = claripy.And(node.reaching_condition, node.node.condition)
                        new_node = CodeNode(ConditionalBreakNode(node.node.addr, cond, node.node.target), None)
                    else:
                        new_node = ConditionNode(node.addr, None, node.reaching_condition, node,
                                                 None)
                    seq.nodes[i] = new_node

    def _make_ite(self, seq, node_0, node_1):

        node_0_pos = seq.node_position(node_0)
        node_1_pos = seq.node_position(node_1)
        pos = max(node_0_pos, node_1_pos)

        node_0_, node_1_ = node_0.copy(), node_1.copy()
        # clear their reaching conditions
        node_0_.reaching_condition = None
        node_1_.reaching_condition = None

        node_0_kids = self._nodes_guarded_by_common_subexpr(seq, node_0.reaching_condition, node_0_pos + 1)
        node_0_kids.insert(0, (node_0_pos, node_0_, [ node_0.reaching_condition ]))
        node_1_kids = self._nodes_guarded_by_common_subexpr(seq, node_1.reaching_condition, node_1_pos + 1)
        node_1_kids.insert(0, (node_1_pos, node_1_, [ node_1.reaching_condition ]))

        new_node_0 = self._create_seq_node_guarded_by_common_subexpr(node_0.reaching_condition,
                                                                     node_0_kids)
        new_node_1 = self._create_seq_node_guarded_by_common_subexpr(node_1.reaching_condition,
                                                                     node_1_kids)

        self._new_sequences.append(new_node_0.node)
        self._new_sequences.append(new_node_1.node)

        # erase all nodes in the candidates
        for idx, _, _ in node_0_kids + node_1_kids:
            seq.nodes[idx] = None

        seq.insert_node(pos, ConditionNode(0, None, node_0.reaching_condition, new_node_0,
                                           new_node_1))
        seq.nodes = [ n for n in seq.nodes if n is not None ]

    def _merge_conditional_breaks(self, seq):

        # Find consecutive ConditionalBreakNodes and merge their conditions

        new_nodes = [ ]
        i = 0
        while i < len(seq.nodes):
            node = seq.nodes[i]

            if type(node) is CodeNode:
                node = node.node

            if isinstance(node, SequenceNode):
                node = self._merge_conditional_breaks(node)
            elif isinstance(node, ConditionalBreakNode) and i > 0:
                prev_node = seq.nodes[i-1]
                if type(prev_node) is CodeNode:
                    prev_node = prev_node.node
                if isinstance(prev_node, ConditionalBreakNode):
                    # found them!

                    # pop the previously added node
                    if new_nodes:
                        new_nodes = new_nodes[:-1]

                    merged_condition = self._simplify_condition(claripy.Or(node.condition, prev_node.condition))
                    new_node = ConditionalBreakNode(node.addr,
                                                    merged_condition,
                                                    node.target
                                                    )
                    node = new_node

            new_nodes.append(node)
            i += 1

        return SequenceNode(new_nodes)

    def _remove_claripy_bool_asts(self, node):

        # Convert claripy Bool ASTs to AIL expressions

        if isinstance(node, SequenceNode):
            new_nodes = [ ]
            for n in node.nodes:
                new_node = self._remove_claripy_bool_asts(n)
                new_nodes.append(new_node)
            new_seq_node = SequenceNode(new_nodes)
            return new_seq_node

        elif isinstance(node, CodeNode):
            node = CodeNode(self._remove_claripy_bool_asts(node.node),
                            None if node.reaching_condition is None
                            else self._convert_claripy_bool_ast(node.reaching_condition))
            return node

        elif isinstance(node, ConditionalBreakNode):

            return ConditionalBreakNode(node.addr,
                                        self._convert_claripy_bool_ast(node.condition),
                                        node.target,
                                        )

        elif isinstance(node, ConditionNode):

            return ConditionNode(node.addr,
                                 None if node.reaching_condition is None else
                                    self._convert_claripy_bool_ast(node.reaching_condition),
                                 self._convert_claripy_bool_ast(node.condition),
                                 self._remove_claripy_bool_asts(node.true_node),
                                 self._remove_claripy_bool_asts(node.false_node),
                                 )

        elif isinstance(node, LoopNode):

            return LoopNode(node.sort,
                            node.condition,
                            self._remove_claripy_bool_asts(node.sequence_node),
                            addr=node.addr,
                            )

        elif isinstance(node, SwitchCaseNode):
            return SwitchCaseNode(self._convert_claripy_bool_ast(node.switch_expr),
                                  dict((idx, self._remove_claripy_bool_asts(case_node))
                                       for idx, case_node in node.cases.items()),
                                  self._remove_claripy_bool_asts(node.default_node),
                                  addr=node.addr)

        else:
            return node

    @staticmethod
    def _merge_nodes(node_0, node_1):

        if isinstance(node_0, SequenceNode):
            if isinstance(node_1, SequenceNode):
                return SequenceNode(nodes=node_0.nodes + node_1.nodes)
            else:
                return SequenceNode(nodes=node_0.nodes + [ node_1 ])
        else:
            if isinstance(node_1, SequenceNode):
                return SequenceNode(nodes=[node_0] + node_1.nodes)
            else:
                return SequenceNode(nodes=[node_0, node_1])

    def _get_last_statement(self, block):
        if type(block) is SequenceNode:
            if block.nodes:
                return self._get_last_statement(block.nodes[-1])
        elif type(block) is CodeNode:
            return self._get_last_statement(block.node)
        elif type(block) is ailment.Block:
            if not block.statements:
                raise EmptyBlockNotice()
            return block.statements[-1]
        elif type(block) is Block:
            return block.vex.statements[-1]
        elif type(block) is BlockNode:
            b = self.project.factory.block(block.addr, size=block.size)
            return b.vex.statements[-1]
        elif type(block) is MultiNode:
            # get the last node
            for the_block in reversed(block.nodes):
                try:
                    last_stmt = self._get_last_statement(the_block)
                    return last_stmt
                except EmptyBlockNotice:
                    continue
        elif type(block) is LoopNode:
            return self._get_last_statement(block.sequence_node)
        elif type(block) is ConditionalBreakNode:
            return None
        elif type(block) is ConditionNode:
            return None
        elif type(block) is BreakNode:
            return None
        elif type(block) is SwitchCaseNode:
            return None
        elif type(block) is GraphRegion:
            # normally this should not happen. however, we have test cases that trigger this case.
            return None

        raise NotImplementedError()

    def _remove_last_statement(self, node):

        stmt = None

        if type(node) is CodeNode:
            stmt = self._remove_last_statement(node.node)
        elif type(node) is ailment.Block:
            stmt = node.statements[-1]
            node.statements = node.statements[:-1]
        elif type(node) is MultiNode:
            if node.nodes:
                stmt = self._remove_last_statement(node.nodes[-1])
        elif type(node) is SequenceNode:
            if node.nodes:
                stmt = self._remove_last_statement(node.nodes[-1])
        else:
            raise NotImplementedError()

        return stmt

    def _append_statement(self, node, stmt):

        if type(node) is CodeNode:
            self._append_statement(node.node, stmt)
            return
        if type(node) is ailment.Block:
            node.statements.append(stmt)
            return
        if type(node) is MultiNode:
            if node.nodes:
                self._append_statement(node.nodes[-1], stmt)
            else:
                raise NotImplementedError()
            return
        if type(node) is SequenceNode:
            if node.nodes:
                self._append_statement(node.nodes[-1], stmt)
            else:
                raise NotImplementedError()
            return

        raise NotImplementedError()

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

        last_stmt = self._get_last_statement(src_block)

        if last_stmt is None:
            return claripy.true
        if type(last_stmt) is ailment.Stmt.Jump:
            if isinstance(last_stmt.target, ailment.Expr.Const):
                return claripy.true
            # indirect jump
            target_ast = self._claripy_ast_from_ail_condition(last_stmt.target)
            return target_ast == dst_block.addr
        if type(last_stmt) is ailment.Stmt.ConditionalJump:
            bool_var = self._claripy_ast_from_ail_condition(last_stmt.condition)
            if last_stmt.true_target.value == dst_block.addr:
                return bool_var
            else:
                return claripy.Not(bool_var)

        return claripy.true

    @staticmethod
    def _extract_jump_targets(stmt):
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

    @staticmethod
    def _get_reaching_condition_subexprs(claripy_ast):

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
                    subexprs = Structurer._get_reaching_condition_subexprs(arg)
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

    def _claripy_ast_from_ail_condition(self, condition):

        # Unpack a condition all the way to the leaves

        _mapping = {
            'LogicalAnd': lambda expr, conv: claripy.And(conv(expr.operands[0]), conv(expr.operands[1])),
            'LogicalOr': lambda expr, conv: claripy.Or(conv(expr.operands[0]), conv(expr.operands[1])),
            'CmpEQ': lambda expr, conv: conv(expr.operands[0]) == conv(expr.operands[1]),
            'CmpNE': lambda expr, conv: conv(expr.operands[0]) != conv(expr.operands[1]),
            'CmpLE': lambda expr, conv: conv(expr.operands[0]) <= conv(expr.operands[1]),
            'CmpLT': lambda expr, conv: conv(expr.operands[0]) < conv(expr.operands[1]),
            'CmpGE': lambda expr, conv: conv(expr.operands[0]) >= conv(expr.operands[1]),
            'CmpGT': lambda expr, conv: conv(expr.operands[0]) > conv(expr.operands[1]),
            'Add': lambda expr, conv: conv(expr.operands[0]) + conv(expr.operands[1]),
            'Sub': lambda expr, conv: conv(expr.operands[0]) - conv(expr.operands[1]),
            'Not': lambda expr, conv: claripy.Not(conv(expr.operand)),
            'Xor': lambda expr, conv: conv(expr.operands[0]) ^ conv(expr.operands[1]),
            'And': lambda expr, conv: conv(expr.operands[0]) & conv(expr.operands[1]),
            'Shr': lambda expr, conv: claripy.LShR(conv(expr.operands[0]), expr.operands[1].value)
        }

        if isinstance(condition, (ailment.Expr.Load, ailment.Expr.DirtyExpression)):
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
                var_ = self._claripy_ast_from_ail_condition(condition.operands[0])
                name = 'ailcond_Conv(%d->%d, %s)' % (condition.from_bits, condition.to_bits, repr(var_))
                var = claripy.BoolS(name, explicit_name=True)
            else:
                var_ = self._claripy_ast_from_ail_condition(condition.operands[0])
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

        lambda_expr = _mapping.get(condition.op, None)
        if lambda_expr is None:
            raise NotImplementedError("Unsupported AIL expression operation %s. Consider implementing." % condition.op)
        expr = lambda_expr(condition, self._claripy_ast_from_ail_condition)
        if expr is NotImplemented:
            expr = claripy.BVS("ailexpr_%r" % condition, condition.bits, explicit_name=True)
            self._condition_mapping[expr] = condition
        return expr

    @staticmethod
    def _negate_cond(cond):
        if isinstance(cond, ailment.Expr.UnaryOp) and cond.op == 'Not':
            # Unpacck it
            return cond.operand
        return ailment.Expr.UnaryOp(0, 'Not', cond)

    def _simplify_condition(self, cond):

        claripy_simplified = claripy.simplify(cond)
        if not claripy_simplified.symbolic:
            return claripy_simplified
        simplified = self._revert_short_circuit_conditions(cond)
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


register_analysis(RecursiveStructurer, 'RecursiveStructurer')
register_analysis(Structurer, 'Structurer')

# delayed import
from .sequence_walker import SequenceWalker
