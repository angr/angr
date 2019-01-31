
import logging

import networkx

import claripy
import ailment

from ...block import Block, BlockNode
from .. import Analysis, register_analysis
from .region_identifier import RegionIdentifier, MultiNode, GraphRegion

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
            if type(node) is CodeNode and self._test_empty_node(node.node):
                continue
            if self._test_empty_node(node):
                continue
            new_nodes.append(node)

        self.nodes = new_nodes

    def _test_empty_condition_node(self, cond_node):

        for node in [ cond_node.true_node, cond_node.false_node ]:
            if node is None:
                continue
            if type(node) is CodeNode and self._test_empty_node(node.node):
                continue
            if self._test_empty_node(node):
                continue
            return False

        return True

    def _test_empty_node(self, node):
        if type(node) is ailment.Block:
            if not node.statements:
                return True
            if len(node.statements) == 1 and type(node.statements[0]) is ailment.Stmt.ConditionalJump:
                # conditional jumps have been taken care of during reaching condition recovery
                return True
            else:
                # not empty
                return False
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
                st = self.project.analyses.Structurer(current_region, parent_region=parent_region)
                # replace this region with the resulting node in its parent region... if it's not an orphan
                if not parent_region:
                    # this is the top-level region. we are done!
                    self.result = st.result
                    break
                else:
                    self._replace_region(parent_region, current_region, st.result)

    @staticmethod
    def _replace_region(parent_region, sub_region, node):

        parent_region.replace_region(sub_region, node)


class Structurer(Analysis):
    """
    Structure a region.
    """
    def __init__(self, region, parent_region=None):

        self._region = region
        self._parent_region = parent_region

        self._reaching_conditions = None
        self._predicate_mapping = None
        self._condition_mapping = {}

        self.result = None

        self._analyze()

    def _analyze(self):

        if self._has_cycle():
            self._analyze_cyclic()
        else:
            self._analyze_acyclic()

    def _analyze_cyclic(self):

        # TODO: transform to a single-entry region

        loop_head = self._region.head

        # determine loop nodes and successors
        loop_subgraph, successors = self._find_loop_nodes_and_successors()

        # refine loop successors
        # TODO: transform to a single-successor region
        self._refine_loop_successors(loop_subgraph, successors)

        assert len(successors) <= 1

        loop_node = self._make_endless_loop(loop_head, loop_subgraph, successors)

        loop_node = self._refine_loop(loop_node)

        self.result = SequenceNode(nodes=[ loop_node ] + [ succ for succ in successors if succ in loop_subgraph ])

    def _analyze_acyclic(self):

        # let's generate conditions first
        self._recover_reaching_conditions()

        # make the sequence node
        seq = self._make_sequence()

        self._make_ites(seq)

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

        # find latching nodes

        latching_nodes = set()

        queue = [ head ]
        traversed = set()
        while queue:
            node = queue.pop()
            successors = graph.successors(node)
            traversed.add(node)

            for dst in successors:
                if dst in traversed:
                    latching_nodes.add(node)
                else:
                    queue.append(dst)

        # find loop nodes and successors
        loop_subgraph = RegionIdentifier.slice_graph(graph, head, latching_nodes, include_frontier=True)
        loop_node_addrs = set( node.addr for node in loop_subgraph )

        # Case A: The loop successor is inside the current region (does it happen at all?)
        loop_successors = set()

        for node, successors in networkx.bfs_successors(graph, head):
            if node.addr in loop_node_addrs:
                for suc in successors:
                    if suc not in loop_subgraph:
                        loop_successors.add(suc)

        # Case B: The loop successor is the successor to this region in the parent graph
        if not loop_successors:
            parent_graph = self._parent_region.graph
            for node, successors in networkx.bfs_successors(parent_graph, self._region):
                if node.addr in loop_node_addrs:
                    for suc in successors:
                        if suc not in loop_subgraph:
                            loop_successors.add(suc)

        return loop_subgraph, loop_successors

    def _refine_loop_successors(self, loop_subgraph, loop_successors):  # pylint:disable=unused-argument,no-self-use

        l.warning('_refine_loop_successors() is not implemented yet.')

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
        loop_region_graph = networkx.DiGraph()

        # TODO: Make sure the loop body has been structured

        queue = [ loop_head ]
        traversed = set()
        loop_successors = set(s.addr for s in loop_successors)
        replaced_nodes = {}

        while queue:
            node = queue[0]
            queue = queue[1:]

            loop_region_graph.add_node(node)

            traversed.add(node)

            successors = list(graph.successors(node))  # successors are all inside the current region

            last_stmt = self._get_last_statement(node)
            real_successor_addrs = self._extract_jump_targets(last_stmt)

            if any(succ_addr in loop_successors for succ_addr in real_successor_addrs):
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
                    if last_stmt.true_target.value in loop_successors:
                        cond = last_stmt.condition
                        target = last_stmt.true_target.value
                    elif last_stmt.false_target.value in loop_successors:
                        cond = ailment.Expr.UnaryOp(last_stmt.condition.idx, 'Not', (last_stmt.condition))
                        target = last_stmt.false_target.value
                    else:
                        l.warning("I'm not sure which branch is jumping out of the loop...")
                        raise Exception()
                    # remove the last statement from the node
                    self._remove_last_statement(node)
                    new_node = ConditionalBreakNode(last_stmt.ins_addr, cond, target)

                if new_node is not None:
                    # special checks if node goes empty
                    if isinstance(node, ailment.Block) and not node.statements:
                        replaced_nodes[node] = new_node
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
                if dst not in loop_subgraph:
                    # what's this node?
                    l.error("Found a node that belongs to neither loop body nor loop successors. Something is wrong.")
                    raise Exception()
                if dst is not loop_head:
                    loop_region_graph.add_edge(node, replaced_nodes.get(dst, dst))
                if dst in traversed:
                    continue
                queue.append(dst)

        # Create a graph region and structure it
        region = GraphRegion(loop_head, loop_region_graph)
        structurer = self.project.analyses.Structurer(region)
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

        edge_conditions = { }
        predicate_mapping = { }
        # traverse the graph to recover the condition for each edge
        for src in self._region.graph.nodes():
            nodes = self._region.graph[src]
            if len(nodes) > 1:
                for dst in nodes:
                    edge = src, dst
                    predicate = self._extract_predicate(src, dst)
                    edge_conditions[edge] = predicate
                    predicate_mapping[predicate] = dst

        reaching_conditions = { }
        # recover the reaching condition for each node
        for node in networkx.topological_sort(self._region.graph):
            preds = self._region.graph.predecessors(node)
            reaching_condition = None
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
        self._predicate_mapping = predicate_mapping

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
            'UGT': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpUGT',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__gt__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpGT',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__eq__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpEQ',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__ne__': lambda cond_: ailment.Expr.BinaryOp(None, 'CmpNE',
                                                          tuple(map(self._convert_claripy_bool_ast, cond_.args)),
                                                          ),
            '__xor__': lambda cond_: ailment.Expr.BinaryOp(None, 'Xor',
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

    def _make_ites(self, seq):

        # search for a == ^a pairs

        while True:
            for node_0 in seq.nodes:
                if not type(node_0) is CodeNode:
                    continue
                rcond_0 = node_0.reaching_condition
                if rcond_0 is None:
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
                        break
            else:
                break

        # make all conditionally-reachable nodes ConditionNodes
        for i in range(len(seq.nodes)):
            node = seq.nodes[i]
            if node.reaching_condition is not None and not claripy.is_true(node.reaching_condition):
                if isinstance(node.node, ConditionalBreakNode):
                    # Put conditions together and simplify them
                    cond = claripy.And(node.reaching_condition, self._bool_variable_from_ail_condition(node.node.condition))
                    new_node = CodeNode(ConditionalBreakNode(node.node.addr, cond, node.node.target), None)
                else:
                    new_node = ConditionNode(node.addr, None, node.reaching_condition, node,
                                             None)
                seq.nodes[i] = new_node

    def _make_ite(self, seq, node_0, node_1):

        pos = max(seq.node_position(node_0), seq.node_position(node_1))

        node_0_, node_1_ = node_0.copy(), node_1.copy()
        # clear their reaching conditions
        node_0_.reaching_condition = None
        node_1_.reaching_condition = None

        seq.insert_node(pos, ConditionNode(0, None, node_0.reaching_condition, node_0_,
                                           node_1_))

        seq.remove_node(node_0)
        seq.remove_node(node_1)

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
            for node in node.nodes:
                node = self._remove_claripy_bool_asts(node)
                new_nodes.append(node)
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

        else:
            return node

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
        else:
            raise NotImplementedError()

        return None

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

    def _extract_predicate(self, src_block, dst_block):

        if type(src_block) is ConditionalBreakNode:
            # bool_var = self._bool_variable_from_ail_condition(src_block.condition)
            # if src_block.target == dst_block.addr:
            #     return bool_var
            # else:
            #     return claripy.Not(bool_var)
            if src_block.target == dst_block.addr:
                return claripy.false
            else:
                return claripy.true

        last_stmt = self._get_last_statement(src_block)

        if last_stmt is None:
            return claripy.true
        if type(last_stmt) is ailment.Stmt.Jump:
            return claripy.true
        if type(last_stmt) is ailment.Stmt.ConditionalJump:
            bool_var = self._bool_variable_from_ail_condition(last_stmt.condition)
            if last_stmt.true_target.value == dst_block.addr:
                return bool_var
            else:
                return claripy.Not(bool_var)

        raise NotImplementedError()

    @staticmethod
    def _extract_jump_targets(stmt):
        """
        Extract goto targets from a Jump or a ConditionalJump statement.

        :param stmt:    The statement to analyze.
        :return:        A list of known concrete jump targets.
        :rtype:         list
        """

        targets = [ ]

        # FIXME: We are assuming all jump targets are concrete targets. They may not be.

        if isinstance(stmt, ailment.Stmt.Jump):
            targets.append(stmt.target.value)
        elif isinstance(stmt, ailment.Stmt.ConditionalJump):
            targets.append(stmt.true_target.value)
            targets.append(stmt.false_target.value)

        return targets

    def _bool_variable_from_ail_condition(self, condition):

        # Unpack a condition all the way to the leaves

        _mapping = {
            'LogicalAnd': lambda expr, conv: claripy.And(conv(expr.operands[0]), conv(expr.operands[1])),
            'LogicalOr': lambda expr, conv: claripy.Or(conv(expr.operands[0]), conv(expr.operands[1])),
            'CmpEQ': lambda expr, conv: conv(expr.operands[0]) == conv(expr.operands[1]),
            'CmpLE': lambda expr, conv: conv(expr.operands[0]) <= conv(expr.operands[1]),
            'Not': lambda expr, conv: claripy.Not(conv(expr.operand)),
            'Xor': lambda expr, conv: conv(expr.operands[0]) ^ conv(expr.operands[1]),
        }

        if isinstance(condition, (ailment.Expr.Load, ailment.Expr.Register, ailment.Expr.DirtyExpression)):
            var = claripy.BVS('ailexpr_%s' % repr(condition), condition.bits, explicit_name=True)
            self._condition_mapping[var] = condition
            return var
        elif isinstance(condition, ailment.Expr.Convert):
            # convert is special. if it generates a 1-bit variable, it should be treated as a BVS
            if condition.to_bits == 1:
                var = claripy.BoolS('ailcond_%s' % repr(condition), explicit_name=True)
            else:
                var = claripy.BVS('ailexpr_%s' % repr(condition), condition.to_bits, explicit_name=True)
            self._condition_mapping[var] = condition
            return var
        elif isinstance(condition, ailment.Expr.Const):
            var = claripy.BVV(condition.value, condition.bits)
            return var

        lambda_expr = _mapping.get(condition.op, None)
        if lambda_expr is None:
            raise NotImplementedError("Unsupported AIL expression operation %s. Consider implementing." % condition.op)
        return lambda_expr(condition, self._bool_variable_from_ail_condition)

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

    def _revert_short_circuit_conditions(self, cond):

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
