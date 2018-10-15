
import logging

import networkx

import claripy
import ailment

from ...block import Block, BlockNode
from .. import Analysis, register_analysis
from .region_identifier import RegionIdentifier, MultiNode, GraphRegion

l = logging.getLogger('angr.analyses.structurer')

INDENT_DELTA = 2


class SequenceNode(object):
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
            if type(node) is ailment.Block and not node.statements:
                continue
            new_nodes.append(node)

        self.nodes = new_nodes

    def copy(self):
        return SequenceNode(nodes=self.nodes[::])

    def dbg_repr(self, indent=0):
        s = ""
        for node in self.nodes:
            s += (node.dbg_repr(indent=indent + INDENT_DELTA))
            s += "\n"

        return s


class CodeNode(object):
    def __init__(self, node, reaching_condition):
        self.node = node
        self.reaching_condition = reaching_condition

    def __repr__(self):
        return "<CodeNode %#x>" % self.addr

    @property
    def addr(self):
        return self.node.addr

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


class ConditionNode(object):
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


class LoopNode(object):
    def __init__(self, sort, condition, sequence_node):
        self.sort = sort
        self.condition = condition
        self.sequence_node = sequence_node

    @property
    def addr(self):
        return self.sequence_node.addr


class BreakNode(object):
    def __init__(self, target):
        self.target = target


class ConditionalBreakNode(BreakNode):
    def __init__(self, condition, target):
        super(ConditionalBreakNode, self).__init__(target)

        self.condition = condition


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

        # Case A: The loop successor is inside the current region (does it happen at all?)
        loop_successors = set()

        for node, successors in networkx.bfs_successors(graph, head):
            if node in loop_subgraph:
                for suc in successors:
                    if suc not in loop_subgraph:
                        loop_successors.add(suc)

        # Case B: The loop successor is the successor to this region in the parent graph
        if not loop_successors:
            parent_graph = self._parent_region.graph
            for node, successors in networkx.bfs_successors(parent_graph, self._region):
                for suc in successors:
                    loop_successors.add(suc)

        return loop_subgraph, loop_successors

    def _refine_loop_successors(self, loop_subgraph, loop_successors):  # pylint:disable=unused-argument,no-self-use

        l.warning('_refine_loop_successors() is not implemented yet.')

    def _make_endless_loop(self, loop_head, loop_subgraph, loop_successors):

        # TODO: At this point, the loop body should be a SequenceNode
        loop_body = self._to_loop_body_sequence(loop_head, loop_subgraph, loop_successors)

        # create a while(true) loop with sequence node being the loop body
        loop_node = LoopNode('while', None, loop_body)

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
            if type(first_node) is ConditionalBreakNode:
                while_cond = ailment.Expr.UnaryOp(0, 'Not', first_node.condition)
                new_seq = loop_node.sequence_node.copy()
                new_seq.nodes = new_seq.nodes[1:]
                new_loop_node = LoopNode('while', while_cond, new_seq)

                return True, new_loop_node

        return False, loop_node

    @staticmethod
    def _refine_loop_dowhile(loop_node):

        if loop_node.sort == 'while' and loop_node.condition is None:
            # it's an endless loop
            last_node = loop_node.sequence_node.nodes[-1]
            if type(last_node) is ConditionalBreakNode:
                while_cond = ailment.Expr.UnaryOp(0, 'Not', last_node.condition)
                new_seq = loop_node.sequence_node.copy()
                new_seq.nodes = new_seq.nodes[:-1]
                new_loop_node = LoopNode('do-while', while_cond, new_seq)

                return True, new_loop_node

        return False, loop_node

    def _to_loop_body_sequence(self, loop_head, loop_subgraph, loop_successors):

        graph = self._region.graph
        seq = SequenceNode()

        # TODO: Make sure the loop body has been structured

        queue = [ loop_head ]
        traversed = set()
        loop_successors = set(loop_successors)

        while queue:
            node = queue[0]
            queue = queue[1:]

            seq.nodes.append(node)

            traversed.add(node)

            successors = graph.successors(node)
            for dst in successors:
                if dst in loop_successors:
                    # add a break or a conditional break node
                    last_stmt = self._get_last_statement(node)
                    if type(last_stmt) is ailment.Stmt.Jump:
                        # add a break
                        seq.nodes.append(BreakNode(dst))
                        # shrink the block to remove the last statement
                        self._remove_last_statement(node)
                    elif type(last_stmt) is ailment.Stmt.ConditionalJump:
                        # add a conditional break
                        if last_stmt.true_target.value == dst.addr:
                            cond = last_stmt.condition
                        elif last_stmt.false_target.value == dst.addr:
                            cond = ailment.Expr.UnaryOp(last_stmt.condition.idx, 'Not', (last_stmt.condition))
                        else:
                            l.warning("I'm not sure which branch is jumping out of the loop...")
                            raise Exception()
                        seq.nodes.append(ConditionalBreakNode(cond, dst))
                        # remove the last statement from the node
                        self._remove_last_statement(node)
                    continue
                else:
                    # sanity check
                    if dst not in loop_subgraph:
                        # what's this node?
                        l.error("Found a node that belongs to neither loop body nor loop successors. Something is wrong.")
                        raise Exception()
                if dst in traversed:
                    continue
                queue.append(dst)

            if len(queue) > 1:
                l.error("It seems that the loop body hasn't been properly structured.")
                raise Exception()

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
                reaching_conditions[node] = claripy.simplify(reaching_condition)

        self._reaching_conditions = reaching_conditions
        self._predicate_mapping = predicate_mapping

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

        # make all conditionally-reachable nodes a ConditionNode
        for i in range(len(seq.nodes)):
            node = seq.nodes[i]
            if node.reaching_condition is not None and not claripy.is_true(node.reaching_condition):
                new_node = ConditionNode(node.addr, None, node.reaching_condition, node, None)
                seq.nodes[i] = new_node

    @staticmethod
    def _make_ite(seq, node_0, node_1):

        pos = max(seq.node_position(node_0), seq.node_position(node_1))

        node_0_, node_1_ = node_0.copy(), node_1.copy()
        # clear their reaching conditions
        node_0_.reaching_condition = None
        node_1_.reaching_condition = None

        seq.insert_node(pos, ConditionNode(0, None, node_0.reaching_condition, node_0_, node_1_))

        seq.remove_node(node_0)
        seq.remove_node(node_1)

    def _get_last_statement(self, block):
        if type(block) is SequenceNode:
            if block.nodes:
                return self._get_last_statement(block.nodes[-1])
        elif type(block) is CodeNode:
            return self._get_last_statement(block.node)
        elif type(block) is ailment.Block:
            return block.statements[-1]
        elif type(block) is Block:
            return block.vex.statements[-1]
        elif type(block) is BlockNode:
            b = self.project.factory.block(block.addr, size=block.size)
            return b.vex.statements[-1]
        elif type(block) is MultiNode:
            # get the last node
            the_block = block.nodes[-1]
            return self._get_last_statement(the_block)
        else:
            raise NotImplementedError()

        return None

    def _remove_last_statement(self, node):

        if type(node) is CodeNode:
            self._remove_last_statement(node.node)
        elif type(node) is ailment.Block:
            node.statements = node.statements[:-1]
        elif type(node) is MultiNode:
            if node.nodes:
                self._remove_last_statement(node.nodes[-1])
        elif type(node) is SequenceNode:
            if node.nodes:
                self._remove_last_statement(node.nodes[-1])
        else:
            raise NotImplementedError()

    def _extract_predicate(self, src_block, dst_block):
        last_stmt = self._get_last_statement(src_block)

        if type(last_stmt) is ailment.Stmt.ConditionalJump:
            bool_var = self._bool_variable_from_ail_condition(src_block, last_stmt.condition)
            if last_stmt.true_target.value == dst_block.addr:
                return bool_var
            else:
                return claripy.Not(bool_var)

        else:
            raise NotImplementedError()

    @staticmethod
    def _bool_variable_from_ail_condition(block, condition):
        return claripy.BoolS('structurer-cond_%#x_%s' % (block.addr, repr(condition)), explicit_name=True)


register_analysis(RecursiveStructurer, 'RecursiveStructurer')
register_analysis(Structurer, 'Structurer')
