
import networkx

import claripy
import ailment

from ..block import Block, BlockNode
from . import Analysis, register_analysis
from .region_identifier import MultiNode

INDENT_DELTA = 2


class SequenceNode(object):
    def __init__(self, nodes=None):
        self.nodes = nodes if nodes is not None else [ ]

    def add_node(self, node):
        self.nodes.append(node)

    def insert_node(self, pos, node):
        self.nodes.insert(pos, node)

    def remove_node(self, node):
        self.nodes.remove(node)

    def node_position(self, node):
        return self.nodes.index(node)

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
    def __init__(self, condition, true_node, false_node):
        self.condition = condition
        self.true_node = true_node
        self.false_node = false_node

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = ""
        s += (indent_str + "if (<block-missing>; %s)\n" +
              indent_str + "{\n" +
              indent_str + "%s\n" +
              indent_str + "}\n" +
              indent_str + "else\n" +
              indent_str + "{\n" +
              indent_str + "%s\n" +
              indent_str + "}") % \
             (self.condition, self.true_node.dbg_repr(indent+2), self.false_node.dbg_repr(indent+2))

        return s


class Structurer(Analysis):
    """
    Structure a region.
    """
    def __init__(self, region):

        self._region = region

        self._reaching_conditions = None
        self._predicate_mapping = None

        self._analyze()

    def _analyze(self):

        # let's generate conditions first
        self._recover_reaching_conditions()

        # make the sequence node
        seq = self._make_sequence()

        self._make_ites(seq)

        seq.dbg_print()

    def _recover_reaching_conditions(self):

        edge_conditions = { }
        predicate_mapping = { }
        # traverse the graph to recover the condition for each edge
        for src in self._region.graph.nodes_iter():
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

            # we only care about "code nodes", which are essentially nodes with one or less successors
            if len(self._region.graph.successors(node)) > 1:
                continue

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

            if len(self._region.graph.successors(node)) > 1:
                continue

            seq.add_node(CodeNode(node, self._reaching_conditions.get(node, None)))

        return seq

    def _make_ites(self, seq):

        # search for a == ^a pairs

        while True:
            for node_0 in seq.nodes:
                if not type(node_0) is CodeNode:
                    continue
                rcond_0 = node_0.reaching_condition
                for node_1 in seq.nodes:
                    if not type(node_1) is CodeNode:
                        continue
                    if node_0 is node_1:
                        continue
                    rcond_1 = node_1.reaching_condition
                    cond_ = claripy.simplify(claripy.Not(rcond_0) == rcond_1)
                    if claripy.is_true(cond_):
                        # node_0 and node_1 should be structured using an if-then-else
                        self._make_ite(seq, node_0, node_1)
                        break
            else:
                break

        import ipdb; ipdb.set_trace()

    def _make_ite(self, seq, node_0, node_1):

        pos = max(seq.node_position(node_0), seq.node_position(node_1))

        node_0_, node_1_ = node_0.copy(), node_1.copy()
        # clear their reaching conditions
        node_0_.reaching_condition = None
        node_1_.reaching_condition = None

        seq.insert_node(pos, ConditionNode(node_0.reaching_condition, node_0_, node_1_))

        seq.remove_node(node_0)
        seq.remove_node(node_1)

    def _get_last_statement(self, block):
        if type(block) is ailment.Block:
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

    def _bool_variable_from_ail_condition(self, block, condition):
        return claripy.BoolS('structurer-cond_%#x_%s' % (block.addr, repr(condition)), explicit_name=True)


register_analysis(Structurer, 'Structurer')
