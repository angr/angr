# pylint:disable=missing-class-docstring
from typing import List, Tuple, Any, Optional, Union, Dict

import claripy
import ailment


INDENT_DELTA = 2


class EmptyBlockNotice(Exception):
    pass


class MultiNode:

    __slots__ = ('nodes', )

    def __init__(self, nodes):

        # delayed import
        from .graph_region import GraphRegion  # pylint:disable=import-outside-toplevel

        self.nodes = [ ]

        for node in nodes:
            if type(node) is MultiNode:
                self.nodes += node.nodes
            elif type(node) is GraphRegion:
                self.nodes += node.nodes
            else:
                self.nodes.append(node)

    def copy(self):
        return MultiNode(self.nodes[::])

    def __repr__(self):

        addrs = [ ]
        s = ""
        for node in self.nodes:
            if hasattr(node, 'addr'):
                addrs.append(node.addr)
            s = ": %#x-%#x" % (min(addrs), max(addrs))

        return "<MultiNode of %d nodes%s>" % (len(self.nodes), s)

    @property
    def addr(self):
        return self.nodes[0].addr


class BaseNode:

    __slots__ = ()

    @staticmethod
    def test_empty_node(node):
        # pylint:disable=simplifiable-if-statement
        if type(node) is ailment.Block:
            if not node.statements:
                return True
            # not empty
            return False
        elif type(node) is CodeNode:
            return BaseNode.test_empty_node(node.node)
        # unsupported node type. probably not empty?
        return False

    @staticmethod
    def test_empty_condition_node(cond_node):

        for node in [ cond_node.true_node, cond_node.false_node ]:
            if node is None:
                continue
            if type(node) is CodeNode and BaseNode.test_empty_node(node.node):
                continue
            if BaseNode.test_empty_node(node):
                continue
            return False

        return True


class SequenceNode(BaseNode):

    __slots__ = ('addr', 'nodes',)

    def __init__(self, addr: Optional[int], nodes=None):
        self.addr = addr
        self.nodes = nodes if nodes is not None else [ ]

    def __repr__(self):
        if self.addr is None:
            return "<SequenceNode, %d nodes>" % len(self.nodes)
        else:
            return "<SequenceNode %#x, %d nodes>" % (self.addr, len(self.nodes))

    def add_node(self, node):
        self.nodes.append(node)

    def insert_node(self, pos, node):
        self.nodes.insert(pos, node)

    def remove_node(self, node):
        self.nodes.remove(node)

    def node_position(self, node):
        return self.nodes.index(node)

    def copy(self):
        return SequenceNode(self.addr, nodes=self.nodes[::])

    def dbg_repr(self, indent=0):
        s = ""
        for node in self.nodes:
            s += (node.dbg_repr(indent=indent + INDENT_DELTA))
            s += "\n"

        return s


class CodeNode(BaseNode):

    __slots__ = ('node', 'reaching_condition', )

    def __init__(self, node, reaching_condition):
        self.node = node
        self.reaching_condition = reaching_condition

    def __repr__(self):
        if self.addr is not None:
            if self.idx is not None:
                return f"<CodeNode {self.addr:#x}.{self.idx}>"
            return "<CodeNode %#x>" % self.addr
        else:
            return "<CodeNode %s>" % repr(self.node)

    @property
    def addr(self):
        if hasattr(self.node, 'addr'):
            return self.node.addr
        else:
            return None

    @property
    def idx(self):
        if hasattr(self.node, "idx"):
            return self.node.idx
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


class ConditionNode(BaseNode):

    __slots__ = ('addr', 'node', 'reaching_condition', 'condition', 'true_node', 'false_node', )

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

    def __repr__(self):
        if self.addr is not None:
            return "<ConditionNode %#x>" % self.addr
        else:
            return "<ConditionNode (%r|%r)>" % (self.true_node, self.false_node)


class CascadingConditionNode(BaseNode):

    __slots__ = ('addr', 'condition_and_nodes', 'else_node', )

    def __init__(self, addr, condition_and_nodes: List[Tuple[Any,BaseNode]], else_node: BaseNode=None):
        self.addr = addr
        self.condition_and_nodes = condition_and_nodes
        self.else_node = else_node


class LoopNode(BaseNode):

    __slots__ = ('sort', 'condition', 'sequence_node', 'initializer', 'iterator', '_addr', '_continue_addr', )

    def __init__(self, sort, condition, sequence_node, addr=None, continue_addr=None, initializer=None, iterator=None):
        self.sort = sort
        self.condition = condition
        self.sequence_node = sequence_node
        self.initializer = initializer
        self.iterator = iterator
        self._addr = addr
        self._continue_addr = continue_addr

    def copy(self):
        return LoopNode(
            self.sort,
            self.condition,
            self.sequence_node,
            addr=self._addr,
            initializer=self.initializer,
            iterator=self.iterator
        )

    @property
    def addr(self):
        if self._addr is None:
            return self.sequence_node.addr
        else:
            return self._addr

    @property
    def continue_addr(self):
        if self._continue_addr is None:
            return self.addr
        else:
            return self._continue_addr

    @continue_addr.setter
    def continue_addr(self, value):
        self._continue_addr = value


class BreakNode(BaseNode):

    __slots__ = ('addr', 'target',)

    def __init__(self, addr, target):
        self.addr = addr
        self.target = target


class ContinueNode(BaseNode):

    __slots__ = ('addr', 'target',)

    def __init__(self, addr, target):
        self.addr = addr
        self.target = target


class ConditionalBreakNode(BreakNode):

    __slots__ = ('condition',)

    def __init__(self, addr, condition, target):
        super().__init__(addr, target)
        self.condition = condition

    def __repr__(self):
        return "<ConditionalBreakNode %#x target:%#x>" % (self.addr, self.target)


class SwitchCaseNode(BaseNode):

    __slots__ = ('switch_expr', 'cases', 'default_node', 'addr', )

    def __init__(self, switch_expr, cases, default_node, addr=None):
        self.switch_expr = switch_expr
        self.cases: Dict[Union[int,Tuple[int]],SequenceNode] = cases
        self.default_node = default_node
        self.addr = addr
