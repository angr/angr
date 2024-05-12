# pylint:disable=missing-class-docstring
from typing import Any
from collections import OrderedDict as ODict

import claripy
import ailment
import ailment.utils


INDENT_DELTA = 2


class EmptyBlockNotice(Exception):
    pass


class MultiNode:
    __slots__ = (
        "nodes",
        "addr",
        "idx",
    )

    def __init__(self, nodes, addr=None, idx=None):
        # delayed import
        from ..graph_region import GraphRegion  # pylint:disable=import-outside-toplevel

        self.nodes = []

        for node in nodes:
            if type(node) is MultiNode:
                self.nodes += node.nodes
            elif type(node) is GraphRegion:
                self.nodes += node.nodes
            else:
                self.nodes.append(node)

        self.addr = addr if addr is not None else self.nodes[0].addr
        self.idx = idx if idx is not None else self.nodes[0].idx if isinstance(self.nodes[0], ailment.Block) else None

    def copy(self):
        return MultiNode(self.nodes[::], addr=self.addr, idx=self.idx)

    def __repr__(self):
        addrs = []
        s = ""
        for node in self.nodes:
            if hasattr(node, "addr"):
                addrs.append(node.addr)
            s = f": {min(addrs):#x}-{max(addrs):#x}"

        return "<MultiNode %#x of %d nodes%s>" % (self.addr, len(self.nodes), s)

    def __hash__(self):
        # changing self.nodes does not change the hash, which enables in-place editing
        return hash((MultiNode, self.addr, self.idx))

    def __eq__(self, other):
        return isinstance(other, MultiNode) and self.nodes == other.nodes

    def dbg_repr(self, indent=0):
        s = ""
        for node in self.nodes:
            s += node.dbg_repr(indent=indent + INDENT_DELTA)
            s += "\n"

        return s


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
        for node in [cond_node.true_node, cond_node.false_node]:
            if node is None:
                continue
            if type(node) is CodeNode and BaseNode.test_empty_node(node.node):
                continue
            if BaseNode.test_empty_node(node):
                continue
            return False

        return True

    addr: int | None

    def dbg_repr(self, indent=0):
        return " " * indent + f"## dbg_repr not implemented for {type(self).__name__}"


class SequenceNode(BaseNode):
    __slots__ = (
        "addr",
        "nodes",
    )

    def __init__(self, addr: int | None, nodes=None):
        self.addr = addr
        self.nodes = nodes if nodes is not None else []

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
            s += node.dbg_repr(indent=indent + INDENT_DELTA)
            s += "\n"

        return s


class CodeNode(BaseNode):
    __slots__ = (
        "node",
        "reaching_condition",
    )

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
        if hasattr(self.node, "addr"):
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
            s += (
                indent_str
                + "if (<block-missing>; %s)\n"
                + indent_str
                + "{\n"
                + indent_str
                + "  %s\n"
                + indent_str
                + "}"
            ) % (self.reaching_condition, self.node)
        else:
            s += indent_str + str(self.node)

        return s

    def copy(self):
        return CodeNode(self.node, self.reaching_condition)


class ConditionNode(BaseNode):
    __slots__ = (
        "addr",
        "node",
        "reaching_condition",
        "condition",
        "true_node",
        "false_node",
    )

    def __init__(self, addr, reaching_condition, condition, true_node, false_node=None):
        self.addr = addr
        self.reaching_condition = reaching_condition
        self.condition = condition
        self.true_node = true_node
        self.false_node = false_node

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = (
            indent_str + f"if (<block-missing>; {self.condition})\n{indent_str}{{\n"
            f"{self.true_node.dbg_repr(indent + INDENT_DELTA) if self.true_node is not None else ''}{indent_str}}}\n"
        )
        if self.false_node is not None:
            s += f"{indent_str}else\n{indent_str}{{\n{self.false_node.dbg_repr(indent + INDENT_DELTA)}{indent_str}}}\n"

        return s

    def __repr__(self):
        if self.addr is not None:
            return "<ConditionNode %#x>" % self.addr
        else:
            return f"<ConditionNode ({self.true_node!r}|{self.false_node!r})>"


class CascadingConditionNode(BaseNode):
    __slots__ = (
        "addr",
        "condition_and_nodes",
        "else_node",
    )

    def __init__(self, addr, condition_and_nodes: list[tuple[Any, BaseNode]], else_node: BaseNode = None):
        self.addr = addr
        self.condition_and_nodes = condition_and_nodes
        self.else_node = else_node


class LoopNode(BaseNode):
    __slots__ = (
        "sort",
        "condition",
        "sequence_node",
        "initializer",
        "iterator",
        "_addr",
        "_continue_addr",
    )

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
            iterator=self.iterator,
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

    def __repr__(self):
        return f"<LoopNode {self.sort}@{self.addr:#x}>"

    def dbg_repr(self, indent=0):
        # initializer = self.initializer.dbg_repr() if self.initializer is not None else 'None'
        # iterator = self.iterator.dbg_repr() if self.iterator else 'None'
        addr = hex(self.addr) if isinstance(self.addr, int) else str(self.addr)
        continue_addr = hex(self.continue_addr) if isinstance(self.continue_addr, int) else str(self.continue_addr)
        indent_str = " " * indent
        return (
            f"{indent_str}LoopNode(sort={self.sort}, initializer={self.initializer}, condition={self.condition}, "
            f"iterator={self.iterator}, addr={addr}, continue_addr={continue_addr}):\n"
            f"{self.sequence_node.dbg_repr(indent=indent + INDENT_DELTA)}"
        )


class BreakNode(BaseNode):
    __slots__ = (
        "addr",
        "target",
    )

    def __init__(self, addr, target):
        self.addr = addr
        self.target = target

    def dbg_repr(self, indent=0):
        return " " * indent + "BreakNode"


class ContinueNode(BaseNode):
    __slots__ = (
        "addr",
        "target",
    )

    def __init__(self, addr, target):
        self.addr = addr
        self.target = target

    def dbg_repr(self, indent=0):
        return " " * indent + "ContinueNode"


class ConditionalBreakNode(BreakNode):
    __slots__ = ("condition",)

    def __init__(self, addr, condition, target):
        super().__init__(addr, target)
        self.condition = condition

    def __repr__(self):
        return f"<ConditionalBreakNode {self.addr:#x} target:{self.target}>"

    def dbg_repr(self, indent=0):
        return " " * indent + "ConditionalBreakNode(condition={self.condition})"


class SwitchCaseNode(BaseNode):
    __slots__ = (
        "switch_expr",
        "cases",
        "default_node",
        "addr",
    )

    def __init__(self, switch_expr, cases: ODict[int | tuple[int, ...], SequenceNode], default_node, addr=None):
        self.switch_expr = switch_expr
        self.cases: ODict[int | tuple[int, ...], SequenceNode] = cases
        self.default_node = default_node
        self.addr = addr


class IncompleteSwitchCaseNode(BaseNode):
    """
    Describes an incomplete set of switch-case nodes. Usually an intermediate result. Should always be restructured
    into a SwitchCaseNode by the end of structuring. Only used in Phoenix structurer.
    """

    __slots__ = ("addr", "head", "cases")

    def __init__(self, addr, head, cases: list):
        self.addr = addr
        self.head = head
        self.cases: list = cases


#
# The following classes are custom AIL statements (not nodes, unfortunately)
#


class IncompleteSwitchCaseHeadStatement(ailment.statement.Statement):
    """
    Describes a switch-case head. This is only created by LoweredSwitchSimplifier.
    """

    __slots__ = ("addr", "switch_variable", "case_addrs", "_case_addrs_str")

    def __init__(self, idx, switch_variable, case_addrs, **kwargs):
        super().__init__(idx, **kwargs)
        self.switch_variable = switch_variable
        # original cmp node, case value | "default", address of the case node, idx of the case node,
        # address of the next cmp node
        self.case_addrs: list[tuple[ailment.Block, int | str, int, int | None, int]] = case_addrs
        # a string representation of the addresses of all cases, used for hashing
        self._case_addrs_str = str(sorted([c[0].addr for c in self.case_addrs if c[0] is not None]))

    def __repr__(self):
        return f"SwitchCaseHead: switch {self.switch_variable} with {len(self.case_addrs)} cases"

    def __str__(self):
        return f"switch ({str(self.switch_variable)}): {len(self.case_addrs)} cases"

    __hash__ = ailment.statement.TaggedObject.__hash__

    def _hash_core(self):
        return ailment.utils.stable_hash(
            (IncompleteSwitchCaseHeadStatement, self.idx, self.switch_variable, self._case_addrs_str)
        )
