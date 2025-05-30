from collections import OrderedDict
from typing import Tuple

from angr.ailment.statement import Statement

from angr.analyses.decompiler.structuring.structurer_nodes import BaseNode, SequenceNode, INDENT_DELTA
from angr.rust.sim_type import EnumVariant


class PatternMatchNode(BaseNode):
    __slots__ = (
        "scrutinee",
        "arms",
        "default_node",
        "addr",
    )

    def __init__(
        self,
        scrutinee,
        arms: OrderedDict[Tuple[EnumVariant, Tuple[Statement]], SequenceNode],
        default_node,
        addr=None,
    ):
        self.scrutinee = scrutinee
        self.arms = arms
        self.default_node = default_node
        self.addr = addr

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = indent_str + f"match {self.scrutinee} {{\n"
        for (variant, _), node in self.arms.items():
            s += indent_str + f"{variant} => {{\n" + node.dbg_repr(indent + INDENT_DELTA) + "\n},\n"
        return s


class IfLetNode(BaseNode):
    __slots__ = (
        "pattern",
        "scrutinee",
        "true_node",
        "false_node",
        "addr",
    )

    def __init__(
        self,
        pattern,
        scrutinee,
        true_node,
        false_node=None,
        addr=None,
    ):
        self.pattern = pattern
        self.scrutinee = scrutinee
        self.true_node = true_node
        self.false_node = false_node
        self.addr = addr

    def dbg_repr(self, indent=0):
        indent_str = indent * " "
        s = indent_str + f"if let {self.pattern} {{\n"
        s += indent_str + self.true_node.dbg_repr(indent + INDENT_DELTA) + "\n}"
        if self.false_node:
            s += ", else {\n" + self.false_node.dbg_repr(indent + INDENT_DELTA) + "\n}"
        return s
