from collections import OrderedDict
from typing import Tuple, List, Any

from ailment.statement import Statement

from angr.analyses.decompiler.structuring.structurer_nodes import BaseNode, SequenceNode
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
