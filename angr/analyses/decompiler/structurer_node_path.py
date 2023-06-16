from typing import List, Tuple, Type, Optional, Any
from enum import Enum

from .structuring.structurer_nodes import BaseNode, SequenceNode, ConditionNode


class ConditionNodeChildren(Enum):
    TrueNode = 0
    FalseNode = 1


CascadingConditionElseNode = -1


class NodePath:
    """
    Describes a serializable path to a node from the root SequenceNode.
    """

    def __init__(self, path: List[Tuple[Type, Any]]):
        self._path = path

    def locate_node(self, root: SequenceNode) -> Tuple[Optional[BaseNode], Optional[BaseNode]]:
        curr_node = root
        parent_node = None
        for node_type, arg in self._path:
            parent_node = curr_node
            if node_type is SequenceNode:
                curr_node = self._locate_node_in_sequence_node(curr_node, arg)
            elif node_type is ConditionNode:
                curr_node = self._locate_node_in_condition_node(curr_node, arg)
            else:
                raise NotImplementedError()
            if curr_node is None:
                break

        if curr_node is None:
            return None, None
        return parent_node, curr_node

    def replace_node(
        self,
        old_node: BaseNode,
        new_node: BaseNode,
        parent_node: Optional[BaseNode] = None,
        root_node: Optional[BaseNode] = None,
    ) -> bool:
        if parent_node is None:
            # find the parent node
            if root_node is None:
                raise ValueError("parent_node and root_node cannot be None at the same time")
            parent_node, _ = self.locate_node(root_node)

        if parent_node is None:
            raise ValueError("Cannot locate the node in the AST")

        if isinstance(parent_node, SequenceNode):
            idx = self._path[-1][1]
            if idx < len(parent_node.nodes) and parent_node.nodes[idx] is old_node:
                parent_node.nodes[idx] = new_node
                return True
        elif isinstance(parent_node, ConditionNode):
            idx = self._path[-1][1]
            if idx == ConditionNodeChildren.TrueNode and parent_node.true_node is old_node:
                parent_node.true_node = new_node
                return True
            elif idx == ConditionNodeChildren.FalseNode and parent_node.false_node is old_node:
                parent_node.false_node = new_node
                return True
        else:
            raise NotImplementedError()

        return False

    def copy(self) -> "NodePath":
        return NodePath(list(self._path))

    def append(self, elem: Tuple[Type, Any]):
        self._path.append(elem)

    def next(self, elem: Tuple[Type, Any]) -> "NodePath":
        o = self.copy()
        o.append(elem)
        return o

    def _locate_node_in_sequence_node(self, node, node_idx: int) -> Optional[BaseNode]:
        if type(node) is not SequenceNode:
            return None

        if node_idx >= len(node.nodes):
            return None

        return node.nodes[node_idx]

    def _locate_node_in_condition_node(self, node, child_idx: ConditionNodeChildren) -> Optional[BaseNode]:
        if type(node) is not ConditionNode:
            return None

        if child_idx == ConditionNodeChildren.TrueNode:
            return node.true_node
        elif child_idx == ConditionNodeChildren.FalseNode:
            return node.false_node
        return None
