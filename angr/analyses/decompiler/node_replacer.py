from __future__ import annotations

from angr.ailment import Block
from .sequence_walker import SequenceWalker
from .structuring.structurer_nodes import BaseNode, SequenceNode, MultiNode


class NodeReplacer(SequenceWalker):
    """
    Replaces nodes in a node with new nodes based on a mapping.
    """

    def __init__(self, root: BaseNode, replacements: dict) -> None:
        super().__init__(update_seqnode_in_place=False)

        self.root = root
        self.replacements = replacements
        self.result: BaseNode = self.walk(self.root)  # type:ignore

    def _handle(self, node: BaseNode, **kwargs):
        return self.replacements[node] if node in self.replacements else super()._handle(node, **kwargs)

    def _handle_MultiNode(self, node: MultiNode, **kwargs):
        changed = False
        nodes_copy = list(node.nodes)

        i = len(nodes_copy) - 1
        has_non_block = False
        while i > -1:
            node_ = nodes_copy[i]
            new_node = self._handle(node_, parent=node, index=i)
            if new_node is not None:
                changed = True
                nodes_copy[i] = new_node
                if not isinstance(new_node, Block):
                    has_non_block = True
            i -= 1
        if not changed:
            return None
        if has_non_block:
            return SequenceNode(node.addr, nodes=nodes_copy)
        return MultiNode(nodes_copy, addr=node.addr, idx=node.idx)
