from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import SwitchCaseNode, LoopNode


class ControlFlowStructureCounter(SequenceWalker):
    """
    Counts the number of different types of control flow structures found in a sequence of nodes.
    This should be used after the sequence has been simplified.
    """

    def __init__(self, node):
        handlers = {
            LoopNode: self._handle_Loop,
        }
        super().__init__(handlers)

        self.while_loops = 0
        self.do_while_loops = 0
        self.for_loops = 0

        self.walk(node)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        if node.sort == "while":
            self.while_loops += 1
        elif node.sort == "do-while":
            self.do_while_loops += 1
        elif node.sort == "for":
            self.for_loops += 1

        return super()._handle_Loop(node, **kwargs)

    def _handle_Condition(self, node, parent=None, **kwargs):
        return super()._handle_Condition(node, parent=parent, **kwargs)

    def _handle_SwitchCase(self, node: SwitchCaseNode, parent=None, **kwargs):
        return super()._handle_SwitchCase(node, parent=parent, **kwargs)
