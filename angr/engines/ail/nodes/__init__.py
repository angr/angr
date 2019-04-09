
from .sequence import handle_SequenceNode
from .multi import handle_MultiNode

NODE_HANDLERS = { }

def init():
    from ....analyses.decompiler.structurer import SequenceNode, MultiNode
    NODE_HANDLERS[SequenceNode] = handle_SequenceNode
    NODE_HANDLERS[MultiNode] = handle_MultiNode
