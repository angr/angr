
from .sequence import handle_SequenceNode
from .multi import handle_MultiNode
from .block import handle_BlockNode

NODE_HANDLERS = { }

def init():
    from ....analyses.decompiler.structurer import SequenceNode, MultiNode
    from ailment import Block
    NODE_HANDLERS[SequenceNode] = handle_SequenceNode
    NODE_HANDLERS[MultiNode] = handle_MultiNode
    NODE_HANDLERS[Block] = handle_BlockNode
