
from ..statements import STMT_CLASSES

def handle_BlockNode(engine, state, node):
    """

    :param engine:
    :param state:
    :param SequenceNode node:
    :return:
    """
    # import ipdb; ipdb.set_trace()

    # Step through all statements in this block
    for s in node.statements:
    	STMT_CLASSES[s.__class__](engine, state, s)
    return False
