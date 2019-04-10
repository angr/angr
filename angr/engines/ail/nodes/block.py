
from ..statements import STMT_CLASSES

def handle_BlockNode(engine, state, node):
    """

    :param engine:
    :param state:
    :param SequenceNode node:
    :return:
    """
    # Step through all statements in this block
    for s in node.statements:
        engine._handle_statement(state, s)
    return False
