
def handle_SequenceNode(engine, state, node):
    """

    :param engine:
    :param state:
    :param SequenceNode node:
    :return:
    """

    for child in reversed(node.nodes):
        state.ailexecstack.push(child)
    return False
