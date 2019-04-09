
def handle_MultiNode(engine, state, node):
    """
    Simply push the childnen of the multinode onto the execution stack.

    :param engine:
    :param state:
    :param node:
    :return:
    """
    for child in reversed(node.nodes):
        state.ailexecstack.push(child)
    return False
