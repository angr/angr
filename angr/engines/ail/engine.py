
from ..engine import SimEngine
from .nodes import init, NODE_HANDLERS


class SimEngineAIL(SimEngine):
    """
    Execution engine based on AIL.
    """

    def __init__(self, project=None):
        super().__init__(project)

        init()
        print(NODE_HANDLERS)
        self.node_handlers = NODE_HANDLERS

    def _check(self, state, *args, **kwargs):
        """
        Check whether the AIL symbolic execution engine is applicable for the current address or not.

        :param state:
        :param args:
        :param kwargs:
        :return:        True if it is applicable, False otherwise.
        """
        kb = kwargs.pop("kb", None)
        if kb is None:
            # KB must be available
            return False

        addr = state._ip
        if addr.symbolic:
            return False

        addr = state.solver.eval(addr)
        if self.lift(addr=addr, kb=kb) is None:
            return False

        return True

    def lift(self, addr=None, kb=None):
        """
        Get an AIL node at address `addr` from the given angr knowledge base.

        :param int addr:            The concrete address to lift at.
        :param KnowledgeBase kb:    The angr knowledge base.
        :return:                    The AIL node that starts at address `addr`.
        """

        node = kb.clinic.get_node(addr)

        return node

    def _process(self, state, successors, kb=None, **kwargs):
        """

        :param state:
        :param successors:
        :param kwargs:
        :return:
        """

        if state.ailexecstack.is_empty():
            # The execution stack is empty. Load a new node according to the address
            addr = state.solver.eval(state._ip)
            # get the node
            node = self.lift(addr=addr, kb=kb)
            # push the node on the stack
            state.ailexecstack.push(node)

        # execute the stack
        self._handle_stack(state, successors)

    def _handle_stack(self, state, successors):
        """

        :param state:
        :param successors:
        :param node:
        :return:
        """

        cont = False
        while cont is False:
            # get the next node based on the top element on the stack
            node = state.ailexecstack.pop()
            # handle the node
            cont = self.node_handlers[node.__class__](self, state, node)
