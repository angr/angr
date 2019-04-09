
from ..engine import SimEngine


class SimEngineAIL(SimEngine):
    """
    Execution engine based on AIL.
    """

    def __init__(self, project=None):
        super().__init__(project)

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


    def _process(self, state, successors, **kwargs):
        addr = state._ip

        raise NotImplementedError()
