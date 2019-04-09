
from ..engine import SimEngine


class SimEngineAIL(SimEngine):
    """
    Execution engine based on AIL.
    """

    def __init__(self, project=None):
        super().__init__(project)

    def _process(self, state, successors, **kwargs):
        raise NotImplementedError()
