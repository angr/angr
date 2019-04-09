
from .plugin import SimStatePlugin


class AILExecutionStack(SimStatePlugin):
    """
    This class stores all AIL program constructs that haven't finished execution before current program point.
    """
    def __init__(self):
        super().__init__()

        self._stack = [ ]

    def set_state(self, state):
        super().set_state(state)

    #
    # Public methods
    #

    def push(self, construct):
        self._stack.append(construct)

    def pop(self):
        construct = self._stack[-1]
        self._stack = self._stack[ : -1]
        return construct

    def is_empty(self):
        return len(self._stack) == 0

    @SimStatePlugin.memo
    def copy(self, _memo):
        r = AILExecutionStack()
        r._stack = self._stack[::]
        return r

    def merge(self, _others, _merge_conditions, _common_ancestor=None):
        raise NotImplementedError()


from ..sim_state import SimState
SimState.register_default('ailexecstack', AILExecutionStack)
