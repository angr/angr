
from ..engines.soot.values import SimSootValue_Local

from ..storage.memory import SimMemory
from .keyvalue_memory import SimKeyValueMemory


class SimJavaVmMemory(SimMemory):
    def __init__(self, memory_id="mem", stack=None):
        super(SimJavaVmMemory, self).__init__()

        self.id = memory_id

        self._stack = [ ] if stack is None else stack

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False, frame=0):

        if type(addr) is SimSootValue_Local:
            cstack = self._stack[-1+(-1*frame)]
            # A local variable
            # TODO: Implement the stacked stack frames model
            cstack.store(addr.name, data, type_=addr.type)
        else:
            import ipdb; ipdb.set_trace()

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False, none_if_missing=False, frame=0):

        if type(addr) is SimSootValue_Local:
            cstack = self._stack[-1+(-1*frame)]
            # Load a local variable
            # TODO: Implement the stacked stack frames model
            return cstack.load(addr.name, none_if_missing)
        else:
            import ipdb; ipdb.set_trace()

    def copy(self):
        return SimJavaVmMemory(
            memory_id=self.id,
            stack=self._stack[::],
        )

    def push_stack_frame(self):
        self._stack.append(SimKeyValueMemory("mem"))

    def pop_stack_frame(self):
        self._stack = self._stack[:-1]

    @property
    def stack(self):
        return self._stack[-1]
