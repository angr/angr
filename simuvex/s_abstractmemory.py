from .plugins import SimMemory
from .s_memory import SimMemory as SimSymbolicMemory


class SimAbstractMemory(SimMemory):
    def __init__(self):
        SimMemory.__init__(self)

    def store(self, key, addr, size, condition=None, fallback=None):
        raise NotImplementedError()

    def load(self, key, addr, condition=None, fallback=None):
        raise NotImplementedError()