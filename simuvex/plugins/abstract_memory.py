from .memory import SimMemory
from .symbolic_memory import SimSymbolicMemory


class SimAbstractMemory(SimMemory):
    '''
    This is an implementation of the abstract store in paper [TODO].
    '''
    def __init__(self, backer=None, memory_id="mem"):
        SimMemory.__init__(self)

        self._regions = {}

        for region, backer_dict in backer.items():
            region_memory = SimSymbolicMemory(backer=backer_dict, memory_id=region)
            region_memory.set_state(self.state)
            self._regions[region] = region_memory

    def set_state(self, state):
        '''
        Overriding the SimStatePlugin.set_state() method
        :param state:
        :return:
        '''
        self.state = state
        for k, v in self._regions.items():
            v.set_state(state)

    def store(self, key, addr, data, condition=None, fallback=None):
        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        self._regions[key].store(addr, data, condition, fallback)

    def load(self, key, addr, size, condition=None, fallback=None):
        if key not in self._regions:
            region_memory = SimSymbolicMemory(memory_id=key)
            region_memory.set_state(self.state)
            self._regions[key] = region_memory

        return self._regions[key].load(addr, size, condition, fallback)
