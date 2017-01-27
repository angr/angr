
from ..storage import SimKVStore


class SimKeyValueMemory(SimKVStore):
    def __init__(self, memory_id):
        super(SimKeyValueMemory, self).__init__()
        self.memory_id = memory_id
