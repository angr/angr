
import logging

from ..storage import SimKVStore
from .plugin import SimStatePlugin

l = logging.getLogger("angr.state_plugins.keyvalue_memory")


class SimKeyValueMemory(SimKVStore): # pylint: disable=abstract-method
    def __init__(self, memory_id, store=None):
        super(SimKeyValueMemory, self).__init__(store)
        self.memory_id = memory_id

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument,arguments-differ
        return SimKeyValueMemory(memory_id=self.memory_id,
                                 store=self._store.copy())

from angr.sim_state import SimState
SimState.register_default('keyvalue_memory', SimKeyValueMemory)
