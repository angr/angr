from .plugin import SimStatePlugin

import logging
l = logging.getLogger('angr.state_plugins.globals')

class SimStateGlobals(SimStatePlugin):
    def __init__(self, backer=None):
        super(SimStateGlobals, self).__init__()
        self._backer = backer if backer is not None else {}

    def set_state(self, state):
        pass

    def merge(self, other):
        l.warning("Merging is unimplemented for globals")
        return False

    def widen(self):
        l.warning("Widening is unimplemented for globals")
        return False

    def __getitem__(self, k):
        return self._backer[k]

    def __setitem__(self, k, v):
        self._backer[k] = v

    def __delitem__(self, k):
        del self._backer[k]

    def __contains__(self, k):
        return k in self._backer

    def keys(self):
        return self._backer.keys()

    def values(self):
        return self._backer.values()

    def items(self):
        return self._backer.items()

    def get(self, k, alt=None):
        return self._backer.get(k, alt)

    def copy(self):
        return SimStateGlobals(dict(self._backer))

SimStatePlugin.register_default('globals', SimStateGlobals)
