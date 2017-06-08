import logging
from collections import defaultdict

import simuvex

l = logging.getLogger('simuvex.plugins.key_value_storage')


class SimVariables(simuvex.SimStatePlugin):
    def __init__(self, initial_globals=None, initial_locals=None):
        super(SimVariables, self).__init__()

        self.globals = initial_globals if initial_globals is not None else {}
        self.locals = initial_locals if initial_locals is not None else {}

    def copy(self):
        return SimVariables(self.globals, self.locals.copy())

    def set_state(self, s):
        super(SimVariables, self).set_state(s)
