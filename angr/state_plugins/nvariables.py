from typing import Type, TypeVar, overload, Any, Optional
import logging

from .plugin import SimStatePlugin
from .sim_action_object import ast_stripping_decorator, SimActionObject

l = logging.getLogger(name=__name__)

class SimVariables(SimStatePlugin):
    """
    This is the plugin you'll use to interact with (global/local) program variables.
    These variables have a name and a visibility scope which depends on the pc address of the state.
    With this plugin, you can access/modify the value of such variable or find its memory address.
    For creating program varibles, or for importing them from cle, see the knowledge plugin nvariables.

    This plugin should be available on a state as ``state.nvariables``.
    """
    def __init__(self):
        super().__init__()

    def get_variable(self, var_name):
        kb = self.state.project.kb
        return kb.nvariables[var_name][self.state.ip]

    def __getitem__(self, var_name):
        return self.get_variable(var_name)


from angr.sim_state import SimState
SimState.register_default('nvariables', SimVariables)

from .. import sim_options as o
from .inspect import BP_AFTER
from ..errors import SimValueError, SimUnsatError, SimSolverModeError, SimSolverOptionError
