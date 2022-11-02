from typing import Type, TypeVar, overload, Any, Optional
import logging

from cle.backends.elf.variable import Variable

from angr.sim_state import SimState

from .plugin import SimStatePlugin
from .sim_action_object import ast_stripping_decorator, SimActionObject

l = logging.getLogger(name=__name__)


class SimVariable:
    """
    A SimVariable will get dynamically created when queriyng for variable in a state with the SimVariables state
    plugin. It features a link to the state, an address and a type.
    """
    def __init__(self, state: SimState, cle_variable: Variable):
        self.state = state
        self._cle_variable = cle_variable

    @property
    def addr(self):
        # FIXME the address should depend on the state ip/pc
        return self._cle_variable.addr

    @property
    def type(self):
        return self._cle_variable.type


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
        cle_var = kb.nvariables[var_name][self.state.ip]
        if cle_var:
            return SimVariable(self.state, cle_var)
        return None

    def __getitem__(self, var_name):
        return self.get_variable(var_name)


SimState.register_default('nvariables', SimVariables)

from .. import sim_options as o
from .inspect import BP_AFTER
from ..errors import SimValueError, SimUnsatError, SimSolverModeError, SimSolverOptionError
