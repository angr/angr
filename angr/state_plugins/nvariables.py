from typing import Type, TypeVar, overload, Any, Optional
import logging

from cle.backends.elf.variable import Variable
from cle.backends.elf.variable_type import VariableType, BaseType, PointerType, ArrayType, StructType

from angr.sim_state import SimState

from .plugin import SimStatePlugin
from .sim_action_object import ast_stripping_decorator, SimActionObject

l = logging.getLogger(name=__name__)


class SimVariable:
    """
    A SimVariable will get dynamically created when queriyng for variable in a state with the SimVariables state
    plugin. It features a link to the state, an address and a type.
    """
    def __init__(self, state, addr, var_type):
        self.state = state
        self.addr = addr
        self.type = var_type

    @staticmethod
    def from_cle_variable(state, cle_variable):
        addr = cle_variable.addr_from_state(state)
        var_type = cle_variable.type
        return SimVariable(state, addr, var_type)

    @property
    def deref(self):
        # dereferincing is equivalent to getting the first array element
        return self.array(0)

    def __getitem__(self, i):
        if type(i) == int:
            return self.array(i)
        if type(i) == str:
            return self.member(i)

    def array(self, i):
        if type(self.type) == ArrayType:
            # an array already addresses its first element
            addr = self.addr
            el_type = self.type.element_type
        elif type(self.type) == PointerType:
            addr = self.state.mem[self.addr].deref
            el_type = self.type.referenced_type
        else:
            raise Exception("{} object cannot be dereferenced".format(self.type))

        new_addr = addr + i * el_type.byte_size
        return SimVariable(self.state, new_addr, el_type)

    def member(self, member_name):
        if type(self.type) == StructType:
            member = self.type[member_name]
            addr = self.addr + member.addr_offset
            return SimVariable(self.state, addr, member.type)

        raise Exception("{} object has no members".format(self.type))


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
            return SimVariable.from_cle_variable(self.state, cle_var)
        return None

    def __getitem__(self, var_name):
        return self.get_variable(var_name)


SimState.register_default('nvariables', SimVariables)

from .. import sim_options as o
from .inspect import BP_AFTER
from ..errors import SimValueError, SimUnsatError, SimSolverModeError, SimSolverOptionError
