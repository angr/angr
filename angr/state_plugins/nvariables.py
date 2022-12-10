from typing import TYPE_CHECKING
import logging

from cle.backends.elf.variable import Variable
from cle.backends.elf.variable_type import VariableType, BaseType, PointerType, ArrayType, StructType, TypedefType

from angr.sim_state import SimState
from angr.sim_type import ALL_TYPES, SimTypeReg

from .plugin import SimStatePlugin
from .sim_action_object import ast_stripping_decorator, SimActionObject

l = logging.getLogger(name=__name__)

if TYPE_CHECKING:
    from angr.state_plugins.view import SimMemView


class SimVariable:
    """
    A SimVariable will get dynamically created when queriyng for variable in a state with the SimVariables state
    plugin. It features a link to the state, an address and a type.
    """
    def __init__(self, state: SimState, addr, var_type: VariableType):
        self.state = state
        self.addr = addr
        self.type = var_type

    @staticmethod
    def from_cle_variable(state: SimState, cle_variable: Variable) -> "SimVariable":
        addr = cle_variable.rebased_addr_from_cfa(state.dwarf_cfa)
        var_type = cle_variable.type
        return SimVariable(state, addr, var_type)

    @property
    def deref(self) -> "SimVariable":
        # dereferincing is equivalent to getting the first array element
        return self.array(0)

    @property
    def mem(self) -> "SimMemView":
        if self.addr is None:
            raise Exception("Cannot view a variable without an address")
        if isinstance(self.type, TypedefType):
            unpacked = SimVariable(self.state, self.addr, self.type.type)
            return unpacked.mem

        arch = self.state.arch
        size = self.type.byte_size * arch.byte_width
        name = self.type.name
        if name in ALL_TYPES:
            sim_type = ALL_TYPES[name].with_arch(arch)
            assert size == sim_type.size
        else:
            # FIXME A lot more types are supported by angr that are not in ALL_TYPES (structs, arrays, pointers)
            # Use a fallback type
            sim_type = SimTypeReg(size, label=name)
        return self.state.mem[self.addr].with_type(sim_type)

    @property
    def string(self) -> "SimMemView":
        first_char = self.deref
        # first char should have some char type (could be checked here)
        return first_char.mem.string

    def __getitem__(self, i):
        if isinstance(i, int):
            return self.array(i)
        elif isinstance(i, str):
            return self.member(i)
        raise KeyError

    def array(self, i) -> "SimVariable":
        if isinstance(self.type, TypedefType):
            unpacked = SimVariable(self.state, self.addr, self.type.type)
            return unpacked.array(i)
        elif isinstance(self.type, ArrayType):
            # an array already addresses its first element
            addr = self.addr
            el_type = self.type.element_type
        elif isinstance(self.type, PointerType):
            if self.addr is None:
                addr = None
            else:
                addr = self.state.memory.load(self.addr, self.state.arch.bytes, endness=self.state.arch.memory_endness)
            el_type = self.type.referenced_type
        else:
            raise Exception("{} object cannot be dereferenced".format(self.type))

        if addr is None or el_type.byte_size is None:
            new_addr = None
        else:
            new_addr = addr + i * el_type.byte_size
        return SimVariable(self.state, new_addr, el_type)

    def member(self, member_name: str) -> "SimVariable":
        if isinstance(self.type, TypedefType):
            unpacked = SimVariable(self.state, self.addr, self.type.type)
            return unpacked.member(member_name)
        elif isinstance(self.type, StructType):
            member = self.type[member_name]
            if self.addr is None:
                addr = None
            else:
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

    def get_variable(self, var_name: str) -> SimVariable:
        kb = self.state.project.kb
        cle_var = kb.nvariables[var_name][self.state.ip]
        if cle_var:
            return SimVariable.from_cle_variable(self.state, cle_var)
        return None

    def __getitem__(self, var_name: str) -> SimVariable:
        return self.get_variable(var_name)


SimState.register_default('nvariables', SimVariables)

from .. import sim_options as o
from .inspect import BP_AFTER
from ..errors import SimValueError, SimUnsatError, SimSolverModeError, SimSolverOptionError
