from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from cle.backends.elf.variable import Variable
from cle.backends.elf.variable_type import VariableType, PointerType, ArrayType, StructType, TypedefType

from angr.sim_state import SimState
from angr.sim_type import ALL_TYPES, SimTypeNum

from .plugin import SimStatePlugin

l = logging.getLogger(name=__name__)

if TYPE_CHECKING:
    from angr.state_plugins.view import SimMemView
    from angr.sim_type import SimType


class SimDebugVariable:
    """
    A SimDebugVariable will get dynamically created when queriyng for variable in a state with the
    SimDebugVariablePlugin. It features a link to the state, an address and a type.
    """

    def __init__(self, state: SimState, addr, var_type: VariableType):
        self.state = state
        self.addr = addr
        self.type = var_type

    @staticmethod
    def from_cle_variable(state: SimState, cle_variable: Variable, dwarf_cfa) -> SimDebugVariable:
        addr = cle_variable.rebased_addr_from_cfa(dwarf_cfa)
        var_type = cle_variable.type
        return SimDebugVariable(state, addr, var_type)

    @property
    def mem_untyped(self) -> SimMemView:
        if self.addr is None:
            raise Exception("Cannot view a variable without an address")
        return self.state.mem[self.addr]

    @property
    def mem(self) -> SimMemView:
        if isinstance(self.type, TypedefType):
            unpacked = SimDebugVariable(self.state, self.addr, self.type.type)
            return unpacked.mem
        if self.type is None or self.type.byte_size is None:
            return self.mem_untyped

        arch = self.state.arch
        size = self.type.byte_size * arch.byte_width
        name = self.type.name
        if name in ALL_TYPES:
            sim_type = ALL_TYPES[name].with_arch(arch)
            assert size == sim_type.size
        else:
            # FIXME A lot more types are supported by angr that are not in ALL_TYPES (structs, arrays, pointers)
            # Use a fallback type
            sim_type = SimTypeNum(size, signed=False, label=name)
        return self.mem_untyped.with_type(sim_type)

    # methods and properties equivalent to SimMemView

    @property
    def string(self) -> SimMemView:
        first_char = self.deref
        # first char should have some char type (could be checked here)
        return first_char.mem_untyped.string

    def with_type(self, sim_type: SimType) -> SimMemView:
        return self.mem_untyped.with_type(sim_type)

    @property
    def resolvable(self):
        return self.mem.resolvable

    @property
    def resolved(self):
        return self.mem.resolved

    @property
    def concrete(self):
        return self.mem.concrete

    def store(self, value):
        return self.mem.store(value)

    def __getitem__(self, i):
        if isinstance(i, int):
            return self.array(i)
        if isinstance(i, str):
            return self.member(i)
        raise KeyError

    @property
    def deref(self) -> SimDebugVariable:
        # dereferincing is equivalent to getting the first array element
        return self.array(0)

    def array(self, i) -> SimDebugVariable:
        if isinstance(self.type, TypedefType):
            unpacked = SimDebugVariable(self.state, self.addr, self.type.type)
            return unpacked.array(i)
        if isinstance(self.type, ArrayType):
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
            raise Exception(f"{self.type} object cannot be dereferenced")

        if i == 0:
            new_addr = addr
        elif addr is None or el_type is None or el_type.byte_size is None:
            new_addr = None
        else:
            new_addr = addr + i * el_type.byte_size
        return SimDebugVariable(self.state, new_addr, el_type)

    def member(self, member_name: str) -> SimDebugVariable:
        if isinstance(self.type, TypedefType):
            unpacked = SimDebugVariable(self.state, self.addr, self.type.type)
            return unpacked.member(member_name)
        if isinstance(self.type, StructType):
            member = self.type[member_name]
            addr = None if self.addr is None else self.addr + member.addr_offset
            return SimDebugVariable(self.state, addr, member.type)

        raise Exception(f"{self.type} object has no members")


class SimDebugVariablePlugin(SimStatePlugin):
    """
    This is the plugin you'll use to interact with (global/local) program variables.
    These variables have a name and a visibility scope which depends on the pc address of the state.
    With this plugin, you can access/modify the value of such variable or find its memory address.
    For creating program variables, or for importing them from cle, see the knowledge plugin debug_variables.
    Run ``p.kb.dvars.load_from_dwarf()`` before using this plugin.

    Example:
        >>> p = angr.Project("various_variables", load_debug_info=True)
        >>> p.kb.dvars.load_from_dwarf()
        >>> state =  # navigate to the state you want
        >>> state.dvars.get_variable("pointer2").deref.mem
        <int (32 bits) <BV32 0x1> at 0x404020>
    """

    def get_variable(self, var_name: str) -> SimDebugVariable:
        """
        Returns the visible variable (if any) with name ``var_name`` based on the current ``state.ip``.
        """
        kb = self.state.project.kb
        cle_var = kb.dvars[var_name][self.state.ip]
        if cle_var:
            return SimDebugVariable.from_cle_variable(self.state, cle_var, self.dwarf_cfa)
        return None

    def __getitem__(self, var_name: str) -> SimDebugVariable:
        return self.get_variable(var_name)

    # DWARF cfa
    @property
    def dwarf_cfa(self):
        """
        Returns the current cfa computation. Set this property to the correct value if needed.
        """
        try:
            return self._dwarf_cfa
        except AttributeError:
            return self.dwarf_cfa_approx

    @dwarf_cfa.setter
    def dwarf_cfa(self, new_val):
        self._dwarf_cfa = new_val

    @property
    def dwarf_cfa_approx(self):
        # FIXME This is only an approximation!
        if self.state.arch.name == "AMD64":
            return self.state.regs.rbp + 16
        if self.state.arch.name == "X86":
            return self.state.regs.ebp + 8
        return 0


SimState.register_default("dvars", SimDebugVariablePlugin)
