from typing import List, TYPE_CHECKING
import logging

import claripy

from cle.backends.elf.compilation_unit import CompilationUnit
from cle.backends.elf.variable import Variable
from cle.backends.elf.elf import ELF

from ..plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from ...knowledge_base import KnowledgeBase

l = logging.getLogger(name=__name__)


class NVariableContainer:
    """
    Variable tree for variables with same name to lock up which variable is visible at a given program counter address.
    """
    def __init__(self):
        """
        It is recommended to use NVariableManager.add_variable() instead
        """
        self.less_visible_vars = []

    def _insertvar(self, var: 'NVariable'):
        for i, v in enumerate(self.less_visible_vars):
            if var.test_unsupported_overlap(v):
                l.warning("Unsupported variable with overlapping scopes. We have \"%s\" with %d-%d and ignore %d-%d.",
                          v.cle_variable.name, v.low_pc, v.high_pc, var.low_pc, var.high_pc)
                return
            if var.contains(v):
                self.less_visible_vars[i] = var
                var.less_visible_vars.append(v)
                return
            if v.contains(var):
                v._insertvar(var)
                return
        self.less_visible_vars.append(var)

    def __setitem__(self, index, value):
        assert isinstance(index, slice) and isinstance(value, Variable)
        low_pc = index.start
        high_pc = index.stop
        nvar = NVariable(low_pc, high_pc, value)
        return self._insertvar(nvar)

    def from_pc(self, pc) -> Variable:
        """
        Returns the visible variable (if any) for a given pc address.
        """
        for var in self.less_visible_vars:
            if claripy.is_true(var.low_pc <= pc) and claripy.is_true(pc < var.high_pc):
                return var.from_pc(pc)
        return None

    def __getitem__(self, index):
        return self.from_pc(index)


class NVariable(NVariableContainer):
    """
    :ivar low_pc:           Start of the visibility scope of the variable as program counter address (rebased)
    :ivar high_pc:          End of the visibility scope of the variable as program counter address (rebased)
    :ivar cle_variable:     Original variable from cle
    """
    def __init__(self, low_pc: int, high_pc: int, cle_variable: Variable):
        """
        It is recommended to use NVariableManager.add_variable() instead
        """
        super().__init__()
        self.low_pc = low_pc
        self.high_pc = high_pc
        self.cle_variable = cle_variable

    # overwrites the method of NVariableContainer
    def from_pc(self, pc) -> Variable:
        if claripy.is_true(pc < self.low_pc) or claripy.is_true(self.high_pc < pc):
            # not within range
            return None
        for var in self.less_visible_vars:
            if claripy.is_true(var.low_pc <= pc) and claripy.is_true(pc < var.high_pc):
                return var.from_pc(pc)
        return self.cle_variable

    def contains(self, nvar: 'NVariable') -> bool:
        if self.low_pc <= nvar.low_pc and nvar.high_pc <= self.high_pc:
            return True
        else:
            return False

    def test_unsupported_overlap(self, nvar: 'NVariable') -> bool:
        """
        Test for an unsupported overlapping

        :param nvar:    Second NVariable to compare with
        :return:        True if there is an unsupported overlapping
        """
        l1 = self.low_pc
        l2 = nvar.low_pc
        h1 = self.high_pc
        h2 = nvar.high_pc
        if l1 == l2 and h1 == h2:
            return True
        if l2 < l1 and l1 < h2 and h2 < h1:
            return True
        if l1 < l2 and l2 < h1 and h1 < h2:
            return True
        return False


class NVariableManager(KnowledgeBasePlugin):
    """
    Structure to manage and access variables with different visibility scopes.
    """

    def __init__(self, kb: 'KnowledgeBase'):
        super().__init__()
        self._kb: 'KnowledgeBase' = kb
        self._nvar_containers = {}

    def from_name_and_pc(self, var_name: str, pc_addr: int) -> Variable:
        """
        Get a variable from its string in the scope of pc.
        """
        nvar = self._nvar_containers[var_name]
        return nvar.from_pc(pc_addr)

    def from_name(self, var_name: str) -> NVariableContainer:
        """
        Get the variable container for all variables named var_name

        :param var_name:    name for a variable
        """
        if var_name not in self._nvar_containers:
            self._nvar_containers[var_name] = NVariableContainer()
        return self._nvar_containers[var_name]

    def __getitem__(self, var_name):
        assert type(var_name) == str
        return self.from_name(var_name)

    def add_variable(self, cle_var: Variable, low_pc: int, high_pc: int):
        """
        Add/load a variable

        :param cle_variable:    The variable to add
        :param low_pc:          Start of the visibility scope of the variable as program counter address (rebased)
        :param high_pc:         End of the visibility scope of the variable as program counter address (rebased)
        """
        name = cle_var.name
        if name not in self._nvar_containers:
            self._nvar_containers[name] = NVariableContainer()
        container = self._nvar_containers[name]
        container[low_pc:high_pc] = cle_var

    def __setitem__(self, index, cle_var):
        assert isinstance(index, slice) and isinstance(cle_var, Variable)
        return self.add_variable(cle_var, index.start, index.stop)

    # Methods similar to the once in VariableManager
    def add_variable_list(self, vlist: List[Variable], low_pc: int, high_pc: int):
        """
        Add all variables in a list with the same visibility range

        :param vlist:       A list of cle varibles to add
        :param low_pc:      Start of the visibility scope as program counter address (rebased)
        :param high_pc:     End of the visibility scope as program counter address (rebased)
        """
        for v in vlist:
            self.add_variable(v, low_pc, high_pc)

    def load_from_dwarf(self, elf_object: ELF = None, cu: CompilationUnit = None):
        """
        Automatically load all variables (global/local) from the DWARF debugging info

        :param elf_object:  Optional, when only one elf object should be considered (e.g. p.loader.main_object)
        :param cu:          Optional, when only one compilation unit should be considered
        """
        if elf_object:
            objs = [elf_object]
        else:
            objs = self._kb._project.loader.all_elf_objects
        for obj in objs:
            if cu:
                if obj not in obj.compilation_units:
                    break
                cu_list = [cu]
            else:
                cu_list = obj.compilation_units

            for cu in cu_list:
                self.add_variable_list(cu.global_variables, obj.min_addr, obj.max_addr)
                for subp in cu.functions.values():
                    for cle_var in subp.local_variables:
                        low_pc = cle_var.lexical_block.low_pc + obj.mapped_base
                        high_pc = cle_var.lexical_block.high_pc + obj.mapped_base
                        self.add_variable(cle_var, low_pc, high_pc)


KnowledgeBasePlugin.register_default('nvariables', NVariableManager)
