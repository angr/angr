from typing import List, TYPE_CHECKING
import logging

from cle.backends.elf.compilation_unit import CompilationUnit
from cle.backends.elf.variable import Variable

from ..plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from ...knowledge_base import KnowledgeBase

l = logging.getLogger(name=__name__)


class NVariableContainer:
    def __init__(self):
        self.less_visible_vars = []

    def _insertvar(self, var):
        for i, v in enumerate(self.less_visible_vars):
            if var.contains(v):
                self.less_visible_vars[i] = var
                var.less_visible_vars.append(v)
                return
            if var.overlaps(v):
                l.warning("Not supported! Trying to add variable %s with scopes %d-%d and %d-%d. Ignoring the former.",
                          v.cle_variable.name, v.low_ip_addr, v.high_ip_addr, var.low_ip_addr, var.high_ip_addr)
                return
            if v.contains(var):
                v._insertvar(var)
                return
        self.less_visible_vars.append(var)

    def from_ip_addr(self, ip_addr):
        for var in self.less_visible_vars:
            if var.low_ip_addr <= ip_addr and ip_addr < var.high_ip_addr:
                return var.from_ip_addr(ip_addr)
        return None


class NVariable(NVariableContainer):
    def __init__(self, low_ip_addr, high_ip_addr, cle_variable: Variable):
        """
        To create a new variable, please use NVariableManager.addvar() instead
        """
        super().__init__()
        self.low_ip_addr = low_ip_addr
        self.high_ip_addr = high_ip_addr
        self.cle_variable = cle_variable

    # overwrites the method of NVariableContainer
    def from_ip_addr(self, ip_addr):
        if ip_addr < self.low_ip_addr or self.high_ip_addr < ip_addr:
            # not within range
            return None
        for var in self.less_visible_vars:
            if var.low_ip_addr <= ip_addr and ip_addr < var.high_ip_addr:
                return var.from_ip_addr(ip_addr)
        return self.cle_variable

    def contains(self, var):
        if self.low_ip_addr <= var.low_ip_addr and var.high_ip_addr <= self.high_ip_addr:
            return True
        else:
            return False

    def overlaps(self, var):
        l1 = self.low_ip_addr
        l2 = var.low_ip_addr
        h1 = self.high_ip_addr
        h2 = var.high_ip_addr
        if l1 == l2 and h1 == h2:
            return True
        if l2 < l1 and l1 < h2 and h2 < h1:
            return True
        if l1 < l2 and l2 < h1 and h1 < h2:
            return True
        return False


class NVariableManager(KnowledgeBasePlugin):

    def __init__(self, kb):
        super().__init__()
        self._kb: 'KnowledgeBase' = kb
        self._most_visible_variables = {}

    def from_name_and_ip_addr(self, var_name, ip_addr):
        """
        Get a variable from its string in the scope of ip_addr.
        """
        var = self._most_visible_variables[var_name]
        return var.from_ip_addr(ip_addr)

    def most_visible(self, var_name):
        """
        Get a most visible variable (a global variable if exists)
        """
        return self._most_visible_variables[var_name]

    def addvar(self, cle_var: Variable, low_ip_addr, high_ip_addr):
        name = cle_var.name
        # low_ip_addr = cle_var.low_addr
        # high_ip_addr = cle_var.high_addr
        nvar = NVariable(low_ip_addr, high_ip_addr, cle_var)
        if name not in self._most_visible_variables:
            self._most_visible_variables[name] = NVariableContainer()
        container = self._most_visible_variables[name]
        container._insertvar(nvar)

    # Methods similar to the once in VariableManager
    def add_variable_list(self, vlist: List[Variable], low_ip_addr, high_ip_addr):
        for v in vlist:
            self.addvar(v, low_ip_addr, high_ip_addr)

    def load_from_dwarf(self, cu_list: List[CompilationUnit] = None):
        cu_list = cu_list or self._kb._project.loader.main_object.compilation_units
        if cu_list is None:
            l.warning("no CompilationUnit found")
            return
        for cu in cu_list:
            self.add_variable_list(cu.global_variables, 0x0, float('inf'))
            for low_pc, subp in cu.functions.items():
                high_pc = subp.high_pc
                self.add_variable_list(subp.local_variables, low_pc, high_pc)


KnowledgeBasePlugin.register_default('nvariables', NVariableManager)
