from typing import Set, List, Tuple, Dict, Union, Optional, TYPE_CHECKING
import logging
from collections import defaultdict
from itertools import count, chain

import networkx

from claripy.utils.orderedset import OrderedSet

from ...sim_variable import SimVariable, SimStackVariable, SimMemoryVariable, SimRegisterVariable
from ...keyed_region import KeyedRegion
from ..plugin import KnowledgeBasePlugin
from .variable_access import VariableAccess

if TYPE_CHECKING:
    from ...knowledge_base import KnowledgeBase


l = logging.getLogger(name=__name__)


class VariableType:
    REGISTER = 0
    MEMORY = 1


class LiveVariables:
    """
    A collection of live variables at a program point.
    """
    def __init__(self, register_region, stack_region):
        self.register_region = register_region
        self.stack_region = stack_region


def _defaultdict_set():
    return defaultdict(set)


class VariableManagerInternal:
    """
    Manage variables for a function. It is meant to be used internally by VariableManager.
    """
    def __init__(self, manager, func_addr=None):
        self.manager = manager

        self.func_addr = func_addr

        self._variables = OrderedSet()  # all variables that are added to any region
        self._global_region = KeyedRegion()
        self._stack_region = KeyedRegion()
        self._register_region = KeyedRegion()
        self._live_variables = { }  # a mapping between addresses of program points and live variable collections

        self._variable_accesses = defaultdict(set)
        self._insn_to_variable = defaultdict(set)
        self._block_to_variable = defaultdict(set)
        self._stmt_to_variable = defaultdict(set)
        self._atom_to_variable = defaultdict(_defaultdict_set)
        self._variable_counters = {
            'register': count(),
            'stack': count(),
            'argument': count(),
            'phi': count(),
            'global': count(),
        }

        self._unified_variables: Set[SimVariable] = set()
        self._variables_to_unified_variables: Dict[SimVariable, SimVariable] = { }

        self._phi_variables = { }
        self._phi_variables_by_block = defaultdict(set)

        self.types = { }

    #
    # Public methods
    #

    def next_variable_ident(self, sort):
        if sort not in self._variable_counters:
            raise ValueError('Unsupported variable sort %s' % sort)

        if sort == 'register':
            prefix = "r"
        elif sort == 'stack':
            prefix = "s"
        elif sort == 'argument':
            prefix = 'arg'
        elif sort == 'global':
            prefix = 'g'
        else:
            prefix = "m"

        ident = "i%s_%d" % (prefix, next(self._variable_counters[sort]))
        return ident

    def add_variable(self, sort, start, variable):
        if sort == 'stack':
            self._stack_region.add_variable(start, variable)
        elif sort == 'register':
            self._register_region.add_variable(start, variable)
        elif sort == 'global':
            self._global_region.add_variable(start, variable)
        else:
            raise ValueError('Unsupported sort %s in add_variable().' % sort)

    def set_variable(self, sort, start, variable: SimVariable):
        if sort == 'stack':
            region = self._stack_region
        elif sort == 'register':
            region = self._register_region
        elif sort == 'global':
            region = self._global_region
        else:
            raise ValueError('Unsupported sort %s in set_variable().' % sort)
        existing = [x for x in region.get_variables_by_offset(start) if x.ident == variable.ident]
        if len(existing) == 1:
            var = existing[0]
            if var.name is not None and not variable.renamed:
                variable.name = var.name
                variable.renamed = var.renamed
        else:
            # implicitly overwrite or add I guess
            pass
        region.set_variable(start, variable)

    def write_to(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access('write', variable, offset, location, overwrite=overwrite, atom=atom)

    def read_from(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access('read', variable, offset, location, overwrite=overwrite, atom=atom)

    def reference_at(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access('reference', variable, offset, location, overwrite=overwrite, atom=atom)

    def _record_variable_access(self, sort, variable, offset, location, overwrite=False, atom=None):
        self._variables.add(variable)
        var_and_offset = variable, offset
        if overwrite:
            self._variable_accesses[variable] = {VariableAccess(variable, sort, location)}
            self._insn_to_variable[location.ins_addr] = {var_and_offset}
            self._block_to_variable[location.block_addr] = {var_and_offset}
            self._stmt_to_variable[(location.block_addr, location.stmt_idx)] = {var_and_offset}
            if atom is not None:
                self._atom_to_variable[(location.block_addr, location.stmt_idx)][atom] = var_and_offset
        else:
            self._variable_accesses[variable].add(VariableAccess(variable, sort, location))
            self._insn_to_variable[location.ins_addr].add(var_and_offset)
            self._block_to_variable[location.block_addr].add(var_and_offset)
            self._stmt_to_variable[(location.block_addr, location.stmt_idx)].add(var_and_offset)
            if atom is not None:
                self._atom_to_variable[(location.block_addr, location.stmt_idx)][atom].add(var_and_offset)

    def make_phi_node(self, block_addr, *variables):
        """
        Create a phi variable for variables at block `block_addr`.

        :param int block_addr:  The address of the current block.
        :param variables:       Variables that the phi variable represents.
        :return:                The created phi variable.
        """

        existing_phis = set()
        non_phis = set()
        for var in variables:
            if self.is_phi_variable(var):
                existing_phis.add(var)
            else:
                non_phis.add(var)
        if len(existing_phis) == 1:
            existing_phi = next(iter(existing_phis))
            if non_phis.issubset(self.get_phi_subvariables(existing_phi)):
                return existing_phi
            else:
                # Update phi variables
                self._phi_variables[existing_phi] |= non_phis
                return existing_phi

        repre = next(iter(variables))
        repre_type = type(repre)
        if repre_type is SimRegisterVariable:
            ident_sort = 'register'
            a = SimRegisterVariable(repre.reg, repre.size, ident=self.next_variable_ident(ident_sort))
        elif repre_type is SimMemoryVariable:
            ident_sort = 'global'
            a = SimMemoryVariable(repre.addr, repre.size, ident=self.next_variable_ident(ident_sort))
        elif repre_type is SimStackVariable:
            ident_sort = 'stack'
            a = SimStackVariable(repre.offset, repre.size, ident=self.next_variable_ident(ident_sort))
        else:
            raise TypeError('make_phi_node(): Unsupported variable type "%s".' % type(repre))

        # Keep a record of all phi variables
        self._phi_variables[a] = set(variables)
        self._phi_variables_by_block[block_addr].add(a)

        return a

    def set_live_variables(self, addr, register_region, stack_region):
        lv = LiveVariables(register_region, stack_region)
        self._live_variables[addr] = lv

    def find_variables_by_insn(self, ins_addr, sort):
        if ins_addr not in self._insn_to_variable:
            return None

        if sort in (VariableType.MEMORY, 'memory'):
            vars_and_offset = [(var, offset) for var, offset in self._insn_to_variable[ins_addr]
                        if isinstance(var, (SimStackVariable, SimMemoryVariable))]
        elif sort in (VariableType.REGISTER, 'register'):
            vars_and_offset = [(var, offset) for var, offset in self._insn_to_variable[ins_addr]
                        if isinstance(var, SimRegisterVariable)]
        else:
            l.error('find_variable_by_insn(): Unsupported variable sort "%s".', sort)
            return [ ]

        return vars_and_offset

    def find_variable_by_stmt(self, block_addr, stmt_idx, sort):
        return next(iter(self.find_variables_by_stmt(block_addr, stmt_idx, sort)), None)

    def find_variables_by_stmt(self, block_addr: int, stmt_idx: int, sort: str) -> List[Tuple[SimVariable,int]]:

        key = block_addr, stmt_idx

        if key not in self._stmt_to_variable:
            return [ ]

        variables = self._stmt_to_variable[key]
        if not variables:
            return [ ]

        if sort == 'memory':
            var_and_offsets = list((var, offset) for var, offset in self._stmt_to_variable[key]
                                   if isinstance(var, (SimStackVariable, SimMemoryVariable)))
        elif sort == 'register':
            var_and_offsets = list((var, offset) for var, offset in self._stmt_to_variable[key]
                                   if isinstance(var, SimRegisterVariable))
        else:
            l.error('find_variables_by_stmt(): Unsupported variable sort "%s".', sort)
            return [ ]

        return var_and_offsets

    def find_variable_by_atom(self, block_addr, stmt_idx, atom):
        return next(iter(self.find_variables_by_atom(block_addr, stmt_idx, atom)), None)

    def find_variables_by_atom(self, block_addr, stmt_idx, atom) -> Set[Tuple[SimVariable, int]]:

        key = block_addr, stmt_idx

        if key not in self._atom_to_variable:
            return set()

        if atom not in self._atom_to_variable[key]:
            return set()

        return self._atom_to_variable[key][atom]

    def get_variable_accesses(self, variable: SimVariable, same_name: bool=False) -> List[VariableAccess]:

        if not same_name:
            if variable in self._variable_accesses:
                return list(self._variable_accesses[variable])

            return [ ]

        # find all variables with the same variable name

        vars_list = [ ]

        for var in self._variable_accesses.keys():
            if variable.name == var.name:
                vars_list.append(var)

        accesses = [ ]
        for var in vars_list:
            accesses.extend(self.get_variable_accesses(var))

        return accesses

    def get_variables(self, sort=None, collapse_same_ident=False) -> List[Union[SimStackVariable,SimRegisterVariable]]:
        """
        Get a list of variables.

        :param str or None sort:    Sort of the variable to get.
        :param collapse_same_ident: Whether variables of the same identifier should be collapsed or not.
        :return:                    A list of variables.
        :rtype:                     list
        """

        variables = [ ]

        if collapse_same_ident:
            raise NotImplementedError()

        for var in self._variables:
            if sort == 'stack' and not isinstance(var, SimStackVariable):
                continue
            if sort == 'reg' and not isinstance(var, SimRegisterVariable):
                continue
            variables.append(var)

        return variables

    def get_global_variables(self, addr):
        """
        Get global variable by the address of the variable.

        :param int addr:    Address of the variable.
        :return:            A set of variables or an empty set if no variable exists.
        """
        return self._global_region.get_variables_by_offset(addr)

    def is_phi_variable(self, var):
        """
        Test if `var` is a phi variable.

        :param SimVariable var: The variable instance.
        :return:                True if `var` is a phi variable, False otherwise.
        :rtype:                 bool
        """

        return var in self._phi_variables

    def get_phi_subvariables(self, var):
        """
        Get sub-variables that phi variable `var` represents.

        :param SimVariable var: The variable instance.
        :return:                A set of sub-variables, or an empty set if `var` is not a phi variable.
        :rtype:                 set
        """

        if not self.is_phi_variable(var):
            return set()
        return self._phi_variables[var]

    def get_phi_variables(self, block_addr):
        """
        Get a dict of phi variables and their corresponding variables.

        :param int block_addr:  Address of the block.
        :return:                A dict of phi variables of an empty dict if there are no phi variables at the block.
        :rtype:                 dict
        """

        if block_addr not in self._phi_variables_by_block:
            return dict()
        variables = { }
        for phi in self._phi_variables_by_block[block_addr]:
            variables[phi] = self._phi_variables[phi]
        return variables

    def input_variables(self, exclude_specials=True):
        """
        Get all variables that have never been written to.

        :return: A list of variables that are never written to.
        """

        def has_write_access(accesses):
            return any(acc for acc in accesses if acc.access_type == 'write')

        def has_read_access(accesses):
            return any(acc for acc in accesses if acc.access_type == 'read')

        input_variables = [ ]

        for variable, accesses in self._variable_accesses.items():
            if variable in self._phi_variables:
                # a phi variable is definitely not an input variable
                continue
            if not has_write_access(accesses) and has_read_access(accesses):
                if not exclude_specials or not variable.category:
                    input_variables.append(variable)

        return input_variables

    def assign_variable_names(self, labels=None):
        """
        Assign default names to all SSA variables.

        :param labels:  Known labels in the binary.
        :return:        None
        """

        for var in self._variables:
            if isinstance(var, SimStackVariable):
                if var.name is not None:
                    continue
                if var.ident.startswith('iarg'):
                    var.name = 'arg_%x' % var.offset
                else:
                    var.name = 's_%x' % (-var.offset)
                    # var.name = var.ident
            elif isinstance(var, SimRegisterVariable):
                if var.name is not None:
                    continue
                var.name = var.ident
            elif isinstance(var, SimMemoryVariable):
                if var.name is not None:
                    continue
                if labels is not None and var.addr in labels:
                    var.name = labels[var.addr]
                    if "@@" in var.name:
                        var.name = var.name[:var.name.index("@@")]
                elif var.ident is not None:
                    var.name = var.ident
                else:
                    var.name = "g_%x" % var.addr

    def assign_unified_variable_names(self, labels=None, reset:bool=False):
        """
        Assign default names to all unified variables.

        :param labels:  Known labels in the binary.
        :param reset:   Reset all variable names or not.
        :return:        None
        """

        if not self._unified_variables:
            return

        sorted_stack_variables = [ ]
        sorted_reg_variables = [ ]
        arg_vars = [ ]

        for var in self._unified_variables:
            if isinstance(var, SimStackVariable):
                if var.ident and var.ident.startswith('iarg_'):
                    arg_vars.append(var)
                else:
                    sorted_stack_variables.append(var)

            elif isinstance(var, SimRegisterVariable):
                if var.ident and var.ident.startswith('arg_'):
                    arg_vars.append(var)
                else:
                    sorted_reg_variables.append(var)

            elif isinstance(var, SimMemoryVariable):
                if not reset and var.name is not None:
                    continue
                # assign names directly
                if labels is not None and var.addr in labels:
                    var.name = labels[var.addr]
                    if "@@" in var.name:
                        var.name = var.name[:var.name.index("@@")]
                elif var.ident:
                    var.name = var.ident
                else:
                    var.name = f"g_{var.addr:x}"

        # rename variables in a fixed order
        var_ctr = count(0)

        sorted_stack_variables = sorted(sorted_stack_variables, key=lambda v: v.offset)
        sorted_reg_variables = sorted(sorted_reg_variables, key=lambda v: v.reg)

        for var in chain(sorted_stack_variables, sorted_reg_variables):
            idx = next(var_ctr)
            if var.name is not None and not reset:
                continue
            if isinstance(var, SimStackVariable):
                var.name = f'v{idx}'
            elif isinstance(var, SimRegisterVariable):
                var.name = f"v{idx}"
            # clear the hash cache
            var._hash = None

        # rename arguments but keeping the original order
        arg_ctr = count(0)
        arg_vars = sorted(arg_vars, key=lambda v: int(v.ident[v.ident.index("_")+1:]) if v.ident else 0)
        for var in arg_vars:
            idx = next(arg_ctr)
            if var.name is not None and not reset:
                continue
            var.name = f"a{idx}"
            var._hash = None

    def get_variable_type(self, var):
        return self.types.get(var, None)

    def remove_types(self):
        self.types.clear()

    def unify_variables(self) -> None:
        """
        Map SSA variables to a unified variable. Fill in self._unified_variables.
        """

        stack_vars: Dict[int,List[SimStackVariable]] = defaultdict(list)
        reg_vars: Set[SimRegisterVariable] = set()

        # unify stack variables based on their locations
        for v in self.get_variables():
            if isinstance(v, SimStackVariable):
                stack_vars[v.offset].append(v)
            elif isinstance(v, SimRegisterVariable):
                reg_vars.add(v)

        for _, vs in stack_vars.items():
            unified = vs[0].copy()
            for v in vs:
                self.set_unified_variable(v, unified)

        # unify register variables based on phi nodes
        graph = networkx.Graph()
        for v, subvs in self._phi_variables.items():
            if not isinstance(v, SimRegisterVariable):
                continue
            if not self.get_variable_accesses(v):
                # this phi node has never been used - discard it
                continue
            for subv in subvs:
                graph.add_edge(v, subv)

        for nodes in networkx.connected_components(graph):
            if len(nodes) <= 1:
                continue
            nodes = list(nodes)
            unified = nodes[0].copy()
            for v in nodes:
                self.set_unified_variable(v, unified)
            for v in nodes:
                reg_vars.discard(v)

        for v in reg_vars:
            self.set_unified_variable(v, v)

    def set_unified_variable(self, variable: SimVariable, unified: SimVariable) -> None:
        """
        Set the unified variable for a given SSA variable.

        :param variable:    The SSA variable.
        :param unified:     The unified variable.
        :return:            None
        """
        old_unified = self._variables_to_unified_variables.get(variable, None)
        if old_unified is not None and old_unified is not unified:
            self._unified_variables.discard(old_unified)
            if old_unified.name is not None and not unified.renamed:
                unified.name = old_unified.name
                unified.renamed = old_unified.renamed

        self._unified_variables.add(unified)
        self._variables_to_unified_variables[variable] = unified

    def unified_variable(self, variable: SimVariable) -> Optional[SimVariable]:
        """
        Return the unified variable for a given SSA variable,

        :param variable:    The SSA variable.
        :return:            The unified variable, or None if there is no such SSA variable.
        """

        return self._variables_to_unified_variables.get(variable, None)


class VariableManager(KnowledgeBasePlugin):
    """
    Manage variables.
    """
    def __init__(self, kb):
        super().__init__()
        self._kb: 'KnowledgeBase' = kb
        self.global_manager = VariableManagerInternal(self)
        self.function_managers: Dict[int,VariableManagerInternal] = { }

    def __getitem__(self, key) -> VariableManagerInternal:
        """
        Get the VariableManagerInternal object for a function or a region.

        :param str or int key: Key of the region. "global" for the global region, or a function address for the
                               function.
        :return:               The VariableManagerInternal object.
        """

        if key == 'global':  # pylint:disable=no-else-return
            return self.global_manager

        else:
            # key refers to a function address
            return self.get_function_manager(key)

    def __delitem__(self, key) -> None:
        """
        Remove the existing VariableManagerInternal object for a function or a region.

        :param Union[str,int] key:  Key of the region. "global" for the global region, or a function address for the
                                    function.
        :return:                    None
        """

        if key == 'global':
            self.global_manager = VariableManagerInternal(self)
        else:
            del self.function_managers[key]

    def has_function_manager(self, key: int) -> bool:
        return key in self.function_managers

    def get_function_manager(self, func_addr) -> VariableManagerInternal:
        if isinstance(func_addr, str):
            func_addr = self._kb.labels.lookup(func_addr)
        elif not isinstance(func_addr, int):
            raise TypeError('Argument "func_addr" must be an int.')

        if func_addr not in self.function_managers:
            self.function_managers[func_addr] = VariableManagerInternal(self, func_addr=func_addr)

        return self.function_managers[func_addr]

    def initialize_variable_names(self) -> None:
        self.global_manager.assign_variable_names()
        for manager in self.function_managers.values():
            manager.assign_variable_names()

    def get_variable_accesses(self, variable: SimVariable, same_name: bool=False) -> List[VariableAccess]:
        """
        Get a list of all references to the given variable.

        :param variable:        The variable.
        :param same_name:       Whether to include all variables with the same variable name, or just based on the
                                variable identifier.
        :return:                All references to the variable.
        """

        if variable.region == 'global':
            return self.global_manager.get_variable_accesses(variable, same_name=same_name)

        elif variable.region in self.function_managers:
            return self.function_managers[variable.region].get_variable_accesses(variable, same_name=same_name)

        l.warning('get_variable_accesses(): Region %s is not found.', variable.region)
        return [ ]

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default('variables', VariableManager)
