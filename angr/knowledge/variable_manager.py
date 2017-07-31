
import logging
from collections import defaultdict
from itertools import count

from claripy.utils.orderedset import OrderedSet
from ..sim_variable import SimStackVariable, SimMemoryVariable, SimRegisterVariable, SimMemoryVariablePhi, \
    SimStackVariablePhi, SimRegisterVariablePhi

from .keyed_region import KeyedRegion
from .variable_access import VariableAccess


l = logging.getLogger("angr.knowledge.variable_manager")


class VariableType(object):
    REGISTER = 0
    MEMORY = 1


class LiveVariables(object):
    """
    A collection of live variables at a program point.
    """
    def __init__(self, register_region, stack_region):
        self.register_region = register_region
        self.stack_region = stack_region


class VariableManagerInternal(object):
    """
    Manage variables for a function. It is meant to be used internally by VariableManager.
    """
    def __init__(self, manager, func_addr=None):
        self.manager = manager

        self.func_addr = func_addr

        self._variables = OrderedSet()  # all variables that are added to any region
        self._stack_region = KeyedRegion()
        self._register_region = KeyedRegion()
        self._live_variables = { }  # a mapping between addresses of program points and live variable collections

        self._variable_accesses = defaultdict(set)
        self._insn_to_variable = defaultdict(set)
        self._block_to_variable = defaultdict(set)
        self._stmt_to_variable = defaultdict(set)
        self._variable_counters = {
            'register': count(),
            'stack': count(),
            'argument': count(),
            'phi': count(),
        }

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
        else:
            prefix = "m"

        return "i%s_%d" % (prefix, self._variable_counters[sort].next())

    def add_variable(self, sort, start, variable):
        if sort == 'stack':
            self._stack_region.add_variable(start, variable)
        elif sort == 'register':
            self._register_region.add_variable(start, variable)
        else:
            raise ValueError('Unsupported sort %s in add_variable().' % sort)

    def set_variable(self, sort, start, variable):
        if sort == 'stack':
            self._stack_region.set_variable(start, variable)
        elif sort == 'register':
            self._register_region.set_variable(start, variable)
        else:
            raise ValueError('Unsupported sort %s in add_variable().' % sort)

    def write_to(self, variable, offset, location, overwrite=False):
        self._record_variable_access('write', variable, offset, location, overwrite=overwrite)

    def read_from(self, variable, offset, location, overwrite=False):
        self._record_variable_access('read', variable, offset, location, overwrite=overwrite)

    def reference_at(self, variable, offset, location, overwrite=False):
        self._record_variable_access('reference', variable, offset, location, overwrite=overwrite)

    def _record_variable_access(self, sort, variable, offset, location, overwrite=False):
        self._variables.add(variable)
        if overwrite:
            self._variable_accesses[variable] = {VariableAccess(variable, sort, location)}
            self._insn_to_variable[location.ins_addr] = {(variable, offset)}
            self._block_to_variable[location.block_addr] = {(variable, offset)}
            self._stmt_to_variable[(location.block_addr, location.stmt_idx)] = {(variable, offset)}
        else:
            self._variable_accesses[variable].add(VariableAccess(variable, sort, location))
            self._insn_to_variable[location.ins_addr].add((variable, offset))
            self._block_to_variable[location.block_addr].add((variable, offset))
            self._stmt_to_variable[(location.block_addr, location.stmt_idx)].add((variable, offset))

    def make_phi_node(self, *variables):

        # unpack phi nodes
        existing_phi = [ ]
        unpacked = set()
        for var in variables:
            if isinstance(var, (SimRegisterVariablePhi, SimStackVariablePhi, SimMemoryVariablePhi)):
                unpacked |= var.variables
                existing_phi.append(var)
            else:
                unpacked.add(var)

        # optimization: if a phi node already contains all of the unpacked variables, just return that phi node
        for phi_node in existing_phi:
            if phi_node.variables.issuperset(unpacked):
                return phi_node

        variables = unpacked

        repre = next(iter(variables))
        repre_type = type(repre)
        if repre_type is SimRegisterVariable:
            cls = SimRegisterVariablePhi
            ident_sort = 'register'
        elif repre_type is SimMemoryVariable:
            cls = SimMemoryVariablePhi
            ident_sort = 'memory'
        elif repre_type is SimStackVariable:
            cls = SimStackVariablePhi
            ident_sort = 'stack'
        else:
            raise TypeError('make_phi_node(): Unsupported variable type "%s".' % type(repre))
        a = cls(ident=self.next_variable_ident(ident_sort),
                   region=self.func_addr,
                   variables=variables,
                   )
        return a

    def set_live_variables(self, addr, register_region, stack_region):
        lv = LiveVariables(register_region, stack_region)
        self._live_variables[addr] = lv

    def find_variables_by_insn(self, ins_addr, sort):
        if ins_addr not in self._insn_to_variable:
            return None

        if sort == VariableType.MEMORY or sort == 'memory':
            vars_and_offset = [(var, offset) for var, offset in self._insn_to_variable[ins_addr]
                        if isinstance(var, (SimStackVariable, SimMemoryVariable))]
        elif sort == VariableType.REGISTER or sort == 'register':
            vars_and_offset = [(var, offset) for var, offset in self._insn_to_variable[ins_addr]
                        if isinstance(var, SimRegisterVariable)]
        else:
            l.error('find_variable_by_insn(): Unsupported variable sort "%s".', sort)
            return [ ]

        return vars_and_offset

    def find_variable_by_stmt(self, block_addr, stmt_idx, sort):
        return next(iter(self.find_variables_by_stmt(block_addr, stmt_idx, sort)), None)

    def find_variables_by_stmt(self, block_addr, stmt_idx, sort):

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

    def get_variable_accesses(self, variable, same_name=False):

        if not same_name:
            if variable in self._variable_accesses:
                return self._variable_accesses[variable]

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

    def get_variables(self, sort=None, collapse_same_ident=False):
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

    def input_variables(self):
        """
        Get all variables that have never been written to.

        :return: A list of variables that are never written to.
        """

        def has_write_access(accesses):
            return any(acc for acc in accesses if acc.access_type == 'write')

        def has_read_access(accesses):
            return any(acc for acc in accesses if acc.access_type == 'read')

        input_variables = [ ]

        for variable, accesses in self._variable_accesses.iteritems():
            if not has_write_access(accesses) and has_read_access(accesses):
                input_variables.append(variable)

        return input_variables

    def assign_variable_names(self):
        """
        Assign default names to all variables.

        :return: None
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


class VariableManager(object):
    """
    Manage variables.
    """
    def __init__(self, kb=None):
        self.kb = kb
        self.global_manager = VariableManagerInternal(self)
        self.function_managers = { }

    def __getitem__(self, key):
        """
        Get the VariableManagerInternal object for a function or a region.

        :param str or int key: Key of the region. "global" for the global region, or a function address for the
                               function.
        :return:               The VariableManagerInternal object.
        :rtype:                VariableManagerInternal
        """

        if key == 'global':  # pylint:disable=no-else-return
            return self.global_manager

        else:
            # key refers to a function address
            return self.get_function_manager(key)

    def get_function_manager(self, func_addr):
        if not isinstance(func_addr, (int, long)):
            raise TypeError('Argument "func_addr" must be an int.')

        if func_addr not in self.function_managers:
            self.function_managers[func_addr] = VariableManagerInternal(self, func_addr=func_addr)

        return self.function_managers[func_addr]

    def initialize_variable_names(self):
        self.global_manager.assign_variable_names()
        for manager in self.function_managers.itervalues():
            manager.assign_variable_names()

    def get_variable_accesses(self, variable, same_name=False):
        """
        Get a list of all references to the given variable.

        :param SimVariable variable:         The variable.
        :param bool same_name:               Whether to include all variables with the same variable name, or just
                                             based on the variable identifier.
        :return:                All references to the variable.
        :rtype:                 list
        """

        if variable.region == 'global':
            return self.global_manager.get_variable_accesses(variable, same_name=same_name)

        elif variable.region in self.function_managers:
            return self.function_managers[variable.region].get_variable_accesses(variable, same_name=same_name)

        l.warning('get_variable_accesses(): Region %s is not found.', variable.region)
        return [ ]
