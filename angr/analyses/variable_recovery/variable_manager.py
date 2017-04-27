
import logging
from itertools import count
from collections import defaultdict

from simuvex.s_variable import SimStackVariable

from claripy.utils.orderedset import OrderedSet
from .keyed_region import KeyedRegion
from .variable_access import VariableAccess

l = logging.getLogger('variable_analysis.variable_manager')


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

        self._variable_accesses = defaultdict(list)
        self._insn_to_variable = defaultdict(list)
        self._variable_counters = {
            'register': count(),
            'stack': count(),
            'argument': count(),
        }

    #
    # Public methods
    #

    def next_variable_ident(self, sort):
        if sort not in self._variable_counters:
            raise ValueError('Unsupported variable sort %s' % sort)

        if sort == 'register':
            prefix = "regvar"
        elif sort == 'stack':
            prefix = "var"
        elif sort == 'argument':
            prefix = 'arg'
        else:
            prefix = "mem"

        return "i%s_%d" % (prefix, self._variable_counters[sort].next())

    def add_variable(self, sort, start, variable):
        if sort == 'stack':
            self._stack_region.add_variable(start, variable)
        elif sort == 'reg':
            self._register_region.add_variable(start, variable)
        else:
            raise ValueError('Unsupported sort %s in add_variable().' % sort)

    def write_to(self, variable, offset, location):
        self._variables.add(variable)
        self._variable_accesses[variable].append(VariableAccess(variable, 'write', location))
        self._insn_to_variable[location.ins_addr].append((variable, offset))

    def read_from(self, variable, offset, location):
        self._variables.add(variable)
        self._variable_accesses[variable].append(VariableAccess(variable, 'read', location))
        self._insn_to_variable[location.ins_addr].append((variable, offset))

    def reference_at(self, variable, offset, location):
        self._variables.add(variable)
        self._variable_accesses[variable].append(VariableAccess(variable, 'reference', location))
        self._insn_to_variable[location.ins_addr].append((variable, offset))

    def find_variable_by_insn(self, ins_addr):
        if ins_addr not in self._insn_to_variable:
            return None

        return self._insn_to_variable[ins_addr][-1]

    def get_variable_accesses(self, variable, same_name=False):

        if not same_name:
            if variable in self._variable_accesses:
                return self._variable_accesses[variable]

            else:
                return [ ]

        else:
            # find all variables with the same variable name

            vars_list = [ ]

            for var in self._variable_accesses.keys():
                if variable.name == var.name:
                    vars_list.append(var)

            accesses = [ ]
            for var in vars_list:
                accesses.extend(self.get_variable_accesses(var))

            return accesses

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
                    var.name = 'var_%x' % (-var.offset)
                    # var.name = var.ident


class VariableManager(object):
    """
    Manage variables.
    """
    def __init__(self):
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

        if key == 'global':
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

        :param simuvex.SimVariable variable: The variable.
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
