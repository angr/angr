from typing import Set, List, Tuple, Dict, Union, Optional, TYPE_CHECKING
import logging
from collections import defaultdict
from itertools import count, chain

import networkx

from cle.backends.elf.compilation_unit import CompilationUnit
from cle.backends.elf.variable import Variable
from claripy.utils.orderedset import OrderedSet

from ...protos import variables_pb2
from ...serializable import Serializable
from ...sim_variable import SimVariable, SimStackVariable, SimMemoryVariable, SimRegisterVariable
from ...sim_type import TypeRef, SimType, SimStruct, SimTypePointer, SimTypeBottom, SimTypeChar, SimTypeShort, \
    SimTypeInt, SimTypeLong
from ...keyed_region import KeyedRegion
from ..plugin import KnowledgeBasePlugin
from ..types import TypesStore
from .variable_access import VariableAccess, VariableAccessSort

if TYPE_CHECKING:
    from ...knowledge_base import KnowledgeBase

l = logging.getLogger(name=__name__)


class VariableType:
    """
    Describes variable types.
    """
    REGISTER = 0
    MEMORY = 1


class LiveVariables:
    """
    A collection of live variables at a program point.
    """

    __slots__ = ('register_region', 'stack_region', )

    def __init__(self, register_region, stack_region):
        self.register_region = register_region
        self.stack_region = stack_region


def _defaultdict_set():
    return defaultdict(set)


class VariableManagerInternal(Serializable):
    """
    Manage variables for a function. It is meant to be used internally by VariableManager.
    """
    def __init__(self, manager, func_addr=None):
        self.manager: 'VariableManager' = manager

        self.func_addr = func_addr

        self._variables: Set[SimVariable] = OrderedSet()  # all variables that are added to any region
        self._global_region = KeyedRegion()
        self._stack_region = KeyedRegion()
        self._register_region = KeyedRegion()
        self._live_variables = { }  # a mapping between addresses of program points and live variable collections

        self._variable_accesses: Dict[SimVariable,Set[VariableAccess]] = defaultdict(set)
        self._insn_to_variable: Dict[int,Set[Tuple[SimVariable,int]]] = defaultdict(set)
        self._stmt_to_variable: Dict[Tuple[int,int],Set[Tuple[SimVariable,int]]] = defaultdict(set)
        self._atom_to_variable: Dict[Tuple[int,int],Dict[int,Set[Tuple[SimVariable,int]]]] = \
            defaultdict(_defaultdict_set)
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

        self.types = TypesStore(self.manager._kb)
        self.variable_to_types: Dict[SimVariable,SimType] = { }
        self.variables_with_manual_types = set()

    #
    # Serialization
    #

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __getstate__(self):
        d = dict(self.__dict__)
        d['manager'] = None
        d['types'].kb = None
        return d

    def set_manager(self, manager: 'VariableManager'):
        self.manager = manager
        self.types.kb = manager._kb

    @classmethod
    def _get_cmsg(cls):
        return variables_pb2.VariableManagerInternal()

    def serialize_to_cmessage(self):
        # pylint:disable=no-member,unused-variable
        cmsg = self._get_cmsg()

        # variables
        temp_variables = [ ]
        register_variables = [ ]
        stack_variables = [ ]
        memory_variables = [ ]

        for variable in self._variables:
            vc = variable.serialize_to_cmessage()
            if isinstance(variable, SimRegisterVariable):
                register_variables.append(vc)
            elif isinstance(variable, SimStackVariable):
                stack_variables.append(vc)
            elif isinstance(variable, SimMemoryVariable):
                memory_variables.append(vc)
            else:
                raise NotImplementedError()
        for variable in self._phi_variables:
            vc = variable.serialize_to_cmessage()
            vc.base.is_phi = True
            if isinstance(variable, SimRegisterVariable):
                register_variables.append(vc)
            elif isinstance(variable, SimStackVariable):
                stack_variables.append(vc)
            elif isinstance(variable, SimMemoryVariable):
                memory_variables.append(vc)
            else:
                raise NotImplementedError()

        cmsg.regvars.extend(register_variables)
        cmsg.stackvars.extend(stack_variables)
        cmsg.memvars.extend(memory_variables)

        # accesses
        accesses = [ ]
        for variable_accesses in self._variable_accesses.values():
            for variable_access in variable_accesses:
                accesses.append(variable_access.serialize_to_cmessage())
        cmsg.accesses.extend(accesses)

        # unified variables
        unified_temp_variables = [ ]
        unified_register_variables = [ ]
        unified_stack_variables = [ ]
        unified_memory_variables = [ ]

        for variable in self._unified_variables:
            if isinstance(variable, SimRegisterVariable):
                unified_register_variables.append(variable.serialize_to_cmessage())
            elif isinstance(variable, SimStackVariable):
                unified_stack_variables.append(variable.serialize_to_cmessage())
            elif isinstance(variable, SimMemoryVariable):
                unified_memory_variables.append(variable.serialize_to_cmessage())
            else:
                raise NotImplementedError()

        cmsg.unified_regvars.extend(unified_register_variables)
        cmsg.unified_stackvars.extend(unified_stack_variables)
        cmsg.unified_memvars.extend(unified_memory_variables)

        relations = [ ]
        for variable, unified in self._variables_to_unified_variables.items():
            relation = variables_pb2.Var2Unified()
            relation.var_ident = variable.ident
            relation.unified_var_ident = unified.ident
            relations.append(relation)
        cmsg.var2unified.extend(relations)

        # phi vars
        phi_relations = []
        for phi, vars_ in self._phi_variables.items():
            for var in vars_:
                if var not in self._variables and var not in self._phi_variables:
                    l.error("Saving a variable which is not in the registered list. The database is likely corrupted.")
                relation = variables_pb2.Phi2Var()
                relation.phi_ident = phi.ident
                relation.var_ident = var.ident
                phi_relations.append(relation)
        cmsg.phi2var.extend(phi_relations)

        # TODO: Types

        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, variable_manager=None, func_addr=None, **kwargs) -> 'VariableManagerInternal':  # pylint:disable=arguments-differ
        model = VariableManagerInternal(variable_manager, func_addr=func_addr)

        variable_by_ident = {}

        # variables
        all_vars = []

        for regvar_pb2 in cmsg.regvars:
            all_vars.append((regvar_pb2.base.is_phi, SimRegisterVariable.parse_from_cmessage(regvar_pb2)))
        for stackvar_pb2 in cmsg.stackvars:
            all_vars.append((stackvar_pb2.base.is_phi, SimStackVariable.parse_from_cmessage(stackvar_pb2)))
        for memvar_pb2 in cmsg.memvars:
            all_vars.append((memvar_pb2.base.is_phi, SimMemoryVariable.parse_from_cmessage(memvar_pb2)))
        for is_phi, var in all_vars:
            variable_by_ident[var.ident] = var
            if is_phi:
                model._phi_variables[var] = set()
            else:
                model._variables.add(var)

        # variable accesses
        for varaccess_pb2 in cmsg.accesses:
            variable_access = VariableAccess.parse_from_cmessage(varaccess_pb2, variable_by_ident=variable_by_ident)
            variable = variable_access.variable
            offset = variable_access.offset
            tpl = (variable, offset)

            model._variable_accesses[variable_access.variable].add(variable_access)
            model._insn_to_variable[variable_access.location.ins_addr].add(tpl)
            loc = (variable_access.location.block_addr, variable_access.location.stmt_idx)
            model._stmt_to_variable[loc].add(tpl)
            if variable_access.atom_hash is not None:
                model._atom_to_variable[loc][variable_access.atom_hash].add(tpl)

        # unified variables
        unified_variable_by_ident = {}
        for regvar_pb2 in cmsg.unified_regvars:
            regvar = SimRegisterVariable.parse_from_cmessage(regvar_pb2)
            unified_variable_by_ident[regvar.ident] = regvar
            model._unified_variables.add(regvar)
        for stackvar_pb2 in cmsg.unified_stackvars:
            stackvar = SimStackVariable.parse_from_cmessage(stackvar_pb2)
            unified_variable_by_ident[stackvar.ident] = stackvar
            model._unified_variables.add(stackvar)
        for memvar_pb2 in cmsg.unified_memvars:
            memvar = SimMemoryVariable.parse_from_cmessage(memvar_pb2)
            unified_variable_by_ident[memvar.ident] = memvar
            model._unified_variables.add(memvar)

        for var2unified in cmsg.var2unified:
            variable = variable_by_ident[var2unified.var_ident]
            unified = unified_variable_by_ident[var2unified.unified_var_ident]
            model._variables_to_unified_variables[variable] = unified

        for phi2var in cmsg.phi2var:
            phi = variable_by_ident[phi2var.phi_ident]
            var = variable_by_ident[phi2var.var_ident]
            model._phi_variables[phi].add(var)

        # TODO: Types

        for var in model._variables:
            if isinstance(var, SimStackVariable):
                region = model._stack_region
                offset = var.offset
            elif isinstance(var, SimRegisterVariable):
                region = model._register_region
                offset = var.reg
            elif isinstance(var, SimMemoryVariable):
                region = model._global_region
                offset = var.addr
            else:
                raise ValueError('Unsupported sort %s in parse_from_cmessage().' % type(var))

            region.add_variable(offset, var)

        return model

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
            region = self._stack_region
        elif sort == 'register':
            region = self._register_region
        elif sort == 'global':
            region = self._global_region
        else:
            raise ValueError('Unsupported sort %s in add_variable().' % sort)
        existing = [x for x in region.get_variables_by_offset(start) if x.ident == variable.ident]
        if len(existing) == 1:
            var = existing[0]
            if var.name is not None and not variable.renamed:
                variable.name = var.name
                variable.renamed = var.renamed
        else:
            # implicitly overwrite or add I guess
            pass
        region.add_variable(start, variable)
        self._variables.add(variable)

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
        self._variables.add(variable)

    def write_to(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access(VariableAccessSort.WRITE, variable, offset, location, overwrite=overwrite,
                                     atom=atom)

    def read_from(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access(VariableAccessSort.READ, variable, offset, location, overwrite=overwrite,
                                     atom=atom)

    def reference_at(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access(VariableAccessSort.REFERENCE, variable, offset, location, overwrite=overwrite,
                                     atom=atom)

    def _record_variable_access(self, sort: int, variable, offset, location, overwrite=False, atom=None):
        # TODO can this line be removed, should we be only adding to _variables in add_variable?
        self._variables.add(variable)
        var_and_offset = variable, offset
        atom_hash = (hash(atom) & 0xffff_ffff) if atom is not None else None
        if overwrite:
            self._variable_accesses[variable] = {VariableAccess(variable, sort, location, offset, atom_hash=atom_hash)}
            self._insn_to_variable[location.ins_addr] = {var_and_offset}
            self._stmt_to_variable[(location.block_addr, location.stmt_idx)] = {var_and_offset}
            if atom_hash is not None:
                self._atom_to_variable[(location.block_addr, location.stmt_idx)][atom_hash] = { var_and_offset }
        else:
            self._variable_accesses[variable].add(VariableAccess(variable, sort, location, offset, atom_hash=atom_hash))
            self._insn_to_variable[location.ins_addr].add(var_and_offset)
            self._stmt_to_variable[(location.block_addr, location.stmt_idx)].add(var_and_offset)
            if atom_hash is not None:
                self._atom_to_variable[(location.block_addr, location.stmt_idx)][atom_hash].add(var_and_offset)

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
            if block_addr in self._phi_variables_by_block and existing_phi in self._phi_variables_by_block[block_addr]:
                if not non_phis.issubset(self.get_phi_subvariables(existing_phi)):
                    # Update the variables that this phi variable represents
                    self._phi_variables[existing_phi] |= non_phis
                return existing_phi

        # allocate a new phi variable
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

        atom_hash = hash(atom) & 0xffff_ffff
        if atom_hash not in self._atom_to_variable[key]:
            return set()

        return self._atom_to_variable[key][atom_hash]

    def find_variables_by_stack_offset(self, offset: int) -> Set[SimVariable]:
        return self._stack_region.get_variables_by_offset(offset)

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
            return { }
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
            return any(acc for acc in accesses if acc.access_type == VariableAccessSort.WRITE)

        def has_read_access(accesses):
            return any(acc for acc in accesses if acc.access_type == VariableAccessSort.READ)

        input_variables = [ ]

        for variable, accesses in self._variable_accesses.items():
            if variable in self._phi_variables:
                # a phi variable is definitely not an input variable
                continue
            if not has_write_access(accesses) and has_read_access(accesses):
                if not exclude_specials or not variable.category:
                    input_variables.append(variable)

        return input_variables

    def assign_variable_names(self, labels=None, types=None):
        """
        Assign default names to all SSA variables.

        :param labels:  Known labels in the binary.
        :return:        None
        """

        for var in self._variables:
            if (types is None or SimStackVariable in types) and isinstance(var, SimStackVariable):
                if var.name is not None:
                    continue
                if var.ident.startswith('iarg'):
                    var.name = 'arg_%x' % var.offset
                else:
                    var.name = 's_%x' % (-var.offset)
                    # var.name = var.ident
            elif (types is None or SimRegisterVariable in types) and isinstance(var, SimRegisterVariable):
                if var.name is not None:
                    continue
                var.name = var.ident
            elif (types is None or SimMemoryVariable in types) and isinstance(var, SimMemoryVariable):
                if var.name is not None:
                    continue
                if labels is not None and var.addr in labels:
                    var.name = labels[var.addr]
                    if "@@" in var.name:
                        var.name = var.name[:var.name.index("@@")]
                elif isinstance(var.addr, int):
                    var.name = "g_%x" % var.addr
                elif var.ident is not None:
                    var.name = var.ident
                else:
                    var.name = "g_%s" % var.addr

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

    def _register_struct_type(self, ty: SimStruct, name: Optional[str]=None) -> TypeRef:
        if not name:
            name = ty.name
        if not name:
            name = self.types.unique_type_name()
        if name in self.types:
            return self.types[name]
        ty = TypeRef(name, ty).with_arch(self.manager._kb._project.arch)
        self.types[name] = ty
        return ty

    def set_variable_type(self, var: SimVariable, ty: SimType, name: Optional[str]=None,
                          override_bot: bool=True) -> None:
        if isinstance(ty, SimTypeBottom) and override_bot:
            # we fall back to assigning a default unsigned integer type for the variable
            if var.size is not None:
                size_to_type = {
                    1: SimTypeChar,
                    2: SimTypeShort,
                    4: SimTypeInt,
                    8: SimTypeLong,
                }
                if var.size in size_to_type:
                    ty = size_to_type[var.size](signed=False, label=ty.label).with_arch(self.manager._kb._project.arch)

        if name:
            if name not in self.types:
                self.types[name] = TypeRef(name, ty).with_arch(self.manager._kb._project.arch)
            ty = self.types[name]
        elif isinstance(ty, SimTypePointer) and isinstance(ty.pts_to, SimStruct):
            typeref = self._register_struct_type(ty.pts_to)
            ty = ty.copy().with_arch(self.manager._kb._project.arch)
            ty.pts_to = typeref
        elif isinstance(ty, SimStruct):
            ty = self._register_struct_type(ty, name=name)

        self.variable_to_types[var] = ty

    def get_variable_type(self, var) -> Optional[SimType]:
        return self.variable_to_types.get(var, None)

    def remove_types(self):
        self.types.clear()
        self.variable_to_types.clear()

    def unify_variables(self) -> None:
        """
        Map SSA variables to a unified variable. Fill in self._unified_variables.
        """

        stack_vars: Dict[int,List[SimStackVariable]] = defaultdict(list)
        reg_vars: Set[SimRegisterVariable] = set()

        # unify stack variables based on their locations
        for v in self.get_variables():
            if v in self._variables_to_unified_variables:
                # do not unify twice
                continue
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
            for subv in subvs:
                graph.add_edge(v, subv)

        # prune the graph: remove nodes that have never been used
        while True:
            unused_nodes = set()
            for node in [ nn for nn in graph.nodes() if graph.degree[nn] == 1]:
                if not self.get_variable_accesses(node):
                    # this node has never been used - discard it
                    unused_nodes.add(node)
            if unused_nodes:
                graph.remove_nodes_from(unused_nodes)
            else:
                break

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

    def __contains__(self, key) -> bool:
        if key == 'global':
            return True
        return key in self.function_managers

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

    @staticmethod
    def convert_variable_list(vlist: List[Variable], manager: VariableManagerInternal ):
        for v in vlist:
            simv = None
            if v.type is None:
                l.warning("skipped unknown type for %s", v.name)
                continue
            if v.sort == "global":
                simv = SimMemoryVariable(v.addr,v.type.byte_size)
            elif v.sort == "register":
                simv = SimRegisterVariable(v.addr,v.type.byte_size)
            elif v.sort == "stack":
                simv = SimStackVariable(v.addr, v.type.byte_size)
            else:
                l.warning("undefined variable sort %s for %s", v.sort, v.addr)
                continue
            simv.name = v.name
            manager.add_variable(v.sort, v.addr, simv)

    def load_from_dwarf(self, cu_list: List[CompilationUnit] = None):
        cu_list = cu_list or self._kb._project.loader.main_object.compilation_units
        if cu_list is None:
            l.warning("no CompilationUnit found")
            return
        for cu in cu_list:
            self.convert_variable_list(cu.global_variables, self.global_manager)
            for low_pc, subp in cu.functions.items():
                manager = self.get_function_manager(low_pc)
                self.convert_variable_list(subp.local_variables, manager)

KnowledgeBasePlugin.register_default('variables', VariableManager)
