from __future__ import annotations
from typing import Literal, TYPE_CHECKING
import logging
from collections import defaultdict
from itertools import count, chain

import networkx

import ailment
from cle.backends.elf.compilation_unit import CompilationUnit
from cle.backends.elf.variable import Variable

from angr.utils.orderedset import OrderedSet
from angr.utils.ail import is_phi_assignment
from ...protos import variables_pb2
from ...serializable import Serializable
from ...sim_variable import SimVariable, SimStackVariable, SimMemoryVariable, SimRegisterVariable
from ...sim_type import (
    TypeRef,
    SimType,
    SimStruct,
    SimTypePointer,
    SimTypeBottom,
    SimTypeChar,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
)
from ...keyed_region import KeyedRegion
from ..plugin import KnowledgeBasePlugin
from ..types import TypesStore
from .variable_access import VariableAccess, VariableAccessSort

if TYPE_CHECKING:
    from angr.code_location import CodeLocation

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

    __slots__ = (
        "register_region",
        "stack_region",
    )

    def __init__(self, register_region, stack_region):
        self.register_region = register_region
        self.stack_region = stack_region


def _defaultdict_set():
    return defaultdict(set)


class VariableManagerInternal(Serializable):
    """
    Manage variables for a function. It is meant to be used internally by VariableManager, but it's common to be
    given a reference to one in response to a query for "the variables for a given function". Maybe a better name
    would be "VariableManagerScope".
    """

    def __init__(self, manager, func_addr=None):
        self.manager: VariableManager = manager

        self.func_addr = func_addr

        self._variables: set[SimVariable] = OrderedSet()  # all variables that are added to any region
        self._global_region = KeyedRegion()
        self._stack_region = KeyedRegion()
        self._register_region = KeyedRegion()
        self._live_variables = {}  # a mapping between addresses of program points and live variable collections

        self._variable_accesses: dict[SimVariable, set[VariableAccess]] = defaultdict(set)
        self._insn_to_variable: dict[int, set[tuple[SimVariable, int]]] = defaultdict(set)
        self._stmt_to_variable: dict[tuple[int, int] | tuple[int, int, int], set[tuple[SimVariable, int]]] = (
            defaultdict(set)
        )
        self._variable_to_stmt: dict[SimVariable, set[tuple[int, int] | tuple[int, int, int]]] = defaultdict(set)
        self._atom_to_variable: dict[
            tuple[int, int] | tuple[int, int, int], dict[int, set[tuple[SimVariable, int]]]
        ] = defaultdict(_defaultdict_set)
        self._ident_to_variable: dict[str, SimVariable] = {}
        self._variable_counters = {
            "register": count(),
            "stack": count(),
            "argument": count(),
            "phi": count(),
            "global": count(),
        }

        self._unified_variables: set[SimVariable] = set()
        self._variables_to_unified_variables: dict[SimVariable, SimVariable] = {}

        self._phi_variables = {}
        self._variables_to_phivars = defaultdict(set)
        self._phi_variables_by_block = defaultdict(set)

        self.types = TypesStore(self.manager._kb)
        self.variable_to_types: dict[SimVariable, SimType] = {}
        self.variables_with_manual_types = set()

        # optimization
        self._variables_without_writes = set()

        self.stack_offset_to_struct_member_info: dict[SimStackVariable, (int, SimStackVariable, SimStruct)] = {}

        self.ret_val_size = None

    #
    # Serialization
    #

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __getstate__(self):
        attributes = [
            "func_addr",
            "_variables",
            "_global_region",
            "_stack_region",
            "_register_region",
            "_live_variables",
            "_variable_accesses",
            "_insn_to_variable",
            "_stmt_to_variable",
            "_variable_to_stmt",
            "_atom_to_variable",
            "_ident_to_variable",
            "_variable_counters",
            "_unified_variables",
            "_variables_to_unified_variables",
            "_phi_variables",
            "_variables_to_phivars",
            "_phi_variables_by_block",
            "types",
            "variable_to_types",
            "variables_with_manual_types",
            "_variables_without_writes",
            "ret_val_size",
        ]
        d = {k: getattr(self, k) for k in attributes}
        d["manager"] = None
        d["types"].kb = None
        return d

    def set_manager(self, manager: VariableManager):
        self.manager = manager
        self.types.kb = manager._kb

    @classmethod
    def _get_cmsg(cls):
        return variables_pb2.VariableManagerInternal()

    def serialize_to_cmessage(self):
        # pylint:disable=no-member,unused-variable
        cmsg = self._get_cmsg()

        # variables
        register_variables = []
        stack_variables = []
        memory_variables = []

        for variable in self._variables:
            vc = variable.serialize_to_cmessage()
            if isinstance(variable, SimRegisterVariable):
                register_variables.append(vc)
            elif isinstance(variable, SimStackVariable):
                stack_variables.append(vc)
            elif isinstance(variable, SimMemoryVariable):
                memory_variables.append(vc)
            else:
                raise NotImplementedError
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
                raise NotImplementedError

        cmsg.regvars.extend(register_variables)
        cmsg.stackvars.extend(stack_variables)
        cmsg.memvars.extend(memory_variables)

        # accesses
        accesses = []
        for variable_accesses in self._variable_accesses.values():
            for variable_access in variable_accesses:
                accesses.append(variable_access.serialize_to_cmessage())
        cmsg.accesses.extend(accesses)

        # unified variables
        unified_register_variables = []
        unified_stack_variables = []
        unified_memory_variables = []

        unified_variable_idents: set[str] = set()
        for variable in self._unified_variables:
            unified_variable_idents.add(variable.ident)
            if isinstance(variable, SimRegisterVariable):
                unified_register_variables.append(variable.serialize_to_cmessage())
            elif isinstance(variable, SimStackVariable):
                unified_stack_variables.append(variable.serialize_to_cmessage())
            elif isinstance(variable, SimMemoryVariable):
                unified_memory_variables.append(variable.serialize_to_cmessage())
            else:
                raise NotImplementedError

        cmsg.unified_regvars.extend(unified_register_variables)
        cmsg.unified_stackvars.extend(unified_stack_variables)
        cmsg.unified_memvars.extend(unified_memory_variables)

        relations = []
        for variable, unified in self._variables_to_unified_variables.items():
            if unified.ident not in unified_variable_idents:
                l.error(
                    "The unified variable %s is missing from the unified variables of function %#x. Please "
                    "report it on GitHub.",
                    unified.ident,
                    self.func_addr,
                )
                continue
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
                    l.error("Ignore variable %s because it is not in the registered list.", var.ident)
                    continue
                relation = variables_pb2.Phi2Var()
                relation.phi_ident = phi.ident
                relation.var_ident = var.ident
                phi_relations.append(relation)
        cmsg.phi2var.extend(phi_relations)

        # TODO: Types

        return cmsg

    @classmethod
    def parse_from_cmessage(
        cls, cmsg, variable_manager=None, func_addr=None, **kwargs
    ) -> VariableManagerInternal:  # pylint:disable=arguments-differ
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
                model._ident_to_variable[var.ident] = var

        # variable accesses
        for varaccess_pb2 in cmsg.accesses:
            variable_access = VariableAccess.parse_from_cmessage(varaccess_pb2, variable_by_ident=variable_by_ident)
            variable = variable_access.variable
            offset = variable_access.offset
            tpl = (variable, offset)

            model._variable_accesses[variable_access.variable].add(variable_access)
            model._insn_to_variable[variable_access.location.ins_addr].add(tpl)
            loc = (
                (variable_access.location.block_addr, variable_access.location.stmt_idx)
                if variable_access.location.block_idx is None
                else (
                    variable_access.location.block_addr,
                    variable_access.location.block_idx,
                    variable_access.location.stmt_idx,
                )
            )
            model._stmt_to_variable[loc].add(tpl)
            model._variable_to_stmt[variable].add(loc)
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
            unified = unified_variable_by_ident.get(var2unified.unified_var_ident, None)
            if unified is None:
                l.warning(
                    "Unified variable %s is not found in unified_variable_by_ident.", var2unified.unified_var_ident
                )
                # as a stop gap, we make the variable unify to itself
                model._variables_to_unified_variables[variable] = variable
                continue
            model._variables_to_unified_variables[variable] = unified

        for phi2var in cmsg.phi2var:
            phi = variable_by_ident.get(phi2var.phi_ident, None)
            if phi is None:
                l.warning("Phi variable %s is not found in variable_by_ident.", phi2var.phi_ident)
                continue
            var = variable_by_ident.get(phi2var.var_ident, None)
            if var is None:
                l.warning("Variable %s is not found in variable_by_ident.", phi2var.var_ident)
                continue
            model._phi_variables[phi].add(var)
            model._variables_to_phivars[var].add(phi)

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
                raise ValueError(f"Unsupported sort {type(var)} in parse_from_cmessage().")

            region.add_variable(offset, var)

        model._variables_without_writes = set(model.get_variables_without_writes())

        return model

    #
    # Public methods
    #

    def next_variable_ident(self, sort):
        if sort not in self._variable_counters:
            raise ValueError(f"Unsupported variable sort {sort}")

        if sort == "register":
            prefix = "r"
        elif sort == "stack":
            prefix = "s"
        elif sort == "argument":
            prefix = "arg"
        elif sort == "global":
            prefix = "g"
        else:
            prefix = "m"

        return "i%s_%d" % (prefix, next(self._variable_counters[sort]))

    def add_variable(self, sort, start, variable: SimVariable):
        if sort == "stack":
            region = self._stack_region
        elif sort == "register":
            region = self._register_region
        elif sort == "global":
            region = self._global_region
        else:
            raise ValueError(f"Unsupported sort {sort} in add_variable().")

        # find if there is already an existing variable with the same identifier
        if variable.ident in self._ident_to_variable:
            existing_var = self._ident_to_variable[variable.ident]
            if existing_var.name is not None and not variable.renamed:
                variable.name = existing_var.name
                variable.renamed = existing_var.renamed
        self._ident_to_variable[variable.ident] = variable
        region.add_variable(start, variable)
        self._variables.add(variable)
        self._variables_without_writes.add(variable)

    def set_variable(self, sort, start, variable: SimVariable):
        if sort == "stack":
            region = self._stack_region
        elif sort == "register":
            region = self._register_region
        elif sort == "global":
            region = self._global_region
        else:
            raise ValueError(f"Unsupported sort {sort} in set_variable().")
        # find if there is already an existing variable with the same identifier
        if variable.ident in self._ident_to_variable:
            existing_var = self._ident_to_variable[variable.ident]
            if existing_var.name is not None and not variable.renamed:
                variable.name = existing_var.name
                variable.renamed = existing_var.renamed
        region.set_variable(start, variable)
        self._variables.add(variable)
        self._variables_without_writes.add(variable)

    def write_to(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access(
            VariableAccessSort.WRITE, variable, offset, location, overwrite=overwrite, atom=atom
        )

    def read_from(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access(
            VariableAccessSort.READ, variable, offset, location, overwrite=overwrite, atom=atom
        )

    def reference_at(self, variable, offset, location, overwrite=False, atom=None):
        self._record_variable_access(
            VariableAccessSort.REFERENCE, variable, offset, location, overwrite=overwrite, atom=atom
        )

    def _record_variable_access(
        self,
        sort: int,
        variable,
        offset,
        location: CodeLocation,
        overwrite=False,
        atom=None,
    ):
        atom_hash = (hash(atom) & 0xFFFF_FFFF) if atom is not None else None
        if overwrite:
            self._variable_accesses[variable] = {VariableAccess(variable, sort, location, offset, atom_hash=atom_hash)}
        else:
            self._variable_accesses[variable].add(VariableAccess(variable, sort, location, offset, atom_hash=atom_hash))
        self.record_variable(location, variable, offset, overwrite=overwrite, atom=atom)
        if sort == VariableAccessSort.WRITE and variable in self._variables_without_writes:
            self._variables_without_writes.discard(variable)

    def record_variable(self, location: CodeLocation, variable, offset, overwrite=False, atom=None):
        if variable.ident not in self._ident_to_variable:
            self._ident_to_variable[variable.ident] = variable
            self._variables.add(variable)
        var_and_offset = variable, offset
        atom_hash = (hash(atom) & 0xFFFF_FFFF) if atom is not None else None
        key = (
            (location.block_addr, location.stmt_idx)
            if location.block_idx is None
            else (location.block_addr, location.block_idx, location.stmt_idx)
        )
        if overwrite:
            self._insn_to_variable[location.ins_addr] = {var_and_offset}
            self._stmt_to_variable[key] = {var_and_offset}
            self._variable_to_stmt[variable].add(key)
            if atom_hash is not None:
                self._atom_to_variable[key][atom_hash] = {var_and_offset}
        else:
            self._insn_to_variable[location.ins_addr].add(var_and_offset)
            self._stmt_to_variable[key].add(var_and_offset)
            self._variable_to_stmt[variable].add(key)
            if atom_hash is not None:
                self._atom_to_variable[key][atom_hash].add(var_and_offset)

    def remove_variable_by_atom(self, location: CodeLocation, variable: SimVariable, atom):
        key = (
            (location.block_addr, location.stmt_idx)
            if location.block_idx is None
            else (location.block_addr, location.block_idx, location.stmt_idx)
        )
        if key in self._stmt_to_variable:
            for var_and_offset in list(self._stmt_to_variable[key]):
                if var_and_offset[0] == variable:
                    self._stmt_to_variable[key].remove(var_and_offset)
            if not self._stmt_to_variable[key]:
                del self._stmt_to_variable[key]

        atom_hash = (hash(atom) & 0xFFFF_FFFF) if atom is not None else None
        if key in self._atom_to_variable and atom_hash is not None and atom_hash in self._atom_to_variable[key]:
            for var_and_offset in list(self._atom_to_variable[key][atom_hash]):
                if var_and_offset[0] == variable:
                    self._atom_to_variable[key][atom_hash].discard(var_and_offset)
            if not self._atom_to_variable[key][atom_hash]:
                del self._atom_to_variable[key][atom_hash]
            if not self._atom_to_variable[key]:
                del self._atom_to_variable[key]

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
            if var in self._variables_to_phivars:
                for phivar in self._variables_to_phivars[var]:
                    existing_phis.add(phivar)

        if len(existing_phis) >= 1:
            # iterate through existing phi variables to see if any of it is already used as the phi variable for this
            # block. if so, we reuse it to avoid redundant variable allocations
            for phi in existing_phis:
                if block_addr in self._phi_variables_by_block and phi in self._phi_variables_by_block[block_addr]:
                    if not non_phis.issubset(self.get_phi_subvariables(phi)):
                        # Update the variables that this phi variable represents
                        self._phi_variables[phi] |= non_phis
                    return phi

        # allocate a new phi variable
        repre = next(iter(variables))
        repre_type = type(repre)
        repre_size = max(var.size for var in variables)
        if repre_type is SimRegisterVariable:
            ident_sort = "register"
            a = SimRegisterVariable(repre.reg, repre_size, ident=self.next_variable_ident(ident_sort))
        elif repre_type is SimMemoryVariable:
            ident_sort = "global"
            a = SimMemoryVariable(repre.addr, repre_size, ident=self.next_variable_ident(ident_sort))
        elif repre_type is SimStackVariable:
            ident_sort = "stack"
            a = SimStackVariable(repre.offset, repre_size, ident=self.next_variable_ident(ident_sort))
        else:
            raise TypeError(f'make_phi_node(): Unsupported variable type "{type(repre)}".')

        # Keep a record of all phi variables
        self._phi_variables[a] = set(variables)
        self._phi_variables_by_block[block_addr].add(a)
        for var in variables:
            self._variables_to_phivars[var].add(a)

        return a

    def set_live_variables(self, addr, register_region, stack_region):
        lv = LiveVariables(register_region, stack_region)
        self._live_variables[addr] = lv

    def find_variables_by_insn(self, ins_addr, sort):
        if ins_addr not in self._insn_to_variable:
            return None

        if sort in (VariableType.MEMORY, "memory"):
            vars_and_offset = [
                (var, offset)
                for var, offset in self._insn_to_variable[ins_addr]
                if isinstance(var, (SimStackVariable, SimMemoryVariable))
            ]
        elif sort in (VariableType.REGISTER, "register"):
            vars_and_offset = [
                (var, offset)
                for var, offset in self._insn_to_variable[ins_addr]
                if isinstance(var, SimRegisterVariable)
            ]
        else:
            l.error('find_variable_by_insn(): Unsupported variable sort "%s".', sort)
            return []

        return vars_and_offset

    def is_variable_used_at(self, variable: SimVariable, loc: tuple[int, int]) -> bool:
        return loc in self._variable_to_stmt[variable]

    def find_variable_by_stmt(self, block_addr, stmt_idx, sort, block_idx: int | None = None):
        return next(iter(self.find_variables_by_stmt(block_addr, stmt_idx, sort, block_idx=block_idx)), None)

    def find_variables_by_stmt(
        self, block_addr: int, stmt_idx: int, sort: str, block_idx: int | None = None
    ) -> list[tuple[SimVariable, int]]:
        key = (block_addr, stmt_idx) if block_idx is None else (block_addr, block_idx, stmt_idx)

        if key not in self._stmt_to_variable:
            return []

        variables = self._stmt_to_variable[key]
        if not variables:
            return []

        if sort == "memory":
            var_and_offsets = [
                (var, offset)
                for var, offset in self._stmt_to_variable[key]
                if isinstance(var, (SimStackVariable, SimMemoryVariable))
            ]
        elif sort == "register":
            var_and_offsets = [
                (var, offset) for var, offset in self._stmt_to_variable[key] if isinstance(var, SimRegisterVariable)
            ]
        else:
            l.error('find_variables_by_stmt(): Unsupported variable sort "%s".', sort)
            return []

        return var_and_offsets

    def find_variable_by_atom(self, block_addr, stmt_idx, atom, block_idx: int | None = None):
        return next(iter(self.find_variables_by_atom(block_addr, stmt_idx, atom, block_idx=block_idx)), None)

    def find_variables_by_atom(
        self, block_addr, stmt_idx, atom, block_idx: int | None = None
    ) -> set[tuple[SimVariable, int]]:
        key = (block_addr, stmt_idx) if block_idx is None else (block_addr, block_idx, stmt_idx)

        if key not in self._atom_to_variable:
            return set()

        atom_hash = hash(atom) & 0xFFFF_FFFF
        if atom_hash not in self._atom_to_variable[key]:
            return set()

        return self._atom_to_variable[key][atom_hash]

    def find_variables_by_stack_offset(self, offset: int) -> set[SimVariable]:
        return self._stack_region.get_variables_by_offset(offset)

    def find_variables_by_register(self, reg: str | int) -> set[SimVariable]:
        if type(reg) is str:
            reg = self.manager._kb._project.arch.registers.get(reg)[0]
        return self._register_region.get_variables_by_offset(reg)

    def get_variable_accesses(self, variable: SimVariable, same_name: bool = False) -> list[VariableAccess]:
        if not same_name:
            if variable in self._variable_accesses:
                return list(self._variable_accesses[variable])

            return []

        # find all variables with the same variable name

        vars_list = []

        for var in self._variable_accesses:
            if variable.name == var.name:
                vars_list.append(var)

        accesses = []
        for var in vars_list:
            accesses.extend(self.get_variable_accesses(var))

        return accesses

    def get_variables(
        self, sort: Literal["stack", "reg"] | None = None, collapse_same_ident=False
    ) -> list[SimStackVariable | SimRegisterVariable]:
        """
        Get a list of variables.

        :param sort:                Sort of the variable to get.
        :param collapse_same_ident: Whether variables of the same identifier should be collapsed or not.
        :return:                    A list of variables.
        """

        variables = []

        if collapse_same_ident:
            raise NotImplementedError

        for var in self._variables:
            if sort == "stack" and not isinstance(var, SimStackVariable):
                continue
            if sort == "reg" and not isinstance(var, SimRegisterVariable):
                continue
            variables.append(var)

        return variables

    def get_unified_variables(
        self, sort: Literal["stack", "reg"] | None = None
    ) -> list[SimStackVariable | SimRegisterVariable]:
        """
        Get a list of unified variables.

        :param sort:    Sort of the variable to get.
        :return:        A list of variables.
        """

        variables = []

        for var in self._unified_variables:
            if sort == "stack" and not isinstance(var, SimStackVariable):
                continue
            if sort == "reg" and not isinstance(var, SimRegisterVariable):
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
            return {}
        variables = {}
        for phi in self._phi_variables_by_block[block_addr]:
            variables[phi] = self._phi_variables[phi]
        return variables

    def get_variables_without_writes(self) -> list[SimVariable]:
        """
        Get all variables that have never been written to.

        :return: A list of variables that are never written to.
        """

        def has_write_access(accesses):
            return any(acc for acc in accesses if acc.access_type == VariableAccessSort.WRITE)

        input_variables = []

        for variable, accesses in self._variable_accesses.items():
            if variable in self._phi_variables:
                # a phi variable is definitely not an input variable
                continue
            if not has_write_access(accesses):
                input_variables.append(variable)

        return input_variables

    def input_variables(self, exclude_specials: bool = True):
        """
        Get all variables that have never been written to.

        :return: A list of variables that are never written to.
        """

        def has_read_access(accesses):
            return any(acc for acc in accesses if acc.access_type == VariableAccessSort.READ)

        input_variables = []

        for variable in self._variables_without_writes:
            if variable in self._phi_variables:
                # a phi variable is definitely not an input variable
                continue
            if variable in self._variable_accesses:
                accesses = self._variable_accesses[variable]
                if has_read_access(accesses) and (not exclude_specials or not variable.category):
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
                if var.ident.startswith("iarg"):
                    var.name = f"arg_{var.offset:x}"
                else:
                    var.name = "s_%x" % (-var.offset)
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
                        var.name = var.name[: var.name.index("@@")]
                elif isinstance(var.addr, int):
                    var.name = f"g_{var.addr:x}"
                elif var.ident is not None:
                    var.name = var.ident
                else:
                    var.name = f"g_{var.addr}"

    def assign_unified_variable_names(
        self,
        labels=None,
        arg_names: list[str] | None = None,
        reset: bool = False,
        func_blocks: list[ailment.Block] | None = None,
    ) -> None:
        """
        Assign default names to all unified variables. If `func_blocks` is provided, we will find out variables that
        are only ever written to in Phi assignments and never used elsewhere, and put these variables at the end of
        the sorted list. These variables are likely completely removed during the dephication process.

        :param labels:    Known labels in the binary.
        :param arg_names: Known argument names.
        :param reset:     Reset all variable names or not.
        :param func_blocks: A list of function blocks of the function where these variables are accessed.
        """

        def _id_from_varident(ident: str) -> int:
            return int(ident[ident.find("_") + 1 :])

        if not self._unified_variables:
            return

        sorted_stack_variables = []
        sorted_reg_variables = []
        arg_vars = []

        for var in self._unified_variables:
            if isinstance(var, SimStackVariable):
                if var.ident and var.ident.startswith("arg_"):
                    arg_vars.append(var)
                else:
                    sorted_stack_variables.append(var)

            elif isinstance(var, SimRegisterVariable):
                if var.ident and var.ident.startswith("arg_"):
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
                        var.name = var.name[: var.name.index("@@")]
                elif var.ident:
                    var.name = var.ident
                else:
                    var.name = f"g_{var.addr:x}"

        # rename variables in a fixed order
        var_ctr = count(0)

        sorted_stack_variables = sorted(sorted_stack_variables, key=lambda v: v.offset)
        sorted_reg_variables = sorted(sorted_reg_variables, key=lambda v: _id_from_varident(v.ident))

        # find variables that are likely only used by phi assignments
        phi_only_vars = []
        if func_blocks:
            func_block_by_addr = {(block.addr, block.idx): block for block in func_blocks}
            for var in list(sorted_stack_variables):
                if self._is_variable_only_used_by_phi_stmt(var, func_block_by_addr):
                    sorted_stack_variables.remove(var)
                    phi_only_vars.append(var)
            for var in list(sorted_reg_variables):
                if self._is_variable_only_used_by_phi_stmt(var, func_block_by_addr):
                    sorted_reg_variables.remove(var)
                    phi_only_vars.append(var)

        for var in chain(sorted_stack_variables, sorted_reg_variables, phi_only_vars):
            idx = next(var_ctr)
            if var.name is not None and not reset:
                continue
            if isinstance(var, (SimStackVariable, SimRegisterVariable)):
                var.name = f"v{idx}"
            # clear the hash cache
            var._hash = None

        # rename arguments but keeping the original order
        arg_ctr = count(0)
        arg_vars = sorted(arg_vars, key=lambda v: _id_from_varident(v.ident))
        for var in arg_vars:
            idx = next(arg_ctr)
            if var.name is not None and not reset:
                continue
            var.name = arg_names[idx] if arg_names else f"a{idx}"
            var._hash = None

    def _register_struct_type(self, ty: SimStruct, name: str | None = None) -> TypeRef:
        if not name:
            name = ty.name
        if not name:
            name = self.types.unique_type_name()
        if name in self.types:
            return self.types[name]
        ty = TypeRef(name, ty).with_arch(self.manager._kb._project.arch)
        self.types[name] = ty
        return ty

    def set_variable_type(
        self,
        var: SimVariable,
        ty: SimType,
        name: str | None = None,
        override_bot: bool = True,
        all_unified: bool = False,
        mark_manual: bool = False,
    ) -> None:
        # we fall back to assigning a default unsigned integer type for the variable
        if isinstance(ty, SimTypeBottom) and override_bot and var.size is not None:
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
        if mark_manual:
            self.variables_with_manual_types.add(var)
        if all_unified:
            unified = self._variables_to_unified_variables.get(var, None)
            if unified is not None:
                for other_var, other_unified in self._variables_to_unified_variables.items():
                    if other_unified is unified and other_var is not var:
                        self.variable_to_types[other_var] = ty
                        if mark_manual:
                            self.variables_with_manual_types.add(other_var)
        if isinstance(var, SimStackVariable) and isinstance(ty, TypeRef) and isinstance(ty.type, SimStruct):
            self.stack_offset_to_struct_member_info.update(self._extract_fields_from_struct(var, ty.type))

    def _extract_fields_from_struct(self, var, ty: SimStruct, top_struct_offset=0):
        result = {}
        for name, field_offset in ty.offsets.items():
            field_ty = ty.fields[name]
            offset = top_struct_offset + field_offset
            if isinstance(field_ty, TypeRef):
                field_ty = field_ty.type
            if isinstance(field_ty, SimStruct):
                result.update(
                    self._extract_fields_from_struct(var, field_ty, top_struct_offset=top_struct_offset + field_offset)
                )
            else:
                result[var.offset + offset] = (offset, var, ty)
        return result

    def get_variable_type(self, var) -> SimType | None:
        return self.variable_to_types.get(var, None)

    def remove_types(self):
        self.types.clear()
        self.variable_to_types.clear()

    def unify_variables(self) -> None:
        """
        Map SSA variables to a unified variable. Fill in self._unified_variables.
        """

        stack_vars: dict[int, list[SimStackVariable]] = defaultdict(list)
        reg_vars: set[SimRegisterVariable] = set()

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
        graph = networkx.DiGraph()  # an edge v1 -> v2 means v2 is the phi variable for v1
        for v, subvs in self._phi_variables.items():
            if not isinstance(v, SimRegisterVariable):
                continue
            for subv in subvs:
                graph.add_edge(subv, v)

        # prune the graph: remove nodes that have never been used
        while True:
            unused_nodes = set()
            for node in [nn for nn in graph.nodes() if graph.out_degree[nn] == 0]:
                if not self.get_variable_accesses(node):
                    # this node has never been used - discard it
                    unused_nodes.add(node)
            if unused_nodes:
                graph.remove_nodes_from(unused_nodes)
            else:
                break

        # convert the directional graph into a non-directional graph
        graph_ = networkx.Graph()
        graph_.add_nodes_from(graph.nodes)
        graph_.add_edges_from(graph.edges)

        for nodes in networkx.connected_components(graph_):
            if len(nodes) <= 1:
                continue
            # side effect of sorting: arg_x variables are always in the front of the list
            nodes = sorted(nodes, key=lambda x: x.ident)
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

    def unified_variable(self, variable: SimVariable) -> SimVariable | None:
        """
        Return the unified variable for a given SSA variable,

        :param variable:    The SSA variable.
        :return:            The unified variable, or None if there is no such SSA variable.
        """

        return self._variables_to_unified_variables.get(variable, None)

    def _is_variable_only_used_by_phi_stmt(
        self, var: SimVariable, func_block_by_addr: dict[tuple[int, int | None], ailment.Block]
    ) -> bool:
        accesses = self.get_variable_accesses(var)
        if not accesses:
            # not used at all?
            return False
        for acc in accesses:
            block = func_block_by_addr.get((acc.location.block_addr, acc.location.block_idx), None)
            if block is not None:
                stmt = block.statements[acc.location.stmt_idx]
                if not is_phi_assignment(stmt):
                    return False
        return True


class VariableManager(KnowledgeBasePlugin):
    """
    Manage variables.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)
        self.global_manager = VariableManagerInternal(self)
        self.function_managers: dict[int, VariableManagerInternal] = {}

    def __contains__(self, key) -> bool:
        if key == "global":
            return True
        return key in self.function_managers

    def __getitem__(self, key) -> VariableManagerInternal:
        """
        Get the VariableManagerInternal object for a function or a region.

        :param str or int key: Key of the region. "global" for the global region, or a function address for the
                               function.
        :return:               The VariableManagerInternal object.
        """

        if key == "global":  # pylint:disable=no-else-return
            return self.global_manager

        # key refers to a function address
        return self.get_function_manager(key)

    def __delitem__(self, key) -> None:
        """
        Remove the existing VariableManagerInternal object for a function or a region.

        :param Union[str,int] key:  Key of the region. "global" for the global region, or a function address for the
                                    function.
        :return:                    None
        """

        if key == "global":
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

    def get_variable_accesses(self, variable: SimVariable, same_name: bool = False) -> list[VariableAccess]:
        """
        Get a list of all references to the given variable.

        :param variable:        The variable.
        :param same_name:       Whether to include all variables with the same variable name, or just based on the
                                variable identifier.
        :return:                All references to the variable.
        """

        if variable.region == "global":
            return self.global_manager.get_variable_accesses(variable, same_name=same_name)

        if variable.region in self.function_managers:
            return self.function_managers[variable.region].get_variable_accesses(variable, same_name=same_name)

        l.warning("get_variable_accesses(): Region %s is not found.", variable.region)
        return []

    def copy(self):
        raise NotImplementedError

    @staticmethod
    def convert_variable_list(vlist: list[Variable], manager: VariableManagerInternal):
        for v in vlist:
            simv = None
            if v.type is None:
                l.warning("skipped unknown type for %s", v.name)
                continue
            if v.sort == "global":
                simv = SimMemoryVariable(v.addr, v.type.byte_size)
            elif v.sort == "register":
                simv = SimRegisterVariable(v.addr, v.type.byte_size)
            elif v.sort == "stack":
                simv = SimStackVariable(v.addr, v.type.byte_size)
            else:
                l.warning("undefined variable sort %s for %s", v.sort, v.addr)
                continue
            simv.name = v.name
            manager.add_variable(v.sort, v.addr, simv)

    def load_from_dwarf(self, cu_list: list[CompilationUnit] | None = None):
        cu_list = cu_list or self._kb._project.loader.main_object.compilation_units
        if cu_list is None:
            l.warning("no CompilationUnit found")
            return
        for cu in cu_list:
            self.convert_variable_list(cu.global_variables, self.global_manager)
            for low_pc, subp in cu.functions.items():
                manager = self.get_function_manager(low_pc)
                self.convert_variable_list(subp.local_variables, manager)


KnowledgeBasePlugin.register_default("variables", VariableManager)
