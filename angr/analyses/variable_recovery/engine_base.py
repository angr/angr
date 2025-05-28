from __future__ import annotations
from typing import Any, Generic, TypeVar, cast
import contextlib
import logging

import angr.ailment as ailment
import claripy

from angr.analyses.variable_recovery.variable_recovery_base import VariableRecoveryStateBase
from angr.engines.light.engine import BlockType
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.engines.light import SimEngineLight, ArithmeticExpression
from angr.errors import SimMemoryMissingError
from angr.sim_variable import SimVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from angr.code_location import CodeLocation
from angr.analyses.typehoon import typevars, typeconsts
from angr.analyses.typehoon.typevars import TypeVariable, DerivedTypeVariable, AddN, SubN, Load, Store
from angr.utils.constants import MAX_POINTSTO_BITS

#
# The base engine used in VariableRecoveryFast
#

l = logging.getLogger(name=__name__)

RichRT_co = TypeVar("RichRT_co", bound=claripy.ast.Bits, covariant=True)


class RichR(Generic[RichRT_co]):
    """
    A rich representation of calculation results. The variable recovery data domain.
    """

    __slots__ = (
        "data",
        "type_constraints",
        "typevar",
        "variable",
    )

    def __init__(
        self,
        data: RichRT_co,
        variable=None,
        typevar: typeconsts.TypeConstant | typevars.TypeVariable | None = None,
        type_constraints: set[typevars.TypeConstraint] | None = None,
    ):
        self.data = data
        self.variable = variable
        self.typevar: typeconsts.TypeConstant | typevars.TypeVariable | None = typevar
        self.type_constraints = type_constraints

    @property
    def bits(self) -> int:
        return self.data.size()

    def __repr__(self):
        return f"R{{{self.data!r}}}"


VRStateType = TypeVar("VRStateType", bound=VariableRecoveryStateBase)


class SimEngineVRBase(
    Generic[VRStateType, BlockType],
    SimEngineLight[VRStateType, RichR[claripy.ast.BV | claripy.ast.FP], BlockType, None],
):
    """
    The base class for variable recovery analyses. Contains methods for basic interactions with the state, like loading
    and storing data.
    """

    def __init__(self, project, kb, vvar_type_hints: dict[int, typeconsts.TypeConstant] | None = None):
        super().__init__(project)

        self.vvar_type_hints: dict[int, typeconsts.TypeConstant] = (
            vvar_type_hints if vvar_type_hints is not None else {}
        )
        self.kb = kb
        self.vvar_region: dict[int, Any] = {}

    @property
    def func_addr(self):
        if self.state is None:
            return None
        return self.state.function.addr

    def _top(self, bits):
        return RichR(self.state.top(bits))

    def _is_top(self, expr):
        return self.state.is_top(expr.data)

    #
    # Address parsing
    #

    @staticmethod
    def _addr_has_concrete_base(addr: claripy.ast.Bits) -> bool:
        if addr.op == "__add__" and len(addr.args) == 2:
            if cast(claripy.ast.BV, addr.args[0]).concrete:
                return True
            if cast(claripy.ast.BV, addr.args[1]).concrete:
                return True
        return False

    @staticmethod
    def _parse_offsetted_addr(addr: claripy.ast.Bits) -> tuple[claripy.ast.BV, claripy.ast.BV, int] | None:
        if addr.op == "__add__" and len(addr.args) == 2:
            concrete_base, byte_offset = None, None
            if cast(claripy.ast.BV, addr.args[0]).concrete:
                concrete_base, byte_offset = cast(tuple[claripy.ast.BV, claripy.ast.BV], addr.args)
            elif cast(claripy.ast.BV, addr.args[1]).concrete:
                concrete_base, byte_offset = cast(tuple[claripy.ast.BV, claripy.ast.BV], (addr.args[1], addr.args[0]))
            if concrete_base is None or byte_offset is None:
                return None
            base_addr = concrete_base
            offset = None
            elem_size = None
            if byte_offset.concrete:
                offset = byte_offset
                elem_size = 1
            else:
                abs_offset = byte_offset
                if abs_offset.op == "__lshift__" and cast(claripy.ast.BV, abs_offset.args[1]).concrete:
                    offset = cast(claripy.ast.BV, abs_offset.args[0])
                    elem_size = 2 ** cast(claripy.ast.BV, abs_offset.args[1]).concrete_value
                elif abs_offset.op == "__mul__" and cast(claripy.ast.BV, abs_offset.args[1]).concrete:
                    offset = cast(claripy.ast.BV, abs_offset.args[0])
                    elem_size = cast(claripy.ast.BV, abs_offset.args[1]).concrete_value

            if base_addr is not None and offset is not None and elem_size is not None:
                return base_addr, offset, elem_size
        return None

    #
    # Logic
    #

    def _ensure_variable_existence(
        self, richr_addr: RichR[claripy.ast.BV | claripy.ast.FP], codeloc: CodeLocation, src_expr=None
    ) -> list[tuple[SimVariable, int]]:
        data = richr_addr.data

        if self.state.is_stack_address(data):
            # this is a stack address
            # extract stack offset
            stack_offset: int | None = self.state.get_stack_offset(data)

            variable_manager = self.state.variable_manager[self.func_addr]
            var_candidates: list[tuple[SimVariable, int]] = variable_manager.find_variables_by_stmt(
                self.block.addr, self.stmt_idx, "memory"
            )

            # find the correct variable
            existing_vars: list[tuple[SimVariable, int]] = []
            for candidate, offset in var_candidates:
                if isinstance(candidate, SimStackVariable) and candidate.offset == stack_offset:
                    existing_vars.append((candidate, offset))
            variable = None
            if existing_vars:
                variable, _ = existing_vars[0]

            vs = None
            if stack_offset is not None:
                stack_addr = self.state.stack_addr_from_offset(stack_offset)
                if variable is None:
                    # TODO: how to determine the size for a lea?
                    try:
                        vs: MultiValues | None = self.state.stack_region.load(stack_addr, size=1)
                    except SimMemoryMissingError:
                        vs = None

                    if vs is not None:
                        # extract variables
                        for values in vs.values():
                            for v in values:
                                for var_stack_offset, var in self.state.extract_variables(v):
                                    existing_vars.append((var, var_stack_offset))

                    if not existing_vars:
                        # no variables exist
                        lea_size = 1
                        variable = SimStackVariable(
                            stack_offset,
                            lea_size,
                            base="bp",
                            ident=self.state.variable_manager[self.func_addr].next_variable_ident("stack"),
                            region=self.func_addr,
                        )
                        self.state.variable_manager[self.func_addr].add_variable("stack", stack_offset, variable)
                        l.debug("Identified a new stack variable %s at %#x.", variable, self.ins_addr)
                        existing_vars.append((variable, 0))

                    else:
                        # FIXME: Why is it only taking the first variable?
                        variable = next(iter(existing_vars))[0]

                # write the variable back to stack
                if vs is None:
                    top = self.state.top(self.project.arch.byte_width)
                    top = self.state.annotate_with_variables(top, [(0, variable)])
                    vs = MultiValues(top)
                self.state.stack_region.store(stack_addr, vs)

        elif self.state.is_global_variable_address(data):
            # this is probably an address for a global variable
            global_var_addr = data.concrete_value

            variable_manager = self.state.variable_manager["global"]

            # special case for global variables: find existing variable by base address
            existing_vars = [(var, 0) for var in variable_manager.get_global_variables(global_var_addr)]

            if not existing_vars:
                variable = SimMemoryVariable(
                    global_var_addr,
                    1,
                    ident=variable_manager.next_variable_ident("global"),
                )
                variable_manager.set_variable("global", global_var_addr, variable)
                l.debug("Identified a new global variable %s at %#x.", variable, self.ins_addr)
                existing_vars = [(variable, 0)]

        else:
            return []

        # record all variables
        for var, offset in existing_vars:
            if offset == 0:
                offset = None
            variable_manager.record_variable(codeloc, var, offset, atom=src_expr)

        return existing_vars

    def _reference(self, richr: RichR[claripy.ast.BV | claripy.ast.FP], codeloc: CodeLocation, src=None):
        data = richr.data

        if data is None:
            return

        if self.state.is_stack_address(data):
            # this is a stack address
            # extract stack offset
            stack_offset: int | None = self.state.get_stack_offset(data)

            variable_manager = self.state.variable_manager[self.func_addr]
            var_candidates: list[tuple[SimVariable, int]] = variable_manager.find_variables_by_stmt(
                self.block.addr,
                self.stmt_idx,
                "memory",
                block_idx=cast(ailment.Block, self.block).idx if isinstance(self.block, ailment.Block) else None,
            )

            # find the correct variable
            existing_vars: list[tuple[SimVariable, int]] = []
            for candidate, offset in var_candidates:
                if isinstance(candidate, SimStackVariable) and candidate.offset == stack_offset:
                    existing_vars.append((candidate, offset))
        elif self.state.is_global_variable_address(data):
            # this is probably an address for a global variable
            global_var_addr = data.concrete_value
            variable_manager = self.state.variable_manager["global"]
            # special case for global variables: find existing variable by base address
            existing_vars = [(var, 0) for var in variable_manager.get_global_variables(global_var_addr)]
        else:
            return

        if not existing_vars:
            # no associated variables. it's usually because _ensure_variable_existence() is not called, or the address
            # is a TOP. we ignore this case.
            return
        variable, _ = existing_vars[0]

        if not self.state.typevars.has_type_variable_for(variable):
            variable_typevar = typevars.TypeVariable()
            self.state.typevars.add_type_variable(variable, variable_typevar)
        # we do not add any type constraint here because we are not sure if the given memory address will ever be
        # accessed or not

        # invoke variable_manager.reference_at for every variable
        for var, offset in existing_vars:
            if offset == 0:
                offset = None
            variable_manager.reference_at(var, offset, codeloc, atom=src)

    def _assign_to_register(
        self, offset, richr, size, src=None, dst=None, create_variable: bool = True
    ):  # pylint:disable=unused-argument
        """

        :param int offset:
        :param RichR data:
        :param int size:
        :return:
        """

        if (
            offset in (self.project.arch.ip_offset, self.project.arch.sp_offset, self.project.arch.lr_offset)
            or not create_variable
        ):
            # only store the value. don't worry about variables.
            v = MultiValues(richr.data)
            self.state.register_region.store(offset, v)
            return

        codeloc: CodeLocation = self._codeloc()
        data = richr.data

        # lea
        self._ensure_variable_existence(richr, codeloc)
        self._reference(richr, codeloc)

        # handle register writes

        # first check if there is an existing variable for the atom at this location already
        existing_vars: set[tuple[SimVariable, int]] = self.state.variable_manager[
            self.func_addr
        ].find_variables_by_atom(self.block.addr, self.stmt_idx, dst)
        if not existing_vars:
            # next check if we are overwriting *part* of an existing variable that is not an input variable
            addr_and_variables = set()
            try:
                vs: MultiValues = self.state.register_region.load(
                    offset, size=size, endness=self.project.arch.register_endness
                )
                for values in vs.values():
                    for value in values:
                        addr_and_variables.update(self.state.extract_variables(value))
            except SimMemoryMissingError:
                pass
            input_vars = self.state.variable_manager[self.func_addr].input_variables()
            existing_vars = {
                (av[1], av[0]) for av in addr_and_variables if av[1] not in input_vars and av[1].size > size
            }

        if not existing_vars:
            variable = SimRegisterVariable(
                offset,
                size,
                ident=self.state.variable_manager[self.func_addr].next_variable_ident("register"),
                region=self.func_addr,
            )
            self.state.variable_manager[self.func_addr].add_variable("register", offset, variable)
        else:
            variable, _ = next(iter(existing_vars))

        # FIXME: The offset does not have to be 0
        annotated_data = self.state.annotate_with_variables(data, [(0, variable)])
        v = MultiValues(annotated_data)
        self.state.register_region.store(offset, v)
        # register with the variable manager
        self.state.variable_manager[self.func_addr].write_to(variable, None, codeloc, atom=dst, overwrite=False)

        if richr.typevar is not None:
            if not self.state.typevars.has_type_variable_for(variable):
                # assign a new type variable to it
                typevar = typevars.TypeVariable()
                self.state.typevars.add_type_variable(variable, typevar)
                # create constraints
            else:
                typevar = self.state.typevars.get_type_variable(variable)
            self.state.add_type_constraint(typevars.Subtype(richr.typevar, typevar))
            self.state.add_type_constraint(typevars.Subtype(typevar, typeconsts.int_type(variable.size * 8)))

    def _assign_to_vvar(
        self,
        vvar: ailment.expression.VirtualVariable,
        richr: RichR[claripy.ast.BV | claripy.ast.FP],
        src=None,
        dst=None,
        create_variable: bool = True,
        vvar_id: int | None = None,
    ):  # pylint:disable=unused-argument

        if vvar_id is None:
            vvar_id = vvar.varid

        if (
            vvar.category == ailment.expression.VirtualVariableCategory.REGISTER
            and vvar.oident in (self.project.arch.ip_offset, self.project.arch.sp_offset, self.project.arch.lr_offset)
        ) or not create_variable:
            # only store the value. don't worry about variables.
            self.vvar_region[vvar_id] = richr.data
            return None

        codeloc: CodeLocation = self._codeloc()
        data = richr.data

        # lea
        self._ensure_variable_existence(richr, codeloc)
        self._reference(richr, codeloc)

        # first check if there is an existing variable for the atom at this location already
        existing_vars: set[tuple[SimVariable, int]] = self.state.variable_manager[
            self.func_addr
        ].find_variables_by_atom(self.block.addr, self.stmt_idx, dst)
        if not existing_vars:
            # next check if there is already a variable for the vvar ID
            addr_and_variables = set()
            try:
                value = self.vvar_region[vvar_id]
                addr_and_variables.update(self.state.extract_variables(value))
            except KeyError:
                pass
            existing_vars = {(av[1], av[0]) for av in addr_and_variables}

        if not existing_vars:
            if vvar.was_reg:
                variable = SimRegisterVariable(
                    vvar.reg_offset,
                    vvar.size,
                    ident=self.state.variable_manager[self.func_addr].next_variable_ident("register"),
                    region=self.func_addr,
                )
                self.state.variable_manager[self.func_addr].add_variable("register", vvar.reg_offset, variable)
            elif vvar.was_stack:
                variable = SimStackVariable(
                    vvar.stack_offset,
                    vvar.size,
                    ident=self.state.variable_manager[self.func_addr].next_variable_ident("stack"),
                    region=self.func_addr,
                    base="bp",
                )
                self.state.variable_manager[self.func_addr].add_variable("stack", vvar.stack_offset, variable)
            elif vvar.was_parameter:
                # FIXME: we assume all parameter vvars were registers
                variable = SimRegisterVariable(
                    vvar.reg_offset,
                    vvar.size,
                    ident=self.state.variable_manager[self.func_addr].next_variable_ident("register"),
                    region=self.func_addr,
                )
                self.state.variable_manager[self.func_addr].add_variable("register", vvar.oident, variable)
            elif vvar.was_tmp:
                # FIXME: we treat all tmp vvars as registers
                assert vvar.tmp_idx is not None
                variable = SimRegisterVariable(
                    4096 + vvar.tmp_idx,
                    vvar.size,
                    ident=self.state.variable_manager[self.func_addr].next_variable_ident("register"),
                    region=self.func_addr,
                )
            else:
                raise NotImplementedError
        else:
            variable, _ = next(iter(existing_vars))

        # FIXME: The offset does not have to be 0
        annotated_data = self.state.annotate_with_variables(data, [(0, variable)])
        self.vvar_region[vvar_id] = annotated_data
        self.state.variable_manager[self.func_addr].write_to(variable, None, codeloc, atom=dst, overwrite=False)

        if richr.typevar is not None:
            if not self.state.typevars.has_type_variable_for(variable):
                # optimization: if richr.typevar is a derived typevar, we simply carry it over instead of creating a
                # new typevar here
                # this is because the solver does not support constraints like tv_1 <: tv_2.+1; we replace it with
                # tv_1 = tv_2.+1
                if isinstance(richr.typevar, typevars.DerivedTypeVariable):
                    typevar = richr.typevar
                else:
                    typevar = typevars.TypeVariable()
                self.state.typevars.add_type_variable(variable, typevar)
            else:
                typevar = self.state.typevars.get_type_variable(variable)

            # create constraints accordingly
            if richr.typevar is not typevar:
                self.state.add_type_constraint(typevars.Subtype(richr.typevar, typevar))
            if vvar.varid in self.vvar_type_hints:
                # handle type hints
                self.state.add_type_constraint(typevars.Subtype(typevar, self.vvar_type_hints[vvar.varid]))
            else:
                # the constraint below is a default constraint that may conflict with more specific ones with different
                # sizes; we post-process at the very end of VRA to remove conflicting default constraints.
                self.state.add_type_constraint(typevars.Subtype(typevar, typeconsts.int_type(variable.size * 8)))

        return variable

    def _store(
        self, richr_addr: RichR[claripy.ast.BV], data: RichR[claripy.ast.BV | claripy.ast.FP], size, atom=None
    ):  # pylint:disable=unused-argument
        """

        :param RichR addr:
        :param RichR data:
        :param int size:
        :return:
        """

        addr = richr_addr.data
        stored = False

        if addr.concrete:
            # fully concrete. this is a global address
            self._store_to_global(addr.concrete_value, data, size, stmt=atom)
            stored = True
        elif self._addr_has_concrete_base(addr) and (parsed := self._parse_offsetted_addr(addr)) is not None:
            # we are storing to a concrete global address with an offset
            base_addr, offset, elem_size = parsed
            self._store_to_global(base_addr.concrete_value, data, size, stmt=atom, offset=offset, elem_size=elem_size)
            stored = True
        else:
            if self.state.is_stack_address(addr):
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    # fast path: Storing data to stack
                    self._store_to_stack(stack_offset, data, size, atom=atom)
                    stored = True

        if not stored:
            # remove existing variables linked to this statement
            existing_vars = self.state.variable_manager[self.func_addr].find_variables_by_stmt(
                self.block.addr, self.stmt_idx, "memory"
            )
            codeloc = self._codeloc()
            if existing_vars:
                for existing_var, _ in list(existing_vars):
                    self.state.variable_manager[self.func_addr].remove_variable_by_atom(codeloc, existing_var, atom)

            # storing to a location specified by a pointer whose value cannot be determined at this point
            self._store_to_variable(richr_addr, data, size)

    def _store_to_stack(
        self, stack_offset, data: RichR[claripy.ast.BV | claripy.ast.FP], size, offset=0, atom=None, endness=None
    ):
        if atom is None:
            existing_vars = self.state.variable_manager[self.func_addr].find_variables_by_stmt(
                self.block.addr, self.stmt_idx, "memory"
            )
        else:
            existing_vars = self.state.variable_manager[self.func_addr].find_variables_by_atom(
                self.block.addr, self.stmt_idx, atom
            )
        if not existing_vars:
            variable = SimStackVariable(
                stack_offset,
                size,
                base="bp",
                ident=self.state.variable_manager[self.func_addr].next_variable_ident("stack"),
                region=self.func_addr,
            )
            variable_offset = offset
            if isinstance(stack_offset, int):
                self.state.variable_manager[self.func_addr].set_variable("stack", stack_offset, variable)
                l.debug("Identified a new stack variable %s at %#x.", variable, self.ins_addr)

        else:
            variable, variable_offset = next(iter(existing_vars))

        if isinstance(stack_offset, int):
            expr = self.state.annotate_with_variables(data.data, [(variable_offset, variable)])
            stack_addr = self.state.stack_addr_from_offset(stack_offset)
            self.state.stack_region.store(stack_addr, expr, endness=endness)

            codeloc = CodeLocation(
                self.block.addr, self.stmt_idx, ins_addr=self.ins_addr, block_idx=getattr(self.block, "idx", None)
            )

            addr_and_variables = set()
            try:
                vs: MultiValues = self.state.stack_region.load(stack_addr, size, endness=endness)
                for values in vs.values():
                    for value in values:
                        addr_and_variables.update(self.state.extract_variables(value))
            except SimMemoryMissingError:
                pass

            for var_offset, var in addr_and_variables:
                offset_into_var = var_offset
                if offset_into_var == 0:
                    offset_into_var = None
                self.state.variable_manager[self.func_addr].write_to(
                    var,
                    offset_into_var,
                    codeloc,
                    atom=atom,
                )

            # create type constraints
            if data.typevar is not None:
                if not self.state.typevars.has_type_variable_for(variable):
                    typevar = typevars.TypeVariable()
                    self.state.typevars.add_type_variable(variable, typevar)
                else:
                    typevar = self.state.typevars.get_type_variable(variable)
                if typevar is not None:
                    self.state.add_type_constraint(typevars.Subtype(data.typevar, typevar))
        # TODO: Create a tv_sp.store.<bits>@N <: typevar type constraint for the stack pointer

    def _store_to_global(
        self,
        addr: int,
        data: RichR,
        size: int,
        stmt=None,
        offset: claripy.ast.BV | None = None,
        elem_size: int | None = None,
    ):
        variable_manager = self.state.variable_manager["global"]
        if stmt is None:
            existing_vars = variable_manager.find_variables_by_stmt(self.block.addr, self.stmt_idx, "memory")
        else:
            existing_vars = variable_manager.find_variables_by_atom(self.block.addr, self.stmt_idx, stmt)

        if offset is None or elem_size is None:
            # trivial case
            abs_addr = addr
        elif offset.concrete:
            abs_addr = addr + offset.concrete_value * elem_size
        else:
            abs_addr = None

        if not existing_vars:
            # special case for global variables: find existing variable by base address
            existing_vars = {(var, (offset, elem_size)) for var in variable_manager.get_global_variables(addr)}

        if not existing_vars:
            variable = SimMemoryVariable(
                addr,
                size,
                ident=variable_manager.next_variable_ident("global"),
            )
            variable_manager.set_variable("global", addr, variable)
            l.debug("Identified a new global variable %s at %#x.", variable, self.ins_addr)
            existing_vars = {(variable, (offset, elem_size))}
        else:
            variable, _ = next(iter(existing_vars))

        data_expr: claripy.ast.Base = data.data
        data_expr = self.state.annotate_with_variables(data_expr, [(0, variable)])

        if abs_addr is not None:
            self.state.global_region.store(
                addr, data_expr, endness=self.project.arch.memory_endness if stmt is None else stmt.endness
            )

        codeloc = CodeLocation(
            self.block.addr, self.stmt_idx, ins_addr=self.ins_addr, block_idx=getattr(self.block, "idx", None)
        )
        values: MultiValues | None = None
        if abs_addr is not None:
            with contextlib.suppress(SimMemoryMissingError):
                values = self.state.global_region.load(
                    abs_addr, size=size, endness=self.project.arch.memory_endness if stmt is None else stmt.endness
                )

        if values is not None:
            for vs in values.values():
                for v in vs:
                    for var_offset, var in self.state.extract_variables(v):
                        variable_manager.write_to(var, var_offset, codeloc, atom=stmt)
        else:
            for var, var_offset in existing_vars:
                variable_manager.write_to(var, var_offset, codeloc, atom=stmt)

        # create type constraints
        if not self.state.typevars.has_type_variable_for(variable):
            typevar = typevars.TypeVariable()
            self.state.typevars.add_type_variable(variable, typevar)
        else:
            typevar = self.state.typevars.get_type_variable(variable)

        if offset is not None and elem_size is not None:
            # it's an array!
            if offset.concrete:
                concrete_offset = offset.concrete_value * elem_size
                store_typevar = self._create_access_typevar(typevar, True, size, concrete_offset)
                self.state.add_type_constraint(typevars.Subtype(store_typevar, typeconsts.TopType()))
            else:
                store_typevar = self._create_access_typevar(typevar, True, size, 0)
                self.state.add_type_constraint(typevars.Subtype(store_typevar, typeconsts.TopType()))
            # FIXME: This is a hack so that we can interpret the target as an array
            is_array = typevars.DerivedTypeVariable(typevar, typevars.IsArray())
            self.state.add_type_constraint(typevars.Existence(is_array))

            if data.typevar is not None:
                self.state.add_type_constraint(typevars.Subtype(data.typevar, store_typevar))

        else:
            # it's just a variable
            # however, since it's a global address, we still treat it as writing to a location
            if data.typevar is not None:
                store_typevar = self._create_access_typevar(typevar, True, size, 0)
                self.state.add_type_constraint(typevars.Subtype(store_typevar, typeconsts.TopType()))
                self.state.add_type_constraint(typevars.Subtype(data.typevar, store_typevar))

    def _store_to_variable(self, richr_addr: RichR[claripy.ast.BV], data: RichR, size: int):
        # Storing data into a pointer
        if richr_addr.type_constraints:
            for tc in richr_addr.type_constraints:
                self.state.add_type_constraint(tc)

        typevar = typevars.TypeVariable() if richr_addr.typevar is None else richr_addr.typevar

        if isinstance(typevar, typevars.TypeVariable):
            if isinstance(typevar, typevars.DerivedTypeVariable) and isinstance(typevar.one_label, typevars.AddN):
                base_typevar = typevar.type_var
                field_offset = typevar.one_label.n
            else:
                base_typevar = typevar
                field_offset = 0

            store_typevar = self._create_access_typevar(base_typevar, True, size, field_offset)
            data_typevar = data.typevar if data.typevar is not None else typeconsts.TopType()
            self.state.add_type_constraint(typevars.Subtype(store_typevar, data_typevar))

    def _load(self, richr_addr: RichR[claripy.ast.BV], size: int, expr=None):
        """

        :param RichR richr_addr:
        :param size:
        :return:
        """

        addr = cast(claripy.ast.BV, richr_addr.data)
        codeloc = CodeLocation(
            self.block.addr, self.stmt_idx, ins_addr=self.ins_addr, block_idx=getattr(self.block, "idx", None)
        )
        typevar = None
        v = None

        if self.state.is_stack_address(addr):
            stack_offset = self.state.get_stack_offset(addr)
            if stack_offset is not None:
                # Loading data from stack

                # split the offset into a concrete offset and a dynamic offset
                # the stack offset may not be a concrete offset
                # for example, SP-0xe0+var_1
                if type(stack_offset) is ArithmeticExpression:
                    if type(stack_offset.operands[0]) is int:
                        concrete_offset = stack_offset.operands[0]
                        dynamic_offset = stack_offset.operands[1]
                    elif type(stack_offset.operands[1]) is int:
                        concrete_offset = stack_offset.operands[1]
                        dynamic_offset = stack_offset.operands[0]
                    else:
                        # cannot determine the concrete offset. give up
                        concrete_offset = None
                        dynamic_offset = stack_offset
                else:
                    # | type(stack_offset) is int
                    concrete_offset = stack_offset
                    dynamic_offset = None

                if concrete_offset is not None:
                    try:
                        values: MultiValues | None = self.state.stack_region.load(
                            self.state.stack_addr_from_offset(concrete_offset),
                            size=size,
                            endness=self.project.arch.memory_endness,
                        )

                    except SimMemoryMissingError:
                        values = None
                else:
                    values = None

                all_vars: set[tuple[int, SimVariable]] = set()
                if values:
                    for vs in values.values():
                        for v in vs:
                            for _, var_ in self.state.extract_variables(v):
                                if isinstance(var_, SimStackVariable):
                                    var_offset = stack_offset - var_.offset
                                    all_vars.add((var_offset, var_))

                if not all_vars and concrete_offset is not None:
                    variables = self.state.variable_manager[self.func_addr].find_variables_by_stack_offset(
                        concrete_offset
                    )
                    if not variables:
                        variable = SimStackVariable(
                            concrete_offset,
                            size,
                            base="bp",
                            ident=self.state.variable_manager[self.func_addr].next_variable_ident("stack"),
                            region=self.func_addr,
                        )
                        self.state.variable_manager[self.func_addr].add_variable("stack", concrete_offset, variable)
                        variables = {variable}
                        l.debug("Identified a new stack variable %s at %#x.", variable, self.ins_addr)
                    for variable in variables:
                        v = self.state.top(size * self.project.arch.byte_width)
                        v = self.state.annotate_with_variables(v, [(0, variable)])
                        stack_addr = self.state.stack_addr_from_offset(concrete_offset)
                        self.state.stack_region.store(stack_addr, v, endness=self.project.arch.memory_endness)

                    all_vars = {(0, variable) for variable in variables}

                all_vars_list = sorted(all_vars, key=lambda val: (val[0], val[1].key), reverse=True)

                if len(all_vars_list) > 1:
                    l.warning(
                        "Reading memory with overlapping variables: %s. Ignoring all but the first one.", all_vars_list
                    )

                var_offset, var = all_vars_list[0]  # won't fail
                # calculate variable_offset
                if dynamic_offset is None:
                    offset_into_variable = var_offset
                else:
                    if var_offset == 0:
                        offset_into_variable = dynamic_offset
                    else:
                        offset_into_variable = ArithmeticExpression(
                            ArithmeticExpression.Add,
                            (
                                dynamic_offset,
                                var_offset,
                            ),
                        )
                self.state.variable_manager[self.func_addr].read_from(
                    var,
                    offset_into_variable,
                    codeloc,
                    atom=expr,
                    # overwrite=True
                )

                if var.size == size:
                    # add delayed type constraints
                    if var in self.state.delayed_type_constraints:
                        for constraint in self.state.delayed_type_constraints[var]:
                            self.state.add_type_constraint(constraint)
                        self.state.delayed_type_constraints.pop(var)

                    # create type constraints
                    if not self.state.typevars.has_type_variable_for(var):
                        typevar = typevars.TypeVariable()
                        self.state.typevars.add_type_variable(var, typevar)
                    else:
                        typevar = self.state.typevars.get_type_variable(var)

                else:
                    typevar = typevars.TypeVariable()
                    self.state.add_type_constraint(typevars.Subtype(typeconsts.int_type(size * 8), typevar))

                # | TODO: Create a tv_sp.load.<bits>@N type variable for the stack variable
                # | typevar = typevars.DerivedTypeVariable(
                # |    typevars.DerivedTypeVariable(typevar, typevars.Load()),
                # |    typevars.HasField(size * 8, 0)
                # | )

                r = self.state.top(size * self.project.arch.byte_width)
                r = self.state.annotate_with_variables(r, all_vars_list)
                return RichR(r, variable=var, typevar=typevar)

        elif addr.concrete:
            # Loading data from memory
            v = self._load_from_global(addr.concrete_value, size, expr=expr)
            typevar = v.typevar

        elif self._addr_has_concrete_base(addr) and (parsed := self._parse_offsetted_addr(addr)) is not None:
            # Loading data from a memory address with an offset
            base_addr, offset, elem_size = parsed
            v = self._load_from_global(base_addr.concrete_value, size, expr=expr, offset=offset, elem_size=elem_size)
            typevar = v.typevar

        if v is None and expr is not None:
            # failed to map the address to a known variable
            # remove existing variables linked to this variable
            existing_vars = self.state.variable_manager[self.func_addr].find_variables_by_atom(
                self.block.addr, self.stmt_idx, expr
            )
            if existing_vars:
                for existing_var, _ in list(existing_vars):
                    self.state.variable_manager[self.func_addr].remove_variable_by_atom(codeloc, existing_var, expr)

        # Loading data from a pointer
        if richr_addr.type_constraints:
            for tc in richr_addr.type_constraints:
                self.state.add_type_constraint(tc)

        # parse the loading offset
        offset = 0
        if isinstance(richr_addr.typevar, typevars.DerivedTypeVariable) and isinstance(
            richr_addr.typevar.one_label, typevars.AddN
        ):
            offset = richr_addr.typevar.one_label.n
            richr_addr_typevar = richr_addr.typevar.type_var  # unpack
        else:
            richr_addr_typevar = richr_addr.typevar

        if isinstance(richr_addr_typevar, typevars.TypeVariable):
            # ensure it's not a type constant, and then we create a type constraint for this typevar
            typevar = self._create_access_typevar(richr_addr_typevar, False, size, offset)
            self.state.add_type_constraint(typevars.Subtype(typevar, typeconsts.TopType()))

        return RichR(self.state.top(size * self.project.arch.byte_width), typevar=typevar)

    def _load_from_global(
        self,
        addr: int,
        size,
        expr=None,
        offset: claripy.ast.BV | None = None,
        elem_size: int | None = None,
    ) -> RichR[claripy.ast.BV]:
        variable_manager = self.state.variable_manager["global"]
        if expr is None:
            existing_vars = variable_manager.find_variables_by_stmt(self.block.addr, self.stmt_idx, "memory")
        else:
            existing_vars = variable_manager.find_variables_by_atom(self.block.addr, self.stmt_idx, expr)

        # if offset is None or elem_size is None:
        #     # trivial case
        #     abs_addr = addr
        # elif offset.concrete and elem_size.concrete:
        #     abs_addr = addr + offset.concrete_value * elem_size.concrete_value
        # else:
        #     abs_addr = None

        if not existing_vars:
            # special case for global variables: find existing variable by base address
            existing_vars = {(var, (offset, elem_size)) for var in variable_manager.get_global_variables(addr)}

        if not existing_vars:
            # is this address mapped?
            if self.project.loader.find_object_containing(addr) is None:
                return RichR(self.state.top(size * self.project.arch.byte_width))
            variable = SimMemoryVariable(
                addr,
                size,
                ident=variable_manager.next_variable_ident("global"),
            )
            variable_manager.add_variable("global", addr, variable)
            l.debug("Identified a new global variable %s at %#x.", variable, self.ins_addr)
            existing_vars = {(variable, (offset, elem_size))}

        codeloc = CodeLocation(
            self.block.addr, self.stmt_idx, ins_addr=self.ins_addr, block_idx=getattr(self.block, "idx", None)
        )
        for variable, _ in existing_vars:
            variable_manager.read_from(variable, None, codeloc, atom=expr)

        variable, _ = next(iter(existing_vars))
        # create type constraints
        if not self.state.typevars.has_type_variable_for(variable):
            typevar = typevars.TypeVariable()
            self.state.typevars.add_type_variable(variable, typevar)
        else:
            typevar = self.state.typevars.get_type_variable(variable)

        if offset is not None and elem_size is not None:
            # it's an array!
            if offset.concrete:
                concrete_offset = offset.concrete_value * elem_size
                load_typevar = self._create_access_typevar(typevar, False, size, concrete_offset)
                self.state.add_type_constraint(typevars.Subtype(load_typevar, typeconsts.TopType()))
            else:
                # FIXME: This is a hack
                for i in range(4):
                    concrete_offset = size * i
                    load_typevar = self._create_access_typevar(typevar, False, size, concrete_offset)
                    self.state.add_type_constraint(typevars.Subtype(load_typevar, typeconsts.TopType()))

        return RichR(self.state.top(size * self.project.arch.byte_width), typevar=typevar)

    def _read_from_register(self, offset, size, expr=None, force_variable_size=None, create_variable: bool = True):
        """

        :param offset:
        :param size:
        :return:
        """

        codeloc = self._codeloc()

        try:
            values: MultiValues | None = self.state.register_region.load(offset, size=size)
        except SimMemoryMissingError:
            values = None

        if offset in (self.project.arch.sp_offset, self.project.arch.ip_offset):
            # load values. don't worry about variables
            if values is None:
                r_value = self.state.top(size * self.project.arch.byte_width)
            else:
                r_value = next(iter(next(iter(values.values()))))
            return RichR(r_value, variable=None, typevar=None)

        if not values:
            # the value does not exist.
            value = self.state.top(size * self.project.arch.byte_width)
            if create_variable:
                # create a new variable if necessary

                # check if there is an existing variable for the atom at this location already
                existing_vars: set[tuple[SimVariable, int]] = self.state.variable_manager[
                    self.func_addr
                ].find_variables_by_atom(self.block.addr, self.stmt_idx, expr)
                if not existing_vars:
                    variable = SimRegisterVariable(
                        offset,
                        size if force_variable_size is None else force_variable_size,
                        ident=self.state.variable_manager[self.func_addr].next_variable_ident("register"),
                        region=self.func_addr,
                    )
                    self.state.variable_manager[self.func_addr].add_variable("register", offset, variable)
                else:
                    variable = next(iter(existing_vars))[0]
                value = self.state.annotate_with_variables(value, [(0, variable)])
            self.state.register_region.store(offset, value)
            value_list = [{value}]
        else:
            value_list = list(values.values())

        variable_set = set()
        for value_set in value_list:
            for value in value_set:
                for _, var in self.state.extract_variables(value):
                    self.state.variable_manager[self.func_addr].read_from(
                        var, None, codeloc, atom=expr, overwrite=False
                    )
                    variable_set.add(var)

        if offset == self.project.arch.sp_offset:
            # ignore sp
            typevar = None
            var = None
        else:
            # we accept the precision loss here by only returning the first variable
            # FIXME: Multiple variables
            typevar = None
            var = None
            if variable_set:
                var = next(iter(variable_set))

                # add delayed type constraints
                if var in self.state.delayed_type_constraints:
                    for constraint in self.state.delayed_type_constraints[var]:
                        self.state.add_type_constraint(constraint)
                    self.state.delayed_type_constraints.pop(var)

                if var not in self.state.typevars:
                    typevar = typevars.TypeVariable()
                    self.state.typevars.add_type_variable(var, typevar)
                else:
                    # FIXME: This is an extremely stupid hack. Fix it later.
                    # | typevar = next(reversed(list(self.state.typevars[var].values())))
                    typevar = self.state.typevars[var]

        r_value = (
            next(iter(value_list[0])) if len(value_list) == 1 else self.state.top(size * self.project.arch.byte_width)
        )  # fall back to top
        if var is not None and var.size != size:
            # ignore the variable and the associated type if we are only reading part of the variable
            return RichR(r_value, variable=var)
        return RichR(r_value, variable=var, typevar=typevar)

    def _read_from_vvar(
        self,
        vvar: ailment.expression.VirtualVariable,
        expr=None,
        create_variable: bool = True,
        vvar_id: int | None = None,
    ):
        codeloc = self._codeloc()

        if vvar_id is None:
            vvar_id = vvar.varid

        value: claripy.ast.BV | None = self.vvar_region.get(vvar_id, None)

        # fallback for register arguments
        if value is None and vvar.was_reg:
            return self._read_from_register(vvar.reg_offset, vvar.size, expr=vvar, create_variable=True)

        if vvar.category == ailment.Expr.VirtualVariableCategory.REGISTER and vvar.oident in (
            self.project.arch.sp_offset,
            self.project.arch.ip_offset,
        ):
            # load values. don't worry about variables
            r_value = self.state.top(vvar.size) if value is None else value
            return RichR(r_value, variable=None, typevar=None)

        if value is None:
            # the value does not exist.
            value = self.state.top(vvar.bits)
            if create_variable:
                # create a new variable if necessary
                if vvar.category == ailment.Expr.VirtualVariableCategory.REGISTER:
                    variable = SimRegisterVariable(
                        vvar.reg_offset,
                        vvar.size,
                        ident=self.state.variable_manager[self.func_addr].next_variable_ident("register"),
                        region=self.func_addr,
                    )
                    value = self.state.annotate_with_variables(value, [(0, variable)])
                    self.state.variable_manager[self.func_addr].add_variable("register", vvar.reg_offset, variable)
                elif vvar.category == ailment.Expr.VirtualVariableCategory.STACK:
                    variable = SimStackVariable(
                        vvar.stack_offset,
                        vvar.size,
                        ident=self.state.variable_manager[self.func_addr].next_variable_ident("stack"),
                        region=self.func_addr,
                        base="bp",
                    )
                    value = self.state.annotate_with_variables(value, [(0, variable)])
                    self.state.variable_manager[self.func_addr].add_variable("stack", vvar.stack_offset, variable)
                elif vvar.category == ailment.Expr.VirtualVariableCategory.PARAMETER:
                    raise KeyError(f"Missing virtual variable for parameter {vvar}")
                elif vvar.category == ailment.Expr.VirtualVariableCategory.TMP:
                    # we don't track variables for tmps
                    pass
                else:
                    raise NotImplementedError

            self.vvar_region[vvar_id] = value

        variable_set = set()
        for _, var in self.state.extract_variables(value):
            self.state.variable_manager[self.func_addr].read_from(var, None, codeloc, atom=expr, overwrite=False)
            variable_set.add(var)

        if (
            vvar.category == ailment.Expr.VirtualVariableCategory.REGISTER
            and vvar.oident == self.project.arch.sp_offset
        ):
            # ignore sp
            typevar = None
            var = None
        else:
            # we accept the precision loss here by only returning the first variable
            # FIXME: Multiple variables
            typevar = None
            var = None
            if variable_set:
                var = next(iter(variable_set))

                # add delayed type constraints
                if var in self.state.delayed_type_constraints:
                    for constraint in self.state.delayed_type_constraints[var]:
                        self.state.add_type_constraint(constraint)
                    self.state.delayed_type_constraints.pop(var)

                if var not in self.state.typevars:
                    typevar = typevars.TypeVariable()
                    self.state.typevars.add_type_variable(var, typevar)
                else:
                    # FIXME: This is an extremely stupid hack. Fix it later.
                    # | typevar = next(reversed(list(self.state.typevars[var].values())))
                    typevar = self.state.typevars[var]

        if var is not None and var.size != vvar.size:
            # ignore the variable and the associated type if we are only reading part of the variable
            return RichR(value, variable=var)

        # handle type hints
        if vvar.varid in self.vvar_type_hints:
            assert isinstance(typevar, typevars.TypeVariable)
            self.state.add_type_constraint(typevars.Subtype(typevar, self.vvar_type_hints[vvar.varid]))

        return RichR(value, variable=var, typevar=typevar)

    def _create_access_typevar(
        self,
        typevar: TypeVariable | DerivedTypeVariable,
        is_store: bool,
        size: int | None,
        offset: int,
    ) -> DerivedTypeVariable:
        if isinstance(typevar, DerivedTypeVariable):
            if isinstance(typevar.labels[-1], AddN):
                offset += typevar.labels[-1].n
                if len(typevar.labels) == 1:
                    typevar = typevar.type_var
                else:
                    typevar = typevars.new_dtv(typevar.type_var, labels=typevar.labels[:-1])
            elif isinstance(typevar.labels[-1], SubN):
                offset -= typevar.labels[-1].n
                if len(typevar.labels) == 1:
                    typevar = typevar.type_var
                else:
                    typevar = typevars.new_dtv(typevar.type_var, labels=typevar.labels[:-1])
        lbl = Store() if is_store else Load()
        bits = size * self.project.arch.byte_width if size is not None else MAX_POINTSTO_BITS
        return DerivedTypeVariable(
            typevar,
            None,
            labels=(lbl, typevars.HasField(bits, offset)),
        )
