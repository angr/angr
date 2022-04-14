from typing import Optional, Set, List, Tuple, TYPE_CHECKING
import logging

import claripy

from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...engines.light import SimEngineLight, ArithmeticExpression
from ...errors import SimEngineError, SimMemoryMissingError
from ...sim_variable import SimVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from ...code_location import CodeLocation
from ..typehoon import typevars, typeconsts

if TYPE_CHECKING:
    from .variable_recovery_base import VariableRecoveryStateBase
    from angr.knowledge_plugins.variables.variable_manager import VariableManager

#
# The base engine used in VariableRecoveryFast
#

l = logging.getLogger(name=__name__)


class RichR:
    """
    A rich representation of calculation results. The variable recovery data domain.
    """

    __slots__ = ('data', 'variable', 'typevar', 'type_constraints', )

    def __init__(self, data: claripy.ast.Base, variable=None, typevar: Optional[typevars.TypeVariable]=None,
                 type_constraints=None):
        self.data: claripy.ast.Base = data
        self.variable = variable
        self.typevar = typevar
        self.type_constraints = type_constraints

    @property
    def bits(self):
        if self.data is not None and not isinstance(self.data, (int, float)):
            if isinstance(self.data, claripy.ast.Base):
                return self.data.size()
            return self.data.bits
        if self.variable is not None:
            return self.variable.bits
        return None

    def __repr__(self):
        return "R{%r}" % self.data


class SimEngineVRBase(SimEngineLight):
    """
    The base class for variable recovery analyses. Contains methods for basic interactions with the state, like loading
    and storing data.
    """

    state: 'VariableRecoveryStateBase'

    def __init__(self, project, kb):
        super().__init__()

        self.project = project
        self.kb = kb
        self.variable_manager: Optional['VariableManager'] = None

    @property
    def func_addr(self):
        if self.state is None:
            return None
        return self.state.function.addr

    def process(self, state, *args, **kwargs):  # pylint:disable=unused-argument

        self.variable_manager = state.variable_manager

        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False) is True:
                raise e

    def _process(self, state, successors, block=None, func_addr=None):  # pylint:disable=unused-argument,arguments-differ
        super()._process(state, successors, block=block)

    #
    # Address parsing
    #

    @staticmethod
    def _addr_has_concrete_base(addr: claripy.ast.BV) -> bool:
        if addr.op == "__add__":
            if len(addr.args) == 2:
                if addr.args[0].concrete:
                    return True
                if addr.args[1].concrete:
                    return True
        return False

    @staticmethod
    def _parse_offseted_addr(addr: claripy.ast.BV) -> Optional[Tuple[claripy.ast.BV,claripy.ast.BV,claripy.ast.BV]]:
        if addr.op == "__add__":
            if len(addr.args) == 2:
                concrete_base, byte_offset = None, None
                if addr.args[0].concrete:
                    concrete_base, byte_offset = addr.args
                elif addr.args[1].concrete:
                    concrete_base, byte_offset = addr.args[1], addr.args[0]
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
                    if abs_offset.op == "__lshift__" and abs_offset.args[1].concrete:
                        offset = abs_offset.args[0]
                        elem_size = 2 ** abs_offset.args[1]._model_concrete.value

                if base_addr is not None and offset is not None and elem_size is not None:
                    return base_addr, offset, elem_size
        return None

    #
    # Logic
    #

    def _reference(self, richr: RichR, codeloc: CodeLocation, src=None):
        data: claripy.ast.Base = richr.data

        if data is None:
            return

        if self.state.is_stack_address(data):
            # this is a stack address
            # extract stack offset
            stack_offset: Optional[int] = self.state.get_stack_offset(data)

            variable_manager = self.variable_manager[self.func_addr]
            var_candidates: List[Tuple[SimVariable, int]] = variable_manager.find_variables_by_stmt(
                self.block.addr,
                self.stmt_idx,
                'memory')

            # find the correct variable
            existing_vars: List[Tuple[SimVariable, int]] = []
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
                        vs: Optional[MultiValues] = self.state.stack_region.load(stack_addr, size=1)
                    except SimMemoryMissingError:
                        vs = None

                    if vs is not None:
                        # extract variables
                        for values in vs.values.values():
                            for v in values:
                                for var_stack_offset, var in self.state.extract_variables(v):
                                    existing_vars.append((var, var_stack_offset))

                    if not existing_vars:
                        # no variables exist
                        lea_size = 1
                        variable = SimStackVariable(stack_offset, lea_size, base='bp',
                                                    ident=self.variable_manager[self.func_addr].next_variable_ident(
                                                        'stack'),
                                                    region=self.func_addr,
                                                    )
                        self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)
                        l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)
                        existing_vars.append((variable, 0))

                    else:
                        # FIXME: Why is it only taking the first variable?
                        variable = next(iter(existing_vars))[0]

                # write the variable back to stack
                if vs is None:
                    top = self.state.top(self.arch.byte_width)
                    top = self.state.annotate_with_variables(top, [(0, variable)])
                    vs = MultiValues(offset_to_values={0: {top}})
                self.state.stack_region.store(stack_addr, vs)

        elif self.state.is_global_variable_address(data):
            # this is probably an address for a global variable
            global_var_addr = data._model_concrete.value

            variable_manager = self.variable_manager['global']

            # special case for global variables: find existing variable by base address
            existing_vars = list((var, 0) for var in variable_manager.get_global_variables(global_var_addr))

            if not existing_vars:
                variable = SimMemoryVariable(global_var_addr, 1,
                                             ident=variable_manager.next_variable_ident('global'),
                                             )
                variable_manager.set_variable('global', global_var_addr, variable)
                l.debug('Identified a new global variable %s at %#x.', variable, self.ins_addr)
                existing_vars = [ (variable, 0) ]
            else:
                variable, _ = next(iter(existing_vars))

        else:
            return

        if not self.state.typevars.has_type_variable_for(variable, codeloc):
            variable_typevar = typevars.TypeVariable()
            self.state.typevars.add_type_variable(variable, codeloc, variable_typevar)
        # we do not add any type constraint here because we are not sure if the given memory address will ever be
        # accessed or not

        # find all variables
        for var, offset in existing_vars:
            if offset == 0:
                offset = None
            variable_manager.reference_at(var, offset, codeloc, atom=src)

    def _assign_to_register(self, offset, richr, size, src=None, dst=None):
        """

        :param int offset:
        :param RichR data:
        :param int size:
        :return:
        """

        if offset in (self.arch.ip_offset, self.arch.sp_offset, self.arch.lr_offset):
            # only store the value. don't worry about variables.
            v = MultiValues(offset_to_values={0: {richr.data}})
            self.state.register_region.store(offset, v)
            return

        codeloc: CodeLocation = self._codeloc()
        data: claripy.ast.Base = richr.data

        # lea
        self._reference(richr, codeloc, src=src)

        # handle register writes
        existing_vars = self.variable_manager[self.func_addr].find_variables_by_atom(self.block.addr, self.stmt_idx,
                                                                                     dst)
        existing_vars: Set[Tuple[SimVariable,int]]
        if not existing_vars:
            variable = SimRegisterVariable(offset, size,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident(
                                               'register'),
                                           region=self.func_addr
                                           )
            self.variable_manager[self.func_addr].set_variable('register', offset, variable)
        else:
            variable, _ = next(iter(existing_vars))

        # FIXME: The offset does not have to be 0
        annotated_data = self.state.annotate_with_variables(data, [(0, variable)])
        v = MultiValues(offset_to_values={0: {annotated_data}})
        self.state.register_region.store(offset, v)
        # register with the variable manager
        self.variable_manager[self.func_addr].write_to(variable, None, codeloc, atom=dst)

        if richr.typevar is not None:
            if not self.state.typevars.has_type_variable_for(variable, codeloc):
                # assign a new type variable to it
                typevar = typevars.TypeVariable()
                self.state.typevars.add_type_variable(variable, codeloc, typevar)
                # create constraints
            else:
                typevar = self.state.typevars.get_type_variable(variable, codeloc)
            self.state.add_type_constraint(typevars.Subtype(richr.typevar, typevar))
            self.state.add_type_constraint(typevars.Subtype(typevar, typeconsts.int_type(variable.size * 8)))

    def _store(self, richr_addr: RichR, data: RichR, size, stmt=None):  # pylint:disable=unused-argument
        """

        :param RichR addr:
        :param RichR data:
        :param int size:
        :return:
        """

        addr: claripy.ast.Base = richr_addr.data
        stored = False

        if addr.concrete:
            # fully concrete. this is a global address
            self._store_to_global(addr._model_concrete.value, data, size, stmt=stmt)
            stored = True
        elif self._addr_has_concrete_base(addr) and self._parse_offseted_addr(addr) is not None:
            # we are storing to a concrete global address with an offset
            base_addr, offset, elem_size = self._parse_offseted_addr(addr)
            self._store_to_global(base_addr._model_concrete.value, data, size,
                                  stmt=stmt, offset=offset, elem_size=elem_size)
            stored = True
        else:
            if self.state.is_stack_address(addr):
                stack_offset = self.state.get_stack_offset(addr)
                if stack_offset is not None:
                    # Storing data to stack
                    self._store_to_stack(stack_offset, data, size, stmt=stmt)
                    stored = True

        if not stored:
            # storing to a location specified by a pointer whose value cannot be determined at this point
            self._store_to_variable(richr_addr, size, stmt=stmt)

    def _store_to_stack(self, stack_offset, data: RichR, size, stmt=None, endness=None):
        if stmt is None:
            existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr,
                                                                                         self.stmt_idx,
                                                                                         'memory'
                                                                                         )
        else:
            existing_vars = self.variable_manager[self.func_addr].find_variables_by_atom(self.block.addr,
                                                                                         self.stmt_idx,
                                                                                         stmt
                                                                                         )
        if not existing_vars:
            variable = SimStackVariable(stack_offset, size, base='bp',
                                        ident=self.variable_manager[self.func_addr].next_variable_ident(
                                            'stack'),
                                        region=self.func_addr,
                                        )
            variable_offset = 0
            if isinstance(stack_offset, int):
                self.variable_manager[self.func_addr].set_variable('stack', stack_offset, variable)
                l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

        else:
            variable, variable_offset = next(iter(existing_vars))

        if isinstance(stack_offset, int):
            expr = self.state.annotate_with_variables(data.data, [(variable_offset, variable)])
            stack_addr = self.state.stack_addr_from_offset(stack_offset)
            self.state.stack_region.store(stack_addr, expr, endness=endness)

            codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

            addr_and_variables = set()
            try:
                vs: MultiValues = self.state.stack_region.load(stack_addr, size, endness=endness)
                for values in vs.values.values():
                    for value in values:
                        addr_and_variables.update(self.state.extract_variables(value))
            except SimMemoryMissingError:
                pass

            for var_offset, var in addr_and_variables:
                offset_into_var = var_offset
                if offset_into_var == 0:
                    offset_into_var = None
                self.variable_manager[self.func_addr].write_to(var,
                                                               offset_into_var,
                                                               codeloc,
                                                               atom=stmt,
                                                               )

            # create type constraints
            if data.typevar is not None:
                if not self.state.typevars.has_type_variable_for(variable, codeloc):
                    typevar = typevars.TypeVariable()
                    self.state.typevars.add_type_variable(variable, codeloc, typevar)
                else:
                    typevar = self.state.typevars.get_type_variable(variable, codeloc)
                if typevar is not None:
                    self.state.add_type_constraint(
                        typevars.Subtype(data.typevar, typevar)
                    )
        # TODO: Create a tv_sp.store.<bits>@N <: typevar type constraint for the stack pointer

    def _store_to_global(self, addr: int, data: RichR, size: int, stmt=None, offset: Optional[claripy.ast.BV]=None,
                         elem_size: Optional[claripy.ast.BV]=None):
        variable_manager = self.variable_manager['global']
        if stmt is None:
            existing_vars = variable_manager.find_variables_by_stmt(self.block.addr, self.stmt_idx, 'memory')
        else:
            existing_vars = variable_manager.find_variables_by_atom(self.block.addr, self.stmt_idx, stmt)

        if offset is None or elem_size is None:
            # trivial case
            abs_addr = addr
        elif offset.concrete and elem_size.concrete:
            abs_addr = addr + offset._model_concrete.value * elem_size._model_concrete.value
        else:
            abs_addr = None

        if not existing_vars:
            # special case for global variables: find existing variable by base address
            existing_vars = { (var, (offset, elem_size)) for var in variable_manager.get_global_variables(addr) }

        if not existing_vars:
            variable = SimMemoryVariable(addr, size,
                                         ident=variable_manager.next_variable_ident('global'),
                                         )
            variable_manager.set_variable('global', addr, variable)
            l.debug('Identified a new global variable %s at %#x.', variable, self.ins_addr)
            existing_vars = {(variable, (offset, elem_size))}
        else:
            variable, _ = next(iter(existing_vars))

        data_expr: claripy.ast.Base = data.data
        data_expr = self.state.annotate_with_variables(data_expr, [(0, variable)])

        if abs_addr is not None:
            self.state.global_region.store(addr,
                                           data_expr,
                                           endness=self.state.arch.memory_endness if stmt is None else stmt.endness)

        codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
        values = None
        if abs_addr is not None:
            try:
                values: MultiValues = self.state.global_region.load(
                    abs_addr,
                    size=size,
                    endness=self.state.arch.memory_endness if stmt is None else stmt.endness)
            except SimMemoryMissingError:
                pass

        if values is not None:
            for vs in values.values.values():
                for v in vs:
                    for var_offset, var in self.state.extract_variables(v):
                        variable_manager.write_to(var, var_offset, codeloc, atom=stmt)
        else:
            for var, var_offset in existing_vars:
                variable_manager.write_to(var, var_offset, codeloc, atom=stmt)

        # create type constraints
        if not self.state.typevars.has_type_variable_for(variable, codeloc):
            typevar = typevars.TypeVariable()
            self.state.typevars.add_type_variable(variable, codeloc, typevar)
        else:
            typevar = self.state.typevars.get_type_variable(variable, codeloc)

        if offset is not None and elem_size is not None:
            # it's an array!
            if offset.concrete and elem_size.concrete:
                concrete_offset = offset._model_concrete.value * elem_size._model_concrete.value
                store_typevar = typevars.DerivedTypeVariable(
                    typevars.DerivedTypeVariable(typevar, typevars.Store()),
                    typevars.HasField(size * self.state.arch.byte_width, concrete_offset)
                )
                self.state.add_type_constraint(
                    typevars.Existence(store_typevar)
                )
            else:
                store_typevar = typevars.DerivedTypeVariable(
                    typevars.DerivedTypeVariable(typevar, typevars.Store()),
                    typevars.HasField(size * self.state.arch.byte_width, 0)
                )
                self.state.add_type_constraint(
                    typevars.Existence(store_typevar)
                )
            # FIXME: This is a hack so that we can interpret the target as an array
            is_array = typevars.DerivedTypeVariable(
                typevar,
                typevars.IsArray()
            )
            self.state.add_type_constraint(
                typevars.Existence(is_array)
            )

            if data.typevar is not None:
                self.state.add_type_constraint(
                    typevars.Subtype(data.typevar, store_typevar)
                )

        else:
            # it's just a variable
            # however, since it's a global address, we still treat it as writing to a location
            if data.typevar is not None:
                store_typevar = typevars.DerivedTypeVariable(
                    typevars.DerivedTypeVariable(typevar, typevars.Store()),
                    typevars.HasField(size * self.state.arch.byte_width, 0)
                )
                self.state.add_type_constraint(
                    typevars.Existence(store_typevar)
                )
                self.state.add_type_constraint(
                    typevars.Subtype(data.typevar, store_typevar)
                )

    def _store_to_variable(self, richr_addr: RichR, size: int, stmt=None):  # pylint:disable=unused-argument

        addr_variable = richr_addr.variable
        codeloc = self._codeloc()

        # Storing data into a pointer
        if richr_addr.type_constraints:
            for tc in richr_addr.type_constraints:
                self.state.add_type_constraint(tc)

        if richr_addr.typevar is None:
            typevar = typevars.TypeVariable()
        else:
            typevar = richr_addr.typevar

        if typevar is not None:
            if isinstance(typevar, typevars.DerivedTypeVariable) and isinstance(typevar.label, typevars.AddN):
                base_typevar = typevar.type_var
                field_offset = typevar.label.n
            else:
                base_typevar = typevar
                field_offset = 0

            # if addr_variable is not None:
            #     self.variable_manager[self.func_addr].reference_at(addr_variable, field_offset, codeloc, atom=stmt)

            store_typevar = typevars.DerivedTypeVariable(
                typevars.DerivedTypeVariable(base_typevar, typevars.Store()),
                typevars.HasField(size * self.state.arch.byte_width, field_offset)
            )
            if addr_variable is not None:
                self.state.typevars.add_type_variable(addr_variable, codeloc, typevar)
            self.state.add_type_constraint(typevars.Existence(store_typevar))

    def _load(self, richr_addr: RichR, size: int, expr=None):
        """

        :param RichR richr_addr:
        :param size:
        :return:
        """

        addr: claripy.ast.Base = richr_addr.data
        codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
        typevar = None

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
                    # type(stack_offset) is int
                    concrete_offset = stack_offset
                    dynamic_offset = None

                try:
                    values: Optional[MultiValues] = self.state.stack_region.load(
                        self.state.stack_addr_from_offset(concrete_offset),
                        size=size,
                        endness=self.state.arch.memory_endness)

                except SimMemoryMissingError:
                    values = None

                all_vars: Set[Tuple[int,SimVariable]] = set()
                if values:
                    for vs in values.values.values():
                        for v in vs:
                            for _, var_ in self.state.extract_variables(v):
                                if isinstance(var_, SimStackVariable):
                                    var_offset = stack_offset - var_.offset
                                    all_vars.add((var_offset, var_))

                if not all_vars:
                    variables = self.variable_manager[self.func_addr].find_variables_by_stack_offset(concrete_offset)
                    if not variables:
                        variable = SimStackVariable(concrete_offset, size, base='bp',
                                                    ident=self.variable_manager[self.func_addr].next_variable_ident(
                                                        'stack'),
                                                    region=self.func_addr,
                                                    )
                        self.variable_manager[self.func_addr].add_variable('stack', concrete_offset, variable)
                        variables = {variable}
                        l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)
                    for variable in variables:
                        v = self.state.top(size * self.state.arch.byte_width)
                        v = self.state.annotate_with_variables(v, [(0, variable)])
                        stack_addr = self.state.stack_addr_from_offset(concrete_offset)
                        self.state.stack_region.store(stack_addr, v, endness=self.state.arch.memory_endness)

                    all_vars = {(0, variable) for variable in variables}

                if len(all_vars) > 1:
                    # overlapping variables
                    l.warning("Reading memory with overlapping variables: %s. Ignoring all but the first one.",
                              all_vars)

                var_offset, var = next(iter(all_vars))  # won't fail
                # calculate variable_offset
                if dynamic_offset is None:
                    offset_into_variable = var_offset
                else:
                    if var_offset == 0:
                        offset_into_variable = dynamic_offset
                    else:
                        offset_into_variable = ArithmeticExpression(ArithmeticExpression.Add,
                                                                    (dynamic_offset, var_offset,)
                                                                    )
                self.variable_manager[self.func_addr].read_from(var,
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
                    if not self.state.typevars.has_type_variable_for(var, codeloc):
                        typevar = typevars.TypeVariable()
                        self.state.typevars.add_type_variable(var, codeloc, typevar)
                    else:
                        typevar = self.state.typevars.get_type_variable(var, codeloc)

                else:
                    typevar = typevars.TypeVariable()
                    self.state.add_type_constraint(
                        typevars.Subtype(typeconsts.int_type(size * 8), typevar)
                    )

                # TODO: Create a tv_sp.load.<bits>@N type variable for the stack variable
                #typevar = typevars.DerivedTypeVariable(
                #    typevars.DerivedTypeVariable(typevar, typevars.Load()),
                #    typevars.HasField(size * 8, 0)
                #)

                r = self.state.top(size * self.state.arch.byte_width)
                r = self.state.annotate_with_variables(r, list(all_vars))
                return RichR(r, variable=var, typevar=typevar)

        elif addr.concrete:
            # Loading data from memory
            v = self._load_from_global(addr._model_concrete.value, size, expr=expr)
            typevar = v.typevar

        elif self._addr_has_concrete_base(addr) and self._parse_offseted_addr(addr) is not None:
            # Loading data from a memory address with an offset
            base_addr, offset, elem_size = self._parse_offseted_addr(addr)
            v = self._load_from_global(base_addr._model_concrete.value, size, expr=expr, offset=offset,
                                          elem_size=elem_size)
            typevar = v.typevar

        # Loading data from a pointer
        if richr_addr.type_constraints:
            for tc in richr_addr.type_constraints:
                self.state.add_type_constraint(tc)

        # parse the loading offset
        offset = 0
        if (isinstance(richr_addr.typevar, typevars.DerivedTypeVariable) and
                isinstance(richr_addr.typevar.label, typevars.AddN)):
            offset = richr_addr.typevar.label.n
            richr_addr_typevar = richr_addr.typevar.type_var  # unpack
        else:
            richr_addr_typevar = richr_addr.typevar

        if richr_addr_typevar is not None:
            # create a type constraint
            typevar = typevars.DerivedTypeVariable(
                typevars.DerivedTypeVariable(richr_addr_typevar, typevars.Load()),
                typevars.HasField(size * self.state.arch.byte_width, offset)
            )
            self.state.add_type_constraint(typevars.Existence(typevar))

        return RichR(self.state.top(size * self.state.arch.byte_width), typevar=typevar)

    def _load_from_global(self, addr: int, size, expr=None, offset: Optional[claripy.ast.BV]=None,
                          elem_size: Optional[claripy.ast.BV]=None) -> RichR:

        variable_manager = self.variable_manager['global']
        if expr is None:
            existing_vars = variable_manager.find_variables_by_stmt(self.block.addr, self.stmt_idx, 'memory')
        else:
            existing_vars = variable_manager.find_variables_by_atom(self.block.addr, self.stmt_idx, expr)

        # if offset is None or elem_size is None:
        #     # trivial case
        #     abs_addr = addr
        # elif offset.concrete and elem_size.concrete:
        #     abs_addr = addr + offset._model_concrete.value * elem_size._model_concrete.value
        # else:
        #     abs_addr = None

        if not existing_vars:
            # special case for global variables: find existing variable by base address
            existing_vars = { (var, (offset, elem_size)) for var in variable_manager.get_global_variables(addr) }

        if not existing_vars:
            # is this address mapped?
            if self.project.loader.find_object_containing(addr) is None:
                return RichR(self.state.top(size * self.state.arch.byte_width))
            variable = SimMemoryVariable(addr, size,
                                         ident=variable_manager.next_variable_ident('global'),
                                         )
            variable_manager.add_variable('global', addr, variable)
            l.debug('Identified a new global variable %s at %#x.', variable, self.ins_addr)
            existing_vars = {(variable, (offset, elem_size))}

        codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
        for variable, _ in existing_vars:
            variable_manager.read_from(variable, None, codeloc, atom=expr)

        variable, _ = next(iter(existing_vars))
        # create type constraints
        if not self.state.typevars.has_type_variable_for(variable, codeloc):
            typevar = typevars.TypeVariable()
            self.state.typevars.add_type_variable(variable, codeloc, typevar)
        else:
            typevar = self.state.typevars.get_type_variable(variable, codeloc)

        if offset is not None and elem_size is not None:
            # it's an array!
            if offset.concrete and elem_size.concrete:
                concrete_offset = offset._model_concrete.value * elem_size._model_concrete.value
                load_typevar = typevars.DerivedTypeVariable(
                    typevars.DerivedTypeVariable(typevar, typevars.Store()),
                    typevars.HasField(size * self.state.arch.byte_width, concrete_offset)
                )
                self.state.add_type_constraint(
                    typevars.Existence(load_typevar)
                )
            else:
                # FIXME: This is a hack
                for i in range(0, 4):
                    concrete_offset = size * i
                    load_typevar = typevars.DerivedTypeVariable(
                        typevars.DerivedTypeVariable(typevar, typevars.Store()),
                        typevars.HasField(size * self.state.arch.byte_width, concrete_offset)
                    )
                    self.state.add_type_constraint(
                        typevars.Existence(load_typevar)
                    )

        return RichR(self.state.top(size * self.state.arch.byte_width), typevar=typevar)

    def _read_from_register(self, offset, size, expr=None):
        """

        :param offset:
        :param size:
        :return:
        """

        codeloc = self._codeloc()

        try:
            values: Optional[MultiValues] = self.state.register_region.load(offset, size=size)
        except SimMemoryMissingError:
            values = None

        if offset in (self.arch.sp_offset, self.arch.ip_offset):
            # load values. don't worry about variables
            if values is None:
                r_value = self.state.top(size * self.arch.byte_width)
            else:
                r_value = next(iter(next(iter(values.values.values()))))
            return RichR(r_value, variable=None, typevar=None)

        if not values:
            # the value does not exist. create a new variable
            variable = SimRegisterVariable(offset, size,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident(
                                               'register'),
                                           region=self.func_addr,
                                           )
            value = self.state.top(size * self.state.arch.byte_width)
            value = self.state.annotate_with_variables(value, [(0, variable)])
            self.state.register_region.store(offset, value)
            self.variable_manager[self.func_addr].add_variable('register', offset, variable)

            value_list = [{ value }]
        else:
            value_list = list(values.values.values())

        variable_set = set()
        for value_set in value_list:
            for value in value_set:
                for _, var in self.state.extract_variables(value):
                    self.variable_manager[self.func_addr].read_from(var, None, codeloc, atom=expr)
                    variable_set.add(var)

        if offset == self.arch.sp_offset:
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
                    self.state.typevars.add_type_variable(var, codeloc, typevar)
                else:
                    # FIXME: This is an extremely stupid hack. Fix it later.
                    # typevar = next(reversed(list(self.state.typevars[var].values())))
                    typevar = self.state.typevars[var]

        if len(value_list) == 1:
            r_value = next(iter(value_list[0]))
        else:
            r_value = self.state.top(size * self.arch.byte_width)  # fall back to top
        return RichR(r_value, variable=var, typevar=typevar)
