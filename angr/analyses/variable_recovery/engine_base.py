from typing import Optional, Set
import logging

from ...engines.light import SimEngineLight, SpOffset, ArithmeticExpression
from ...errors import SimEngineError
from ...sim_variable import SimVariable, SimStackVariable, SimRegisterVariable
from ...code_location import CodeLocation
from ..typehoon import typevars, typeconsts

#
# The base engine used in VariableRecoveryFast
#

l = logging.getLogger(name=__name__)


class RichR:
    """
    A rich representation of calculation results.
    """

    __slots__ = ('data', 'variable', 'typevar', 'type_constraints', )

    def __init__(self, data, variable=None, typevar: Optional[typevars.TypeVariable]=None, type_constraints=None):
        self.data = data
        self.variable = variable
        self.typevar = typevar
        self.type_constraints = type_constraints

    @property
    def bits(self):
        if self.data is not None and not isinstance(self.data, (int, float)):
            return self.data.bits
        if self.variable is not None:
            return self.variable.bits
        return None

    def __repr__(self):
        return "R{%r}" % self.data


class SimEngineVRBase(SimEngineLight):
    def __init__(self, project, kb):
        super().__init__()

        self.project = project
        self.kb = kb
        self.processor_state = None
        self.variable_manager = None

    @property
    def func_addr(self):
        if self.state is None:
            return None
        return self.state.function.addr

    def process(self, state, *args, **kwargs):  # pylint:disable=unused-argument

        self.processor_state = state.processor_state
        self.variable_manager = state.variable_manager

        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False) is True:
                raise e

    def _process(self, state, successors, block=None, func_addr=None):  # pylint:disable=unused-argument,arguments-differ
        super()._process(state, successors, block=block)

    #
    # Logic
    #

    def _assign_to_register(self, offset, richr, size, src=None, dst=None):
        """

        :param int offset:
        :param RichR data:
        :param int size:
        :return:
        """

        codeloc = self._codeloc()  # type: CodeLocation
        data = richr.data

        if offset == self.arch.sp_offset:
            if type(data) is SpOffset:
                sp_offset = data.offset
                if isinstance(sp_offset, int):
                    self.processor_state.sp_adjusted = True
                    self.processor_state.sp_adjustment = sp_offset
                    l.debug('Adjusting stack pointer at %#x with offset %+#x.', self.ins_addr, sp_offset)
                elif (isinstance(sp_offset, ArithmeticExpression)
                      and sp_offset.op == ArithmeticExpression.And
                      and isinstance(sp_offset.operands[0], SpOffset)
                      and isinstance(sp_offset.operands[1], int)):
                    l.debug('Masking stack pointer at %#x with mask %#x.', self.ins_addr, sp_offset.operands[1])
                    # ignore masking
                else:
                    l.debug('An unsupported arithmetic expression %r is assigned to stack pointer at %#x. Ignore.',
                            sp_offset,
                            self.ins_addr,
                            )
                    # ignore unsupported arithmetic expressions.
            return

        if offset == self.arch.bp_offset:
            if data is not None:
                self.processor_state.bp = data
            else:
                self.processor_state.bp = None
            return

        if type(data) is SpOffset and isinstance(data.offset, int):
            # lea
            stack_offset = data.offset
            existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr,
                                                                                         self.stmt_idx,
                                                                                         'memory')

            if not existing_vars:
                # TODO: how to determine the size for a lea?
                existing_vars = self.state.stack_region.get_variables_by_offset(stack_offset)
                if not existing_vars:
                    lea_size = 1
                    variable = SimStackVariable(stack_offset, lea_size, base='bp',
                                                ident=self.variable_manager[self.func_addr].next_variable_ident(
                                                    'stack'),
                                                region=self.func_addr,
                                                )

                    self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)
                    l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)
                else:
                    variable = next(iter(existing_vars))

            else:
                variable, _ = existing_vars[0]

            self.state.stack_region.add_variable(stack_offset, variable)
            typevar = typevars.TypeVariable() if richr.typevar is None else richr.typevar
            self.state.typevars.add_type_variable(variable, codeloc, typevar)
            base_offset = self.state.stack_region.get_base_addr(stack_offset)
            for var in self.state.stack_region.get_variables_by_offset(base_offset):
                offset_into_var = stack_offset - base_offset
                if offset_into_var == 0: offset_into_var = None
                self.variable_manager[self.func_addr].reference_at(var, offset_into_var, codeloc,
                                                                   atom=src)

        else:
            pass

        # handle register writes
        existing_vars = self.variable_manager[self.func_addr].find_variables_by_atom(self.block.addr, self.stmt_idx,
                                                                                     dst)
        existing_vars: Set[SimVariable,int]
        if not existing_vars:
            variable = SimRegisterVariable(offset, size,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident(
                                               'register'),
                                           region=self.func_addr
                                           )
            self.variable_manager[self.func_addr].set_variable('register', offset, variable)
        else:
            variable, _ = next(iter(existing_vars))

        self.state.register_region.set_variable(offset, variable)
        self.variable_manager[self.func_addr].write_to(variable, None, codeloc, atom=dst)

        if not self.arch.is_artificial_register(offset, size) and richr.typevar is not None:
            if not self.state.typevars.has_type_variable_for(variable, codeloc):
                # assign a new type variable to it
                typevar = typevars.TypeVariable()
                self.state.typevars.add_type_variable(variable, codeloc, typevar)
                # create constraints
                self.state.add_type_constraint(typevars.Subtype(richr.typevar, typevar))
                self.state.add_type_constraint(typevars.Subtype(typevar, typeconsts.int_type(variable.size * 8)))

    def _store(self, richr_addr: RichR, data, size, stmt=None):  # pylint:disable=unused-argument
        """

        :param RichR addr:
        :param RichR data:
        :param int size:
        :return:
        """

        addr = richr_addr.data

        if type(addr) is SpOffset:
            # Storing data to stack
            stack_offset = addr.offset
            self._store_to_stack(stack_offset, data, size, stmt=stmt)
            return

        if type(addr) is int:
            # TODO: Handle storing to global
            return

        if addr is None:
            # storing to a location specified by a pointer whose value cannot be determined at this point
            self._store_to_variable(richr_addr, size, stmt=stmt)

    def _store_to_stack(self, stack_offset, data, size, stmt=None):
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
            if isinstance(stack_offset, int):
                self.variable_manager[self.func_addr].set_variable('stack', stack_offset, variable)
                l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

        else:
            variable, _ = next(iter(existing_vars))

        if isinstance(stack_offset, int):
            self.state.stack_region.set_variable(stack_offset, variable)
            base_offset = self.state.stack_region.get_base_addr(stack_offset)
            codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
            for var in self.state.stack_region.get_variables_by_offset(stack_offset):
                offset_into_var = stack_offset - base_offset
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

    def _store_to_variable(self, richr_addr: RichR, size, stmt=None):  # pylint:disable=unused-argument

        addr_variable = richr_addr.variable
        codeloc = self._codeloc()

        if richr_addr.typevar is None:
            typevar = typevars.TypeVariable()
        else:
            typevar = richr_addr.typevar
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
            typevars.HasField(size * 8, field_offset)
        )
        if addr_variable is not None:
            self.state.typevars.add_type_variable(addr_variable, codeloc, typevar)
        self.state.add_type_constraint(typevars.Existence(store_typevar))

    def _load(self, richr_addr, size, expr=None):
        """

        :param RichR richr_addr:
        :param size:
        :return:
        """

        addr = richr_addr.data

        if type(addr) is SpOffset:
            # Loading data from stack
            stack_offset = addr.offset

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

            # decide which base variable is being accessed using the concrete offset
            if concrete_offset is not None and concrete_offset not in self.state.stack_region:
                variable = SimStackVariable(concrete_offset, size, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident(
                                                'stack'),
                                            region=self.func_addr,
                                            )
                self.state.stack_region.add_variable(concrete_offset, variable)

                self.variable_manager[self.func_addr].add_variable('stack', concrete_offset, variable)

                l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

            base_offset = self.state.stack_region.get_base_addr(concrete_offset)
            codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

            all_vars = self.state.stack_region.get_variables_by_offset(base_offset)
            if len(all_vars) > 1:
                # overlapping variables
                l.warning("Reading memory with overlapping variables: %s. Ignoring all but the first one.",
                          all_vars)

            var = next(iter(all_vars))
            # calculate variable_offset
            if dynamic_offset is None:
                offset_into_variable = concrete_offset - base_offset
                if offset_into_variable == 0:
                    offset_into_variable = None
            else:
                if concrete_offset == base_offset:
                    offset_into_variable = dynamic_offset
                else:
                    offset_into_variable = ArithmeticExpression(ArithmeticExpression.Add,
                                                                (dynamic_offset, concrete_offset - base_offset,)
                                                                )
            data = self.variable_manager[self.func_addr].read_from(var,
                                                                   offset_into_variable,
                                                                   codeloc,
                                                                   atom=expr,
                                                                   # overwrite=True
                                                                   )

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
            # TODO: Create a tv_sp.load.<bits>@N type variable for the stack variable
            #typevar = typevars.DerivedTypeVariable(
            #    typevars.DerivedTypeVariable(typevar, typevars.Load()),
            #    typevars.HasField(size * 8, 0)
            #)

            return RichR(data, variable=var, typevar=typevar)

        # Loading data from a pointer

        # parse the loading offset
        offset = 0
        if (isinstance(richr_addr.typevar, typevars.DerivedTypeVariable) and
                isinstance(richr_addr.typevar.label, typevars.AddN)):
            offset = richr_addr.typevar.label.n
            richr_addr_typevar = richr_addr.typevar.type_var  # unpack
        else:
            richr_addr_typevar = richr_addr.typevar

        # create a type constraint
        typevar = typevars.DerivedTypeVariable(
            typevars.DerivedTypeVariable(richr_addr_typevar, typevars.Load()),
            typevars.HasField(size * 8, offset)
        )
        self.state.add_type_constraint(typevars.Existence(typevar))
        return RichR(None, typevar=typevar)

    def _read_from_register(self, offset, size, expr=None):
        """

        :param offset:
        :param size:
        :return:
        """

        codeloc = self._codeloc()

        if offset == self.arch.sp_offset:
            # loading from stack pointer
            return RichR(SpOffset(self.arch.bits, self.processor_state.sp_adjustment, is_base=False))
        elif offset == self.arch.bp_offset:
            return RichR(self.processor_state.bp)

        if offset not in self.state.register_region:
            variable = SimRegisterVariable(offset, size,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident(
                                               'register'),
                                           region=self.func_addr,
                                           )
            self.state.register_region.add_variable(offset, variable)
            self.variable_manager[self.func_addr].add_variable('register', offset, variable)

        for var in self.state.register_region.get_variables_by_offset(offset):
            self.variable_manager[self.func_addr].read_from(var, None, codeloc, atom=expr)

        # we accept the precision loss here by only returning the first variable
        var = next(iter(self.state.register_region.get_variables_by_offset(offset)))
        if self.arch.is_artificial_register(offset, size):
            typevar = None
        else:
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

        return RichR(None, variable=var, typevar=typevar)
