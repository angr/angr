
from typing import Set, Optional
from collections import defaultdict
import logging

import ailment

from ... import sim_options
from ...engines.light import SpOffset
from ...keyed_region import KeyedRegion
from ...code_location import CodeLocation  # pylint:disable=unused-import
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from .values import Top
from .engine_vex import SimEnginePropagatorVEX
from .engine_ail import SimEnginePropagatorAIL


_l = logging.getLogger(name=__name__)

# The base state

class PropagatorState:
    def __init__(self, arch, replacements=None, only_consts=False, prop_count=None, equivalence=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        # propagation count of each expression
        self._prop_count = defaultdict(int) if prop_count is None else prop_count
        self._only_consts = only_consts
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._equivalence: Set[Equivalence] = equivalence if equivalence is not None else set()

    def __repr__(self):
        return "<PropagatorState>"

    def copy(self) -> 'PropagatorState':
        raise NotImplementedError()

    def merge(self, *others):

        state = self.copy()

        for o in others:
            for loc, vars_ in o._replacements.items():
                if loc not in state._replacements:
                    state._replacements[loc] = vars_.copy()
                else:
                    for var, repl in vars_.items():
                        if var not in state._replacements[loc]:
                            state._replacements[loc][var] = repl
                        else:
                            if state._replacements[loc][var] != repl:
                                state._replacements[loc][var] = Top(1)
            state._equivalence |= o._equivalence

        return state

    def add_replacement(self, codeloc, old, new):
        """
        Add a replacement record: Replacing expression `old` with `new` at program location `codeloc`.
        If the self._only_consts flag is set to true, only constant values will be set.

        :param CodeLocation codeloc:    The code location.
        :param old:                     The expression to be replaced.
        :param new:                     The expression to replace with.
        :return:                        None
        """
        if self._only_consts:
            if isinstance(new, int) or type(new) is Top:
                self._replacements[codeloc][old] = new
        else:
            self._replacements[codeloc][old] = new

    def filter_replacements(self):
        pass


# VEX state

class PropagatorVEXState(PropagatorState):
    def __init__(self, arch, registers=None, local_variables=None, replacements=None, only_consts=False,
                 prop_count=None):
        super().__init__(arch, replacements=replacements, only_consts=only_consts, prop_count=prop_count)
        self.registers = {} if registers is None else registers  # offset to values
        self.local_variables = {} if local_variables is None else local_variables  # offset to values

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self):
        cp = PropagatorVEXState(
            self.arch,
            registers=self.registers.copy(),
            local_variables=self.local_variables.copy(),
            replacements=self._replacements.copy(),
            prop_count=self._prop_count.copy(),
            only_consts=self._only_consts
        )

        return cp

    def merge(self, *others):
        state = self.copy()
        for other in others:  # type: PropagatorVEXState
            for offset, value in other.registers.items():
                if offset not in state.registers:
                    state.registers[offset] = value
                else:
                    if state.registers[offset] != value:
                        state.registers[offset] = Top(self.arch.bytes)

            for offset, value in other.local_variables.items():
                if offset not in state.local_variables:
                    state.local_variables[offset] = value
                else:
                    if state.local_variables[offset] != value:
                        state.local_variables[offset] = Top(self.arch.bytes)

        return state

    def store_local_variable(self, offset, size, value):  # pylint:disable=unused-argument
        # TODO: Handle size
        self.local_variables[offset] = value

    def load_local_variable(self, offset, size):  # pylint:disable=unused-argument
        # TODO: Handle size
        try:
            return self.local_variables[offset]
        except KeyError:
            return Top(size)

    def store_register(self, offset, size, value):
        if size != self.gpr_size:
            return

        self.registers[offset] = value

    def load_register(self, offset, size):

        # TODO: Fix me
        if size != self.gpr_size:
            return Top(size)

        try:
            return self.registers[offset]
        except KeyError:
            return Top(size)


# AIL state


class Equivalence:

    __slots__ = ('codeloc', 'atom0', 'atom1', )

    def __init__(self, codeloc, atom0, atom1):
        self.codeloc = codeloc
        self.atom0 = atom0
        self.atom1 = atom1

    def __repr__(self):
        return "<EqRelation: %r==%r@%r>" % (self.atom0, self.atom1, self.codeloc)

    def __eq__(self, other):
        return type(other) is Equivalence \
                and other.codeloc == self.codeloc \
                and other.atom0 == self.atom0 \
                and other.atom1 == self.atom1

    def __hash__(self):
        return hash((Equivalence, self.codeloc, self.atom0, self.atom1))


class PropagatorAILState(PropagatorState):
    def __init__(self, arch, replacements=None, only_consts=False, prop_count=None, equivalence=None):
        super().__init__(arch, replacements=replacements, only_consts=only_consts, prop_count=prop_count,
                         equivalence=equivalence)

        self._stack_variables = KeyedRegion()
        self._registers = KeyedRegion()
        self._tmps = { }

    def __repr__(self):
        return "<PropagatorAILState>"

    def copy(self):
        rd = PropagatorAILState(
            self.arch,
            replacements=self._replacements.copy(),
            prop_count=self._prop_count.copy(),
            only_consts=self._only_consts,
            equivalence=self._equivalence.copy(),
        )

        rd._stack_variables = self._stack_variables.copy()
        rd._registers = self._registers.copy()
        # drop tmps

        return rd

    def merge(self, *others) -> 'PropagatorAILState':
        # TODO:
        state = super().merge(*others)

        for o in others:
            state._stack_variables.merge_to_top(o._stack_variables, top=Top(1))
            state._registers.merge_to_top(o._registers, top=Top(1))

        return state

    def store_variable(self, old, new):
        if old is None or new is None:
            return
        if type(new) is not Top and new.has_atom(old, identity=False):
            return

        if isinstance(old, ailment.Expr.Tmp):
            self._tmps[old.tmp_idx] = new
        elif isinstance(old, ailment.Expr.Register):
            self._registers.set_object(old.reg_offset, new, old.size)
        else:
            _l.warning("Unsupported old variable type %s.", type(old))

    def store_stack_variable(self, addr, size, new, endness=None):  # pylint:disable=unused-argument
        if isinstance(addr, ailment.Expr.StackBaseOffset):
            if addr.offset is None:
                offset = 0
            else:
                offset = addr.offset
            self._stack_variables.set_object(offset, new, size)
        else:
            _l.warning("Unsupported addr type %s.", type(addr))

    def get_variable(self, variable):
        if isinstance(variable, ailment.Expr.Tmp):
            return self._tmps.get(variable.tmp_idx, None)
        elif isinstance(variable, ailment.Expr.Register):
            objs = self._registers.get_objects_by_offset(variable.reg_offset)
            if not objs:
                return None
            # FIXME: Right now we are always getting one item - we should, in fact, work on a multi-value domain
            first_obj = next(iter(objs))
            if type(first_obj) is Top:
                # return a Top
                if first_obj.bits != variable.bits:
                    return Top(variable.bits // 8)
                return first_obj
            if first_obj.bits != variable.bits:
                # conversion is needed
                if isinstance(first_obj, ailment.Expr.Convert):
                    if variable.bits == first_obj.operand.bits:
                        first_obj = first_obj.operand
                    else:
                        first_obj = ailment.Expr.Convert(first_obj.idx, first_obj.operand.bits, variable.bits,
                                                         first_obj.is_signed, first_obj.operand)
                else:
                    first_obj = ailment.Expr.Convert(first_obj.idx, first_obj.bits, variable.bits, False, first_obj)
            return first_obj
        return None

    def get_stack_variable(self, addr, size, endness=None):  # pylint:disable=unused-argument
        if isinstance(addr, ailment.Expr.StackBaseOffset):
            objs = self._stack_variables.get_objects_by_offset(addr.offset)
            if not objs:
                return None
            return next(iter(objs))
        return None

    def add_replacement(self, codeloc, old, new):

        prop_count = 0
        if not isinstance(old, ailment.Expr.Tmp) and isinstance(new, ailment.Expr.Expression) \
                and not isinstance(new, ailment.Expr.Const):
            self._prop_count[new] += 1
            prop_count = self._prop_count[new]

        if prop_count <= 1:
            # we can propagate this expression
            super().add_replacement(codeloc, old, new)
        else:
            # eliminate the past propagation of this expression
            for codeloc_ in self._replacements:
                if old in self._replacements[codeloc_]:
                    del self._replacements[codeloc_][old]

    def filter_replacements(self):

        to_remove = set()

        for old, new in self._replacements.items():
            if isinstance(new, ailment.Expr.Expression) and not isinstance(new, ailment.Expr.Const):
                if self._prop_count[new] > 1:
                    # do not propagate this expression
                    to_remove.add(old)

        for old in to_remove:
            del self._replacements[old]

    def add_equivalence(self, codeloc, old, new):
        eq = Equivalence(codeloc, old, new)
        self._equivalence.add(eq)


class PropagatorAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    PropagatorAnalysis propagates values (either constant values or variables) and expressions inside a block or across
    a function. It supports both VEX and AIL. It performs certain arithmetic operations between constants, including
    but are not limited to:

    - addition
    - subtraction
    - multiplication
    - division
    - xor

    It also performs the following memory operations, too:

    - Loading values from a known address
    - Writing values to a stack variable
    """

    def __init__(self, func=None, block=None, func_graph=None, base_state=None, max_iterations=3,
                 load_callback=None, stack_pointer_tracker=None, only_consts=False):
        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._base_state = base_state
        self._function = func
        self._max_iterations = max_iterations
        self._load_callback = load_callback
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions
        self._only_consts = only_consts

        self._node_iterations = defaultdict(int)
        self._states = { }
        self.replacements: Optional[defaultdict] = None
        self.equivalence: Set[Equivalence] = set()

        self._engine_vex = SimEnginePropagatorVEX(project=self.project)
        self._engine_ail = SimEnginePropagatorAIL(stack_pointer_tracker=self._stack_pointer_tracker)

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        if isinstance(node, ailment.Block):
            # AIL
            state = PropagatorAILState(arch=self.project.arch, only_consts=self._only_consts)
        else:
            # VEX
            state = PropagatorVEXState(arch=self.project.arch, only_consts=self._only_consts)
            state.store_register(self.project.arch.sp_offset,
                                 self.project.arch.bytes,
                                 SpOffset(self.project.arch.bits, 0)
                                 )
        return state

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
            block_key = node.addr
            engine = self._engine_vex
            if block.size == 0:
                # maybe the block is not decodeable
                return False, state

        state = state.copy()
        # Suppress spurious output
        if self._base_state is not None:
            self._base_state.options.add(sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
            self._base_state.options.add(sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        state = engine.process(state, block=block, project=self.project, base_state=self._base_state,
                               load_callback=self._load_callback, fail_fast=self._fail_fast)
        state.filter_replacements()

        self._node_iterations[block_key] += 1
        self._states[block_key] = state

        if self.replacements is None:
            self.replacements = state._replacements
        else:
            self.replacements.update(state._replacements)

        self.equivalence |= state._equivalence

        # TODO: Clear registers according to calling conventions

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(PropagatorAnalysis, "Propagator")
