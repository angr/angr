# pylint:disable=isinstance-second-argument-not-valid-type
import weakref
from typing import Set, Optional, Any, Tuple, TYPE_CHECKING
from collections import defaultdict
import logging

import claripy
import ailment

from ... import sim_options
from ...storage.memory_mixins import LabeledMemory
from ...errors import SimMemoryMissingError
from ...code_location import CodeLocation  # pylint:disable=unused-import
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from .engine_vex import SimEnginePropagatorVEX
from .engine_ail import SimEnginePropagatorAIL

if TYPE_CHECKING:
    from angr.storage import SimMemoryObject


_l = logging.getLogger(name=__name__)


# The base state

class PropagatorState:

    _tops = {}

    def __init__(self, arch, project=None, replacements=None, only_consts=False, prop_count=None, equivalence=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        # propagation count of each expression
        self._prop_count = defaultdict(int) if prop_count is None else prop_count
        self._only_consts = only_consts
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._equivalence: Set[Equivalence] = equivalence if equivalence is not None else set()

        self.project = project

    def __repr__(self):
        return "<PropagatorState>"

    def _get_weakref(self):
        return weakref.proxy(self)

    @staticmethod
    def _mo_cmp(mo_self: 'SimMemoryObject', mo_other: 'SimMemoryObject', addr: int, size: int):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.

        if mo_self.object.symbolic or mo_other.object.symbolic:
            return mo_self.object is mo_other.object
        return None

    @staticmethod
    def top(bits: int) -> claripy.ast.Base:
        """
        Get a TOP value.

        :param size:    Width of the TOP value (in bits).
        :return:        The TOP value.
        """

        if bits in PropagatorState._tops:
            return PropagatorState._tops[bits]
        r = claripy.BVS("TOP", bits, explicit_name=True)
        PropagatorState._tops[bits] = r
        return r

    @staticmethod
    def is_top(expr) -> bool:
        """
        Check if the given expression is a TOP value.

        :param expr:    The given expression.
        :return:        True if the expression is TOP, False otherwise.
        """
        if isinstance(expr, claripy.ast.Base):
            if expr.op == "BVS" and expr.args[0] == "TOP":
                return True
            if "TOP" in expr.variables:
                return True
        return False

    def copy(self) -> 'PropagatorState':
        raise NotImplementedError()

    def merge(self, *others):

        state = self.copy()
        merge_occurred = False

        for o in others:
            for loc, vars_ in o._replacements.items():
                if loc not in state._replacements:
                    state._replacements[loc] = vars_.copy()
                    merge_occurred = True
                else:
                    for var, repl in vars_.items():
                        if var not in state._replacements[loc]:
                            state._replacements[loc][var] = repl
                            merge_occurred = True
                        else:
                            if self.is_top(repl) or self.is_top(state._replacements[loc][var]):
                                t = self.top(repl.bits if isinstance(repl, ailment.Expression) else repl.size())
                                state._replacements[loc][var] = t
                                merge_occurred = True
                            elif state._replacements[loc][var] != repl:
                                t = self.top(repl.bits if isinstance(repl, ailment.Expression) else repl.size())
                                state._replacements[loc][var] = t
                                merge_occurred = True

            if state._equivalence != o._equivalence:
                merge_occurred = True
            state._equivalence |= o._equivalence

        return state, merge_occurred

    def add_replacement(self, codeloc, old, new):
        """
        Add a replacement record: Replacing expression `old` with `new` at program location `codeloc`.
        If the self._only_consts flag is set to true, only constant values will be set.

        :param CodeLocation codeloc:    The code location.
        :param old:                     The expression to be replaced.
        :param new:                     The expression to replace with.
        :return:                        None
        """
        if self.is_top(new):
            return

        if self._only_consts:
            if isinstance(new, int) or self.is_top(new):
                self._replacements[codeloc][old] = new
        else:
            self._replacements[codeloc][old] = new

    def filter_replacements(self):
        pass


# VEX state

class PropagatorVEXState(PropagatorState):
    def __init__(self, arch, project=None, registers=None, local_variables=None, replacements=None, only_consts=False,
                 prop_count=None):
        super().__init__(arch, project=project, replacements=replacements, only_consts=only_consts, prop_count=prop_count)
        self._registers = LabeledMemory(memory_id='reg', top_func=self.top, page_kwargs={'mo_cmp': self._mo_cmp}) if registers is None else registers
        self._stack_variables = LabeledMemory(memory_id='mem', top_func=self.top, page_kwargs={'mo_cmp': self._mo_cmp}) if local_variables is None else local_variables

        self._registers.set_state(self)
        self._stack_variables.set_state(self)

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self) -> 'PropagatorVEXState':
        cp = PropagatorVEXState(
            self.arch,
            project=self.project,
            registers=self._registers.copy(),
            local_variables=self._stack_variables.copy(),
            replacements=self._replacements.copy(),
            prop_count=self._prop_count.copy(),
            only_consts=self._only_consts
        )

        return cp

    def merge(self, *others: 'PropagatorVEXState') -> Tuple['PropagatorVEXState',bool]:
        state = self.copy()
        merge_occurred = state._registers.merge([o._registers for o in others], None)
        merge_occurred |= state._stack_variables.merge([o._stack_variables for o in others], None)
        return state, merge_occurred

    def store_local_variable(self, offset, size, value, endness):  # pylint:disable=unused-argument
        # TODO: Handle size
        self._stack_variables.store(offset, value, size=size, endness=endness)

    def load_local_variable(self, offset, size, endness):  # pylint:disable=unused-argument
        # TODO: Handle size
        try:
            return self._stack_variables.load(offset, size=size, endness=endness)
        except SimMemoryMissingError:
            return self.top(size * self.arch.byte_width)

    def store_register(self, offset, size, value):
        self._registers.store(offset, value, size=size)

    def load_register(self, offset, size):

        # TODO: Fix me
        if size != self.gpr_size:
            return self.top(size * self.arch.byte_width)

        try:
            return self._registers.load(offset, size=size)
        except SimMemoryMissingError:
            return self.top(size * self.arch.byte_width)


# AIL state


class Equivalence:
    __slots__ = ('codeloc', 'atom0', 'atom1',)

    def __init__(self, codeloc, atom0, atom1):
        self.codeloc = codeloc
        self.atom0 = atom0
        self.atom1 = atom1

    def __repr__(self):
        return "<Eq@%r: %r==%r>" % (self.codeloc, self.atom0, self.atom1)

    def __eq__(self, other):
        return type(other) is Equivalence \
               and other.codeloc == self.codeloc \
               and other.atom0 == self.atom0 \
               and other.atom1 == self.atom1

    def __hash__(self):
        return hash((Equivalence, self.codeloc, self.atom0, self.atom1))


class PropagatorAILState(PropagatorState):
    def __init__(self, arch, project=None, replacements=None, only_consts=False, prop_count=None, equivalence=None,
                 stack_variables=None, registers=None):
        super().__init__(arch, project=project, replacements=replacements, only_consts=only_consts, prop_count=prop_count,
                         equivalence=equivalence)

        self._stack_variables = LabeledMemory(memory_id='mem', top_func=self.top, page_kwargs={'mo_cmp': self._mo_cmp}) \
            if stack_variables is None else stack_variables
        self._registers = LabeledMemory(memory_id='reg', top_func=self.top, page_kwargs={'mo_cmp': self._mo_cmp}) \
            if registers is None else registers
        self._tmps = {}

        self._registers.set_state(self)
        self._stack_variables.set_state(self)

    def __repr__(self):
        return "<PropagatorAILState>"

    def copy(self):
        rd = PropagatorAILState(
            self.arch,
            project=self.project,
            replacements=self._replacements.copy(),
            prop_count=self._prop_count.copy(),
            only_consts=self._only_consts,
            equivalence=self._equivalence.copy(),
            stack_variables=self._stack_variables.copy(),
            registers=self._registers.copy(),
            # drop tmps
        )

        return rd

    def merge(self, *others) -> Tuple['PropagatorAILState',bool]:
        state, merge_occurred = super().merge(*others)
        state: 'PropagatorAILState'

        merge_occurred |= state._registers.merge([o._registers for o in others], None)
        merge_occurred |= state._stack_variables.merge([o._stack_variables for o in others], None)

        return state, merge_occurred

    def store_variable(self, variable, value, def_at) -> None:
        if variable is None or value is None:
            return
        if isinstance(value, ailment.Expr.Expression) and value.has_atom(variable, identity=False):
            return

        if isinstance(variable, ailment.Expr.Tmp):
            self._tmps[variable.tmp_idx] = value
        elif isinstance(variable, ailment.Expr.Register):
            if isinstance(value, claripy.ast.Base):
                # We directly store the value in memory
                expr = None
            elif isinstance(value, ailment.Expr.Const):
                # convert the const expression to a claripy AST
                expr = value
                value = claripy.BVV(value.value, value.bits)
            elif isinstance(value, ailment.Expr.Expression):
                # the value is an expression. the actual value will be TOP.
                expr = value
                value = self.top(expr.bits)
            else:
                raise TypeError("Unsupported value type %s" % type(value))

            label = {
                'expr': expr,
                'def_at': def_at,
            }

            self._registers.store(variable.reg_offset, value, size=variable.size, label=label)
        else:
            _l.warning("Unsupported old variable type %s.", type(variable))

    def store_stack_variable(self, sp_offset: int, size, new, expr=None, def_at=None, endness=None) -> None:  # pylint:disable=unused-argument
        # normalize sp_offset to handle negative offsets
        sp_offset += 0x65536
        sp_offset &= (1 << self.arch.bits) - 1

        label = {
            'expr': expr,
            'def_at': def_at,
        }

        self._stack_variables.store(sp_offset, new, size=size, endness=endness, label=label)

    def get_variable(self, variable) -> Any:
        if isinstance(variable, ailment.Expr.Tmp):
            return self._tmps.get(variable.tmp_idx, None)
        elif isinstance(variable, ailment.Expr.Register):
            try:
                value, labels = self._registers.load_with_labels(variable.reg_offset, size=variable.size)
            except SimMemoryMissingError:
                # value does not exist
                return None

            if len(labels) == 1:
                # extract labels
                offset, size, label = labels[0]
                if value.size() // self.arch.byte_width == size:
                    # the label covers the entire expression
                    expr: Optional[ailment.Expr.Expression] = label['expr']
                    def_at = label['def_at']
                    if expr is not None:
                        if expr.bits > size * self.arch.byte_width:
                            # we are loading a chunk of the original expression
                            expr = self._extract_ail_expression(
                                offset * self.arch.byte_width,
                                size * self.arch.byte_width,
                                expr,
                            )
                        if expr.bits < variable.size * self.arch.byte_width:
                            # we are loading more than the expression has - extend the size of the expression
                            expr = self._extend_ail_expression(
                                variable.size * self.arch.byte_width - expr.bits,
                                expr,
                            )
                else:
                    expr = None
                    def_at = None
            else:
                # Multiple definitions and expressions
                expr = None
                def_at = None

            if self.is_top(value):
                # return a non-const expression if there is one, or return a Top
                if expr is not None:
                    if isinstance(expr, ailment.Expr.Expression) and not isinstance(expr, ailment.Expr.Const):
                        copied_expr = expr.copy()
                        copied_expr.tags['def_at'] = def_at
                        return copied_expr
                    else:
                        return value
                if value.size() != variable.bits:
                    return self.top(variable.bits)
                return value

            # value is not TOP
            if value.size() != variable.bits:
                raise TypeError("Incorrect sized read. Expect %d bits." % variable.bits)

            if expr is None:
                return value
            else:
                return expr

        return None

    def get_stack_variable(self, sp_offset: int, size, endness=None) -> Optional[Any]:
        # normalize sp_offset to handle negative offsets
        sp_offset += 0x65536
        sp_offset &= (1 << self.arch.bits) - 1
        try:
            value, labels = self._stack_variables.load_with_labels(sp_offset, size=size, endness=endness)
        except SimMemoryMissingError:
            # the stack variable does not exist
            return None

        if len(labels) == 1:
            # extract labels
            offset, size, label = labels[0]
            expr: Optional[ailment.Expr.Expression] = label['expr']
            def_at = label['def_at']
            if expr is not None:
                if expr.bits > size * self.arch.byte_width:
                    # we are loading a chunk of the original expression
                    expr = self._extract_ail_expression(
                        offset * self.arch.byte_width,
                        size * self.arch.byte_width,
                        expr,
                    )
                if expr.bits < size * self.arch.byte_width:
                    # we are loading more than the expression has - extend the size of the expression
                    expr = self._extend_ail_expression(
                        size * self.arch.byte_width - expr.bits,
                        expr,
                    )
        else:
            # Multiple definitions and expressions
            expr = None
            def_at = None

        if self.is_top(value):
            # return a non-const expression if there is one, or return a Top
            if expr is not None:
                if isinstance(expr, ailment.Expr.Expression) and not isinstance(expr, ailment.Expr.Const):
                    copied_expr = expr.copy()
                    copied_expr.tags['def_at'] = def_at
                    return copied_expr
                else:
                    return value
            if value.size() != size * self.arch.byte_width:
                return self.top(size * self.arch.byte_width)
            return value

        return expr if expr is not None else value

    def add_replacement(self, codeloc, old, new):

        if isinstance(new, ailment.statement.Call):
            # do not replace anything with a call expression
            return

        if self.is_top(new):
            # eliminate the past propagation of this expression
            if codeloc in self._replacements and old in self._replacements[codeloc]:
                self._replacements[codeloc][old] = self.top(1)  # placeholder
            return

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
                    self._replacements[codeloc_][old] = self.top(1)

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

    @staticmethod
    def _extract_ail_expression(start: int, bits: int, expr: ailment.Expr.Expression) -> Optional[ailment.Expr.Expression]:
        if start == 0:
            return ailment.Expr.Convert(None, expr.bits, bits, False, expr)
        else:
            a = ailment.Expr.BinaryOp(None, "Shr", (expr, bits), False)
            return ailment.Expr.Convert(None, a.bits, bits, False, a)

    @staticmethod
    def _extend_ail_expression(bits: int, expr: ailment.Expr.Expression) -> Optional[ailment.Expr.Expression]:
        return ailment.Expr.Convert(None, expr.bits, bits + expr.bits, False, expr)


class PropagatorAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    PropagatorAnalysis propagates values (either constant values or variables) and expressions inside a block or across
    a function.

    PropagatorAnalysis supports both VEX and AIL. The VEX propagator only performs constant propagation. The AIL
    propagator performs both constant propagation and copy propagation of depth-N expressions.

    PropagatorAnalysis performs certain arithmetic operations between constants, including but are not limited to:

    - addition
    - subtraction
    - multiplication
    - division
    - xor

    It also performs the following memory operations:

    - Loading values from a known address
    - Writing values to a stack variable
    """

    def __init__(self, func=None, block=None, func_graph=None, base_state=None, max_iterations=3,
                 load_callback=None, stack_pointer_tracker=None, only_consts=False, completed_funcs=None):
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
        self._completed_funcs = completed_funcs

        self._node_iterations = defaultdict(int)
        self._states = {}
        self.replacements: Optional[defaultdict] = None
        self.equivalence: Set[Equivalence] = set()

        self._engine_vex = SimEnginePropagatorVEX(project=self.project, arch=self.project.arch)
        self._engine_ail = SimEnginePropagatorAIL(
            arch=self.project.arch,
            stack_pointer_tracker=self._stack_pointer_tracker,
            # We only propagate tmps within the same block. This is because the lifetime of tmps is one block only.
            propagate_tmps=block is not None,
        )

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
            state = PropagatorAILState(self.project.arch, project=self.project, only_consts=self._only_consts)
        else:
            # VEX
            state = PropagatorVEXState(self.project.arch, project=self.project, only_consts=self._only_consts)
            spoffset_var = self._engine_vex.sp_offset(0)
            state.store_register(self.project.arch.sp_offset,
                                 self.project.arch.bytes,
                                 spoffset_var,
                                 )
        return state

    def _merge_states(self, node, *states: PropagatorState):
        merged_state, merge_occurred = states[0].merge(*states[1:])
        return merged_state, not merge_occurred

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            block = node
            block_key = (node.addr, node.idx)
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

    def _check_func_complete(self, func):
        """
        Checks if a function is completely created by the CFG. Completed
        functions are passed to the Propagator at initialization. Defaults to
        being empty if no pass is initiated.

        :param func:    Function to check (knowledge_plugins.functions.function.Function)
        :return:        Bool
        """
        complete = False
        if self._completed_funcs is None:
            return complete

        if func.addr in self._completed_funcs:
            complete = True

        return complete

    def _post_analysis(self):
        """
        Post Analysis of Propagation().
        We add the current propagation replacements result to the kb if the
        function has already been completed in cfg creation.
        """

        # Filter replacements and remove all TOP values
        if self.replacements is not None:
            for codeloc in list(self.replacements.keys()):
                rep = dict((k, v) for k, v in self.replacements[codeloc].items() if not PropagatorState.is_top(v))
                self.replacements[codeloc] = rep

        if self._function is not None:
            if self._check_func_complete(self._function):
                func_loc = CodeLocation(self._function.addr, None)
                self.kb.propagations.update(func_loc, self.replacements)

    def _check_prop_kb(self):
        """
        Checks, and gets, stored propagations from the KB for the current
        Propagation state.

        :return:    None or Dict of replacements
        """
        replacements = None
        if self._function is not None:
            func_loc = CodeLocation(self._function.addr, None)
            replacements = self.kb.propagations.get(func_loc)

        return replacements

    def _analyze(self):
        """
        The main analysis for Propagator. Overwritten to include an optimization to stop
        analysis if we have already analyzed the entire function once.
        """
        self._pre_analysis()

        # optimization check
        stored_replacements = self._check_prop_kb()
        if stored_replacements is not None:
            if self.replacements is not None:
                self.replacements.update(stored_replacements)
            else:
                self.replacements = stored_replacements

        # normal analysis execution
        elif self._graph_visitor is None:
            # There is no base graph that we can rely on. The analysis itself should generate successors for the
            # current job.
            # An example is the CFG recovery.

            self._analysis_core_baremetal()

        else:
            # We have a base graph to follow. Just handle the current job.

            self._analysis_core_graph()

        self._post_analysis()


register_analysis(PropagatorAnalysis, "Propagator")
