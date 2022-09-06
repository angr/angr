# pylint:disable=isinstance-second-argument-not-valid-type
import weakref
from typing import Set, Optional, Any, Tuple, Union, List
from collections import defaultdict
import logging

import claripy
import ailment
import pyvex

from ... import sim_options
from ...storage.memory_mixins import LabeledMemory
from ...errors import SimMemoryMissingError
from ...code_location import CodeLocation  # pylint:disable=unused-import
from ...storage.memory_object import SimMemoryObject, SimLabeledMemoryObject
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from .engine_vex import SimEnginePropagatorVEX
from .engine_ail import SimEnginePropagatorAIL
from .prop_value import PropValue, Detail


_l = logging.getLogger(name=__name__)


class PropagatorState:
    """
    Describes the base state used in Propagator.
    """

    __slots__ = ('arch', 'gpr_size', '_prop_count', '_only_consts', '_replacements', '_equivalence', 'project',
                 '_store_tops', '_gp', '__weakref__', )

    _tops = {}

    def __init__(self, arch, project=None, replacements=None, only_consts=False, prop_count=None, equivalence=None,
                 store_tops=True, gp=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        # propagation count of each expression
        self._prop_count = defaultdict(int) if prop_count is None else prop_count
        self._only_consts = only_consts
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._equivalence: Set[Equivalence] = equivalence if equivalence is not None else set()
        self._store_tops = store_tops

        # architecture-specific information
        self._gp: Optional[int] = gp  # Value of gp for MIPS32 and 64 binaries

        self.project = project

    def __repr__(self):
        return "<PropagatorState>"

    def _get_weakref(self):
        return weakref.proxy(self)

    @staticmethod
    def _mo_cmp(mo_self: Union['SimMemoryObject','SimLabeledMemoryObject'],
                mo_other: Union['SimMemoryObject','SimLabeledMemoryObject'],
                addr: int, size: int):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.

        if mo_self.object.symbolic or mo_other.object.symbolic:
            if type(mo_self) is SimLabeledMemoryObject and type(mo_other) is SimLabeledMemoryObject:
                return mo_self.label == mo_other.label and mo_self.object is mo_other.object
            if type(mo_self) is SimMemoryObject and type(mo_other) is SimMemoryObject:
                return mo_self.object is mo_other.object
            # SimMemoryObject vs SimLabeledMemoryObject -> the label must be different
            return False
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
    """
    Describes the state used in the VEX engine of Propagator.
    """

    __slots__ = ('_registers', '_stack_variables', 'do_binops', )

    def __init__(self, arch, project=None, registers=None, local_variables=None, replacements=None, only_consts=False,
                 prop_count=None, do_binops=True, store_tops=True, gp=None):
        super().__init__(arch, project=project, replacements=replacements, only_consts=only_consts,
                         prop_count=prop_count, store_tops=store_tops, gp=gp)
        self.do_binops = do_binops
        self._registers = LabeledMemory(
            memory_id='reg',
            top_func=self.top,
            page_kwargs={'mo_cmp': self._mo_cmp}) \
            if registers is None else registers
        self._stack_variables = LabeledMemory(
            memory_id='mem',
            top_func=self.top,
            page_kwargs={'mo_cmp': self._mo_cmp}) \
            if local_variables is None else local_variables

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
            only_consts=self._only_consts,
            do_binops=self.do_binops,
            store_tops=self._store_tops,
            gp=self._gp,
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
    """
    Describes an equivalence relationship between two atoms.
    """

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
    """
    Describes the state used in the AIL engine of Propagator.
    """

    __slots__ = ('_registers', '_stack_variables', '_tmps', 'temp_expressions', 'register_expressions',
                 'last_stack_store', 'global_stores')

    def __init__(self, arch, project=None, replacements=None, only_consts=False, prop_count=None, equivalence=None,
                 stack_variables=None, registers=None, gp=None):
        super().__init__(arch, project=project, replacements=replacements, only_consts=only_consts,
                         prop_count=prop_count, equivalence=equivalence, gp=gp)

        self._stack_variables = LabeledMemory(memory_id='mem',
                                              top_func=self.top,
                                              page_kwargs={'mo_cmp': self._mo_cmp}) \
            if stack_variables is None else stack_variables
        self._registers = LabeledMemory(memory_id='reg', top_func=self.top, page_kwargs={'mo_cmp': self._mo_cmp}) \
            if registers is None else registers
        self._tmps = {}
        self.temp_expressions = { }
        self.register_expressions = { }

        self._registers.set_state(self)
        self._stack_variables.set_state(self)
        # last_stack_store stores the most recent stack store statement with a non-concrete or unresolvable address. we
        # use this information to determine if stack reads after this store can be safely resolved to definitions prior
        # to the stack read.
        self.last_stack_store: Optional[Tuple[int,int,ailment.Stmt.Store]] = None
        self.global_stores: List[Tuple[int,int,Any,ailment.Stmt.Store]] = [ ]

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
            gp=self._gp,
        )

        return rd

    def merge(self, *others) -> Tuple['PropagatorAILState',bool]:
        state, merge_occurred = super().merge(*others)
        state: 'PropagatorAILState'

        merge_occurred |= state._registers.merge([o._registers for o in others], None)
        merge_occurred |= state._stack_variables.merge([o._stack_variables for o in others], None)

        return state, merge_occurred

    def store_temp(self, tmp_idx: int, value: PropValue):
        self._tmps[tmp_idx] = value

    def load_tmp(self, tmp_idx: int) -> Optional[PropValue]:
        return self._tmps.get(tmp_idx, None)

    def store_register(self, reg: ailment.Expr.Register, value: PropValue) -> None:
        if isinstance(value, ailment.Expr.Expression) and value.has_atom(reg, identity=False):
            return

        for offset, chopped_value, size, label in value.value_and_labels():
            self._registers.store(reg.reg_offset + offset, chopped_value, size=size, label=label,
                                  endness=self.project.arch.register_endness)

    def store_stack_variable(self, sp_offset: int, new: PropValue, endness=None) -> None:  # pylint:disable=unused-argument
        # normalize sp_offset to handle negative offsets
        sp_offset += 0x65536
        sp_offset &= (1 << self.arch.bits) - 1

        for offset, value, size, label in new.value_and_labels():
            self._stack_variables.store(sp_offset + offset, value, size=size, endness=endness, label=label)

    def load_register(self, reg: ailment.Expr.Register) -> Optional[PropValue]:
        try:
            value, labels = self._registers.load_with_labels(reg.reg_offset, size=reg.size,
                                                             endness=self.project.arch.register_endness)
        except SimMemoryMissingError:
            # value does not exist
            return None

        prop_value = PropValue.from_value_and_labels(value, labels)
        return prop_value

    def load_stack_variable(self, sp_offset: int, size, endness=None) -> Optional[PropValue]:
        # normalize sp_offset to handle negative offsets
        sp_offset += 0x65536
        sp_offset &= (1 << self.arch.bits) - 1
        try:
            value, labels = self._stack_variables.load_with_labels(sp_offset, size=size, endness=endness)
        except SimMemoryMissingError as ex:
            # the stack variable does not exist - however, maybe some portion of it exists!
            if ex.missing_addr > sp_offset:
                # some data exist. load again
                try:
                    value, labels = self._stack_variables.load_with_labels(sp_offset,
                                                                           size=ex.missing_addr - sp_offset,
                                                                           endness=endness)
                    # then we zero-extend both the value and labels
                    if value is not None and len(labels) == 1 and labels[0][0] == 0:
                        value = claripy.ZeroExt(ex.missing_size * self.arch.byte_width, value)
                        offset, offset_in_expr, size, label = labels[0]
                        labels = ((offset, offset_in_expr, size + ex.missing_size, label),)
                except SimMemoryMissingError:
                    # failed again... welp
                    return None
            else:
                return None

        prop_value = PropValue.from_value_and_labels(value, labels)
        return prop_value

    def add_replacement(self, codeloc, old, new):

        # do not replace anything with a call expression
        if isinstance(new, ailment.statement.Call):
            return
        else:
            from .call_expr_finder import CallExprFinder  # pylint:disable=import-outside-toplevel

            callexpr_finder = CallExprFinder()
            callexpr_finder.walk_expression(new)
            if callexpr_finder.has_call:
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

        if prop_count <= 1 or isinstance(new, ailment.Expr.StackBaseOffset) or (
                isinstance(old, ailment.Expr.Register) and self.arch.is_artificial_register(old.reg_offset, old.size)):
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


class PropagatorAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    PropagatorAnalysis implements copy propagation. It propagates values (either constant values or variables) and
    expressions inside a block or across a function.

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
                 load_callback=None, stack_pointer_tracker=None, only_consts=False, completed_funcs=None,
                 do_binops=True, store_tops=True, vex_cross_insn_opt=False, func_addr: Optional[int]=None,
                 gp: Optional[int]=None):
        if block is None and func is not None:
            # only func is specified. traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
        elif block is not None:
            # traversing a block (but func might be specified at the same time to provide extra information, e.g., the
            # value for register t9 for MIPS32/64 binaries)
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._base_state = base_state
        self._function = func
        self._func_addr = func_addr if func_addr is not None else (None if func is None else func.addr)
        self._max_iterations = max_iterations
        self._load_callback = load_callback
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions
        self._only_consts = only_consts
        self._completed_funcs = completed_funcs
        self._do_binops = do_binops
        self._store_tops = store_tops
        self._vex_cross_insn_opt = vex_cross_insn_opt
        self._gp = gp

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

        # optimization: skip state copying for the initial state
        self._initial_state = None

        self._analyze()

    #
    # Main analysis routines
    #

    def _node_key(self, node: Union[ailment.Block,pyvex.IRSB]) -> Any:
        if type(node) is ailment.Block:
            return node.addr, node.idx
        elif type(node) is pyvex.IRSB:
            return node.addr
        # fallback
        return node

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        if isinstance(node, ailment.Block):
            # AIL
            state = PropagatorAILState(self.project.arch, project=self.project, only_consts=self._only_consts,
                                       gp=self._gp)
            ail = True
        else:
            # VEX
            state = PropagatorVEXState(self.project.arch, project=self.project, only_consts=self._only_consts,
                                       do_binops=self._do_binops, store_tops=self._store_tops,
                                       gp=self._gp)
            spoffset_var = self._engine_vex.sp_offset(0)
            ail = False
            state.store_register(self.project.arch.sp_offset,
                                 self.project.arch.bytes,
                                 spoffset_var,
                                 )

        if self.project.arch.name == "MIPS64":
            if self._func_addr is not None:
                if ail:
                    reg_expr = ailment.Expr.Register(None, None, self.project.arch.registers['t9'][0],
                                                     self.project.arch.registers['t9'][1])
                    reg_value = ailment.Expr.Const(None, None, self._func_addr, 64)
                    state.store_register(reg_expr,
                                         PropValue(claripy.BVV(self._func_addr, 64),
                                                   offset_and_details={0: Detail(8, reg_value, CodeLocation(0, 0))}),
                                         )
                else:
                    state.store_register(self.project.arch.registers['t9'][0],  # pylint:disable=too-many-function-args
                                         self.project.arch.registers['t9'][1],
                                         claripy.BVV(self._func_addr, 64),
                                         )
        elif self.project.arch.name == "MIPS32":
            if self._func_addr is not None:
                if ail:
                    reg_expr = ailment.Expr.Register(None, None, self.project.arch.registers['t9'][0],
                                                                 self.project.arch.registers['t9'][1])
                    reg_value = ailment.Expr.Const(None, None, self._func_addr, 32)
                    state.store_register(reg_expr,
                                         PropValue(claripy.BVV(self._func_addr, 32),
                                                   offset_and_details={0: Detail(4, reg_value, CodeLocation(0, 0))}),
                                         )
                else:
                    state.store_register(self.project.arch.registers['t9'][0],  # pylint:disable=too-many-function-args
                                         self.project.arch.registers['t9'][1],
                                         claripy.BVV(self._func_addr, 32),
                                         )

        self._initial_state = state
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
            block = self.project.factory.block(node.addr, node.size, opt_level=1,
                                               cross_insn_opt=self._vex_cross_insn_opt)
            block_key = node.addr
            engine = self._engine_vex
            if block.size == 0:
                # maybe the block is not decodeable
                return False, state

        if state is not self._initial_state:
            # make a copy of the state if it's not the initial state
            state = state.copy()
        else:
            # clear self._initial_state so that we *do not* run this optimization again!
            self._initial_state = None

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
