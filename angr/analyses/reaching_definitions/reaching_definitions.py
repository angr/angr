import logging
from collections import defaultdict

import ailment
import archinfo
import pyvex

from ...calling_conventions import SimRegArg, SimStackArg
from ...engines.light import SpOffset
from ...keyed_region import KeyedRegion
from ...block import Block
from ...knowledge_plugins.functions.function_manager import Function
from ...codenode import CodeNode
from ...misc.ux import deprecated
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from ..code_location import CodeLocation
from .atoms import Register, MemoryLocation, Tmp, Parameter
from .constants import OP_BEFORE, OP_AFTER
from .dataset import DataSet
from .definition import Definition
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX
from .undefined import Undefined
from .uses import Uses


l = logging.getLogger(name=__name__)


class LiveDefinitions:
    """
    Represents the internal state of the ReachingDefinitionAnalysis.

    It contains definitions and uses for register, stack, memory, and temporary variables, uncovered during the analysis.

    :param archinfo.Arch arch: The architecture targeted by the program.
    :param Boolean track_tmps: Only tells whether or not temporary variables should be taken into consideration when
                              representing the state of the analysis.
                              Should be set to true when the analysis has counted uses and definitions for temporary
                              variables, false otherwise.
    :param angr.analyses.analysis.Analysis analysis: The analysis that generated the state represented by this object.
    :param Boolean init_func: Whether or not the internal state of the analysis should be initialized.
    :param angr.calling_conventions.SimCC cc: The calling convention the analyzed function respects.
    :param int func_addr: The address of the analyzed function.
    :param int rtoc_value: When the targeted architecture is ppc64, the initial function needs to know the `rtoc_value`.
    """
    def __init__(self, arch, track_tmps=False, analysis=None, init_func=False, cc=None, func_addr=None,
                 rtoc_value=None):

        # handy short-hands
        self.arch = arch
        self._track_tmps = track_tmps
        self.analysis = analysis
        self.rtoc_value = rtoc_value

        self.register_definitions = KeyedRegion()
        self.stack_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()
        self.tmp_definitions = {}

        # sanity check
        if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not self.rtoc_value:
            raise ValueError('The architecture being ppc64, the parameter `rtoc_value` should be provided.')

        if init_func:
            self._init_func(cc, func_addr)

        self.register_uses = Uses()
        self.stack_uses = Uses()
        self.memory_uses = Uses()
        self.uses_by_codeloc = defaultdict(set)
        self.tmp_uses = defaultdict(set)

        self._dead_virgin_definitions = set()  # definitions that are killed before used

    def __repr__(self):
        ctnt = "LiveDefs, %d regdefs, %d stackdefs, %d memdefs" % (
            len(self.register_definitions),
            len(self.stack_definitions),
            len(self.memory_definitions),
        )
        if self._track_tmps:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    def _init_func(self, cc, func_addr):
        # initialize stack pointer
        sp = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp, None, DataSet(self.arch.initial_sp, self.arch.bits))
        self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)
        if self.arch.name.startswith('MIPS'):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9 = Register(self.arch.registers['t9'][0],self.arch.bytes)
            t9_def = Definition(t9, None, DataSet(func_addr,self.arch.bits))
            self.register_definitions.set_object(t9_def.offset,t9_def,t9_def.size)

        if cc is not None:
            for arg in cc.args:
                # initialize register parameters
                if type(arg) is SimRegArg:
                    # FIXME: implement reg_offset handling in SimRegArg
                    reg_offset = self.arch.registers[arg.reg_name][0]
                    reg = Register(reg_offset, self.arch.bytes)
                    reg_def = Definition(reg, None, DataSet(Parameter(reg), self.arch.bits))
                    self.register_definitions.set_object(reg.reg_offset, reg_def, reg.size)
                # initialize stack parameters
                elif type(arg) is SimStackArg:
                    ml = MemoryLocation(self.arch.initial_sp + arg.stack_offset, self.arch.bytes)
                    sp_offset = SpOffset(arg.size * 8, arg.stack_offset)
                    ml_def = Definition(ml, None, DataSet(Parameter(sp_offset), self.arch.bits))
                    self.memory_definitions.set_object(ml.addr, ml_def, ml.size)
                else:
                    raise TypeError('Unsupported parameter type %s.' % type(arg).__name__)

        # architecture dependent initialization
        if self.arch.name.lower().find('ppc64') > -1:
            offset, size = self.arch.registers['rtoc']
            rtoc = Register(offset, size)
            rtoc_def = Definition(rtoc, None, DataSet(self.rtoc_value, self.arch.bits))
            self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = Definition(t9, None, DataSet(func_addr, self.arch.bits))
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def copy(self):
        rd = LiveDefinitions(
            self.arch,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            init_func=False,
        )

        rd.register_definitions = self.register_definitions.copy()
        rd.stack_definitions = self.stack_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.stack_uses = self.stack_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()
        rd._dead_virgin_definitions = self._dead_virgin_definitions.copy()

        return rd


    def get_sp(self):
        """
        Return the concrete value contained by the stack pointer.
        """
        sp_definitions = self.register_definitions.get_objects_by_offset(self.arch.sp_offset)

        assert len(sp_definitions) == 1
        [sp_definition] = sp_definitions

        # Assuming sp_definition has only one concrete value.
        return sp_definition.data.get_first_element()


    def merge(self, *others):

        state = self.copy()

        for other in others:
            state.register_definitions.merge(other.register_definitions)
            state.stack_definitions.merge(other.stack_definitions)
            state.memory_definitions.merge(other.memory_definitions)

            state.register_uses.merge(other.register_uses)
            state.stack_uses.merge(other.stack_uses)
            state.memory_uses.merge(other.memory_uses)

            state._dead_virgin_definitions |= other._dead_virgin_definitions

        return state

    def downsize(self):
        self.analysis = None

    def kill_definitions(self, atom, code_loc, data=None, dummy=True):
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param Atom atom:
        :param CodeLocation code_loc:
        :param object data:
        :return: None
        """

        if data is None:
            data = DataSet(Undefined(atom.size), atom.size)

        self.kill_and_add_definition(atom, code_loc, data, dummy=dummy)

    def kill_and_add_definition(self, atom, code_loc, data, dummy=False):
        if type(atom) is Register:
            self._kill_and_add_register_definition(atom, code_loc, data, dummy=dummy)
        elif type(atom) is SpOffset:
            self._kill_and_add_stack_definition(atom, code_loc, data, dummy=dummy)
        elif type(atom) is MemoryLocation:
            self._kill_and_add_memory_definition(atom, code_loc, data, dummy=dummy)
        elif type(atom) is Tmp:
            self._add_tmp_definition(atom, code_loc, data)
        else:
            raise NotImplementedError()

    def add_use(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_use(atom, code_loc)
        elif type(atom) is SpOffset:
            self._add_stack_use(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_use(atom, code_loc)
        elif type(atom) is Tmp:
            self._add_tmp_use(atom, code_loc)

    def add_use_by_def(self, def_, code_loc):
        if type(def_.atom) is Register:
            self._add_register_use_by_def(def_, code_loc)
        elif type(def_.atom) is SpOffset:
            self._add_stack_use_by_def(def_, code_loc)
        elif type(def_.atom) is MemoryLocation:
            self._add_memory_use_by_def(def_, code_loc)
        elif type(def_.atom) is Tmp:
            self._add_tmp_use_by_def(def_, code_loc)
        else:
            raise TypeError()

    #
    # Private methods
    #

    def _kill_and_add_register_definition(self, atom, code_loc, data, dummy=False):

        # FIXME: check correctness
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)
        if current_defs:
            uses = set()
            for current_def in current_defs:
                uses |= self.register_uses.get_uses(current_def)
            if not uses:
                self._dead_virgin_definitions |= current_defs

        definition = Definition(atom, code_loc, data, dummy=dummy)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.register_definitions.set_object(atom.reg_offset, definition, atom.size)

    def _kill_and_add_stack_definition(self, atom, code_loc, data, dummy=False):
        current_defs = self.stack_definitions.get_objects_by_offset(atom.offset)
        if current_defs:
            uses = set()
            for current_def in current_defs:
                uses |= self.stack_uses.get_uses(current_def)
            if not uses:
                self._dead_virgin_definitions |= current_defs

        definition = Definition(atom, code_loc, data, dummy=dummy)
        self.stack_definitions.set_object(atom.offset, definition, data.bits // 8)

    def _kill_and_add_memory_definition(self, atom, code_loc, data, dummy=False):
        definition = Definition(atom, code_loc, data, dummy=dummy)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.memory_definitions.set_object(atom.addr, definition, atom.size)

    def _add_tmp_definition(self, atom, code_loc, data):

        if self._track_tmps:
            self.tmp_definitions[atom.tmp_idx] = Definition(atom, code_loc, data)
        else:
            self.tmp_definitions[atom.tmp_idx] = self.uses_by_codeloc[code_loc]

    def _add_register_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)

        for current_def in current_defs:
            self._add_register_use_by_def(current_def, code_loc)

    def _add_register_use_by_def(self, def_, code_loc):
        self.register_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_stack_use(self, atom, code_loc):
        """

        :param SpOffset atom:
        :param code_loc:
        :return:
        """

        current_defs = self.stack_definitions.get_objects_by_offset(atom.offset)

        for current_def in current_defs:
            self._add_stack_use_by_def(current_def, code_loc)

    def _add_stack_use_by_def(self, def_, code_loc):
        self.stack_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_memory_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.memory_definitions.get_objects_by_offset(atom.addr)

        for current_def in current_defs:
            self._add_memory_use_by_def(current_def, code_loc)

    def _add_memory_use_by_def(self, def_, code_loc):
        self.memory_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_tmp_use(self, atom, code_loc):

        if self._track_tmps:
            def_ = self.tmp_definitions[atom.tmp_idx]
            self._add_tmp_use_by_def(def_, code_loc)
        else:
            defs = self.tmp_definitions[atom.tmp_idx]
            for d in defs:
                assert not type(d.atom) is Tmp
                self.add_use_by_def(d, code_loc)

    def _add_tmp_use_by_def(self, def_, code_loc):
        self.tmp_uses[def_.atom.tmp_idx].add(code_loc)
        self.uses_by_codeloc[code_loc].add(def_)


class ReachingDefinitionAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    ReachingDefinitionAnalysis is a text-book implementation of a static data-flow analysis that works on either a
    function or a block. It supports both VEX and AIL. By registering observers to observation points, users may use
    this analysis to generate use-def chains, def-use chains, and reaching definitions, and perform other traditional
    data-flow analyses such as liveness analysis.

    * I've always wanted to find a better name for this analysis. Now I gave up and decided to live with this name for
      the foreseeable future (until a better name is proposed by someone else).
    * Aliasing is definitely a problem, and I forgot how aliasing is resolved in this implementation. I'll leave this
      as a post-graduation TODO.
    * Some more documentation and examples would be nice.
    """

    def __init__(self, subject=None, func_graph=None, max_iterations=3, track_tmps=False,
                 observation_points=None, init_state=None, init_func=False, cc=None, function_handler=None,
                 current_local_call_depth=1, maximum_local_call_depth=5, observe_all=False):
        """
        :param Block|Function subject: The subject of the analysis: a function, or a single basic block.
        :param func_graph:                      Alternative graph for function.graph.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param Boolean track_tmps:              Whether or not temporary variables should be taken into consideration
                                                during the analysis.
        :param iterable observation_points:     A collection of tuples of ("node"|"insn", ins_addr, OP_TYPE) defining
                                                where reaching definitions should be copied and stored. OP_TYPE can be
                                                OP_BEFORE or OP_AFTER.
        :param angr.analyses.reaching_definitions.reaching_definitions.LiveDefinitions init_state:
                                                An optional initialization state. The analysis creates and works on a
                                                copy.
        :param Boolean init_func:               Whether stack and arguments are initialized or not.
        :param SimCC cc:                        Calling convention of the function.
        :param list function_handler:           Handler for functions, naming scheme: handle_<func_name>|local_function(
                                                <ReachingDefinitions>, <Codeloc>, <IP address>).
        :param int current_local_call_depth:    Current local function recursion depth.
        :param int maximum_local_call_depth:    Maximum local function recursion depth.
        :param Boolean observe_all:             Observe every statement, both before and after.
        """

        def _init_subject(subject):
            """
            :param ailment.Block|angr.Block|Function subject:
            :return Tuple[ailment.Block|angr.Block, SimCC, Function, GraphVisitor, Boolean]:
                 Return the values for `_block`, `_cc`, `_function`, `_graph_visitor`, `_init_func`.
            """
            if isinstance(subject, Function):
                return (None, cc, subject, FunctionGraphVisitor(subject, func_graph), init_func)
            elif isinstance(subject, (ailment.Block, Block)):
                return (subject, None, None, SingleNodeGraphVisitor(subject), False)
            else:
                raise ValueError('Unsupported analysis target.')

        self._block, self._cc, self._function, self._graph_visitor, self._init_func = _init_subject(subject)

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=self._graph_visitor)

        self._track_tmps = track_tmps
        self._max_iterations = max_iterations
        self._observation_points = observation_points
        self._init_state = init_state
        self._function_handler = function_handler
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self

        self._observe_all = observe_all

        # sanity check
        if self._observation_points and any(not type(op) is tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        if type(self) is ReachingDefinitionAnalysis and not self._observe_all and not self._observation_points:
            l.warning('No observation point is specified. '
                      'You cannot get any analysis result from performing the analysis.'
                      )

        self._node_iterations = defaultdict(int)
        self._states = {}

        self._engine_vex = SimEngineRDVEX(self.project, self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)
        self._engine_ail = SimEngineRDAIL(self.project, self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)

        self.observed_results = {}

        self._analyze()

    @property
    def one_result(self):

        if not self.observed_results:
            raise ValueError('No result is available.')
        if len(self.observed_results) != 1:
            raise ValueError("More than one results are available.")

        return next(iter(self.observed_results.values()))

    @deprecated(replacement="get_reaching_definitions_by_insn")
    def get_reaching_definitions(self, ins_addr, op_type):
        return self.get_reaching_definitions_by_insn(ins_addr, op_type)

    def get_reaching_definitions_by_insn(self, ins_addr, op_type):
        key = 'insn', ins_addr, op_type
        if key not in self.observed_results:
            raise KeyError(("Reaching definitions are not available at observation point %s. "
                            "Did you specify that observation point?") % key)

        return self.observed_results[key]

    def get_reaching_definitions_by_node(self, node_addr, op_type):
        key = 'node', node_addr, op_type
        if key not in self.observed_results:
            raise KeyError(("Reaching definitions are not available at observation point %s. "
                            "Did you specify that observation point?") % key)

        return self.observed_results[key]

    def node_observe(self, node_addr, state, op_type):
        """
        :param int node_addr:
        :param angr.analyses.reaching_definitions.LiveDefinitions state:
        :param angr.analyses.reaching_definitions.constants op_type: OP_BEFORE, OP_AFTER
        """

        key = 'node', node_addr, op_type

        if self._observe_all or \
                self._observation_points is not None and key in self._observation_points:
            self.observed_results[key] = state

    def insn_observe(self, insn_addr, stmt, block, state, op_type):
        """
        :param int insn_addr:
        :param ailment.Stmt.Statement|pyvex.stmt.IRStmt stmt:
        :param angr.Block block:
        :param angr.analyses.reaching_definitions.LiveDefinitions state:
        :param angr.analyses.reaching_definitions.constants op_type: OP_BEFORE, OP_AFTER
        """

        key = 'insn', insn_addr, op_type

        if self._observe_all or \
                self._observation_points is not None and key in self._observation_points:
            if isinstance(stmt, pyvex.stmt.IRStmt):
                # it's an angr block
                vex_block = block.vex
                # OP_BEFORE: stmt has to be IMark
                if op_type == OP_BEFORE and type(stmt) is pyvex.stmt.IMark:
                    self.observed_results[key] = state.copy()
                # OP_AFTER: stmt has to be last stmt of block or next stmt has to be IMark
                elif op_type == OP_AFTER:
                    idx = vex_block.statements.index(stmt)
                    if idx == len(vex_block.statements) - 1 or type(
                            vex_block.statements[idx + 1]) is pyvex.IRStmt.IMark:
                        self.observed_results[key] = state.copy()
            elif isinstance(stmt, ailment.Stmt.Statement):
                # it's an AIL block
                self.observed_results[key] = state.copy()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node):
        if self._init_state is not None:
            return self._init_state
        else:
            func_addr = self._function.addr if self._function else None
            return LiveDefinitions(self.project.arch, track_tmps=self._track_tmps, analysis=self,
                                   init_func=self._init_func, cc=self._cc, func_addr=func_addr)

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        elif isinstance(node, (Block, CodeNode)):
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.addr
            engine = self._engine_vex
        else:
            l.warning("Unsupported node type %s.", node.__class__)
            return False, state.copy()

        self.node_observe(node.addr, state, OP_BEFORE)

        state = state.copy()
        state = engine.process(state, block=block, fail_fast=self._fail_fast)

        # clear the tmp store
        # state.tmp_uses.clear()
        # state.tmp_definitions.clear()

        self._node_iterations[block_key] += 1

        if not self._graph_visitor.successors(node):
            # no more successors. kill definitions of certain registers
            if isinstance(node, ailment.Block):
                codeloc = CodeLocation(node.addr, len(node.statements))
            elif isinstance(node, Block):
                codeloc = CodeLocation(node.addr, len(node.vex.statements))
            else: #if isinstance(node, CodeNode):
                codeloc = CodeLocation(node.addr, 0)
            state.kill_definitions(Register(self.project.arch.sp_offset, self.project.arch.bytes),
                                   codeloc)
            state.kill_definitions(Register(self.project.arch.ip_offset, self.project.arch.bytes),
                                   codeloc)
        self.node_observe(node.addr, state, OP_AFTER)

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(ReachingDefinitionAnalysis, "ReachingDefinitions")
