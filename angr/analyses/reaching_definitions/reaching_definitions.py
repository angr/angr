import logging
from collections import defaultdict

import ailment
import pyvex

from .atoms import Register, MemoryLocation, Tmp, Parameter
from .constants import OP_BEFORE, OP_AFTER
from .dataset import DataSet
from .definition import Definition
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX
from .undefined import Undefined
from .uses import Uses
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from ...calling_conventions import SimRegArg, SimStackArg
from ...engines.light import SpOffset
from ...keyed_region import KeyedRegion

l = logging.getLogger('angr.analyses.reaching_definitions')


class LiveDefinitions(object):
    def __init__(self, arch, loader, track_tmps=False, analysis=None, init_func=False, cc=None, func_addr=None):

        # handy short-hands
        self.arch = arch
        self.loader = loader
        self._track_tmps = track_tmps
        self.analysis = analysis

        self.register_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()
        self.tmp_definitions = {}

        if init_func:
            self._init_func(cc, func_addr)

        self.register_uses = Uses()
        self.memory_uses = Uses()
        self.tmp_uses = defaultdict(set)

        self._dead_virgin_definitions = set()  # definitions that are killed before used

    def __repr__(self):
        ctnt = "LiveDefs, %d regdefs, %d memdefs" % (len(self.register_definitions),
                                                                len(self.memory_definitions))
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

        # architecture depended initialization
        if self.arch.name.lower().find('ppc64') > -1:
            rtoc_value = self.loader.main_object.ppc64_initial_rtoc
            if rtoc_value:
                offset, size = self.arch.registers['rtoc']
                rtoc = Register(offset, size)
                rtoc_def = Definition(rtoc, None, DataSet(rtoc_value, self.arch.bits))
                self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = Definition(t9, None, DataSet(func_addr, self.arch.bits))
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def copy(self):
        rd = LiveDefinitions(
            self.arch,
            self.loader,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            init_func=False,
        )

        rd.register_definitions = self.register_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()
        rd._dead_virgin_definitions = self._dead_virgin_definitions.copy()

        return rd

    def merge(self, *others):

        state = self.copy()

        for other in others:
            state.register_definitions.merge(other.register_definitions)
            state.memory_definitions.merge(other.memory_definitions)

            state.register_uses.merge(other.register_uses)
            state.memory_uses.merge(other.memory_uses)

            state._dead_virgin_definitions |= other._dead_virgin_definitions

        return state

    def downsize(self):
        self.analysis = None

    def kill_definitions(self, atom, code_loc, data=None):
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance.

        :param Atom atom:
        :param CodeLocation code_loc:
        :param object data:
        :return: None
        """

        if data is None:
            data = DataSet(Undefined(), 8)

        self.kill_and_add_definition(atom, code_loc, data)

    def kill_and_add_definition(self, atom, code_loc, data):
        if type(atom) is Register:
            self._kill_and_add_register_definition(atom, code_loc, data)
        elif type(atom) is MemoryLocation:
            self._kill_and_add_memory_definition(atom, code_loc, data)
        elif type(atom) is Tmp:
            self._add_tmp_definition(atom, code_loc)
        else:
            raise NotImplementedError()

    def add_use(self, atom, code_loc):
        if type(atom) is Register:
            self._add_register_use(atom, code_loc)
        elif type(atom) is MemoryLocation:
            self._add_memory_use(atom, code_loc)
        elif type(atom) is Tmp:
            self._add_tmp_use(atom, code_loc)

    #
    # Private methods
    #

    def _kill_and_add_register_definition(self, atom, code_loc, data):

        # FIXME: check correctness
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)
        if current_defs:
            uses = set()
            for current_def in current_defs:
                uses |= self.register_uses.get_current_uses(current_def)
            if not uses:
                self._dead_virgin_definitions |= current_defs

        definition = Definition(atom, code_loc, data)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.register_definitions.set_object(atom.reg_offset, definition, atom.size)

    def _kill_and_add_memory_definition(self, atom, code_loc, data):
        definition = Definition(atom, code_loc, data)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.memory_definitions.set_object(atom.addr, definition, atom.size)

    def _add_tmp_definition(self, atom, code_loc):

        self.tmp_definitions[atom.tmp_idx] = (atom, code_loc)

    def _add_register_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)

        for current_def in current_defs:
            self.register_uses.add_use(current_def, code_loc)

    def _add_memory_use(self, atom, code_loc):

        # get all current definitions
        current_defs = self.memory_definitions.get_objects_by_offset(atom.addr)

        for current_def in current_defs:
            self.memory_uses.add_use(current_def, code_loc)

    def _add_tmp_use(self, atom, code_loc):

        current_def = self.tmp_definitions[atom.tmp_idx]
        self.tmp_uses[atom.tmp_idx].add((code_loc, current_def))


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

    def __init__(self, func=None, block=None, func_graph=None, max_iterations=3, track_tmps=False,
                 observation_points=None, init_state=None, init_func=False, cc=None, function_handler=None,
                 current_local_call_depth=1, maximum_local_call_depth=5):
        """

        :param angr.knowledge.Function func:    The function to run reaching definition analysis on.
        :param block:                           A single block to run reaching definition analysis on. You cannot
                                                specify both `func` and `block`.
        :param func_graph:                      Alternative graph for function.graph.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param bool track_tmps:                 Whether tmps are tracked or not.
        :param iterable observation_points:     A collection of tuples of (ins_addr, OP_TYPE) defining where reaching
                                                definitions should be copied and stored. OP_TYPE can be OP_BEFORE or
                                                OP_AFTER.
        :param angr.analyses.reaching_definitions.reaching_definitions.LiveDefinitions init_state:
                                                An optional initialization state. The analysis creates and works on a
                                                copy.
        :param bool init_func:                  Whether stack and arguments are initialized or not.
        :param SimCC cc:                        Calling convention of the function.
        :param list function_handler:           Handler for functions, naming scheme: handle_<func_name>|local_function(
                                                <ReachingDefinitions>, <Codeloc>, <IP address>).
        :param int current_local_call_depth:    Current local function recursion depth.
        :param int maximum_local_call_depth:    Maximum local function recursion depth.
        """

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

        self._track_tmps = track_tmps
        self._max_iterations = max_iterations
        self._function = func
        self._block = block
        self._observation_points = observation_points
        self._init_state = init_state
        self._function_handler = function_handler
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self

        # ignore initialization parameters if a block was passed
        if self._function is not None:
            self._init_func = init_func
            self._cc = cc
            self._func_addr = func.addr
        else:
            self._init_func = False
            self._cc = None
            self._func_addr = None

        # sanity check
        if self._observation_points and any(not type(op) is tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        if not self._observation_points:
            l.warning('No observation point is specified. '
                      'You cannot get any analysis result from performing the analysis.'
                      )

        self._node_iterations = defaultdict(int)
        self._states = {}

        self._engine_vex = SimEngineRDVEX(self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)
        self._engine_ail = SimEngineRDAIL(self._current_local_call_depth, self._maximum_local_call_depth,
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

    def observe(self, ins_addr, stmt, block, state, ob_type):
        if self._observation_points is not None and (ins_addr, ob_type) in self._observation_points:
            if isinstance(stmt, pyvex.IRStmt.IRStmt):
                # it's an angr block
                vex_block = block.vex
                # OP_BEFORE: stmt has to be IMark
                if ob_type == OP_BEFORE and type(stmt) is pyvex.IRStmt.IMark:
                    self.observed_results[(ins_addr, ob_type)] = state.copy()
                # OP_AFTER: stmt has to be last stmt of block or next stmt has to be IMark
                elif ob_type == OP_AFTER:
                    idx = vex_block.statements.index(stmt)
                    if idx == len(vex_block.statements) - 1 or type(
                            vex_block.statements[idx + 1]) is pyvex.IRStmt.IMark:
                        self.observed_results[(ins_addr, ob_type)] = state.copy()
            elif isinstance(stmt, ailment.Stmt.Statement):
                # it's an AIL block
                self.observed_results[(ins_addr, ob_type)] = state.copy()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        if self._init_state is not None:
            return self._init_state
        else:
            return LiveDefinitions(self.project.arch, self.project.loader, track_tmps=self._track_tmps,
                                   analysis=self, init_func=self._init_func, cc=self._cc, func_addr=self._func_addr)

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.addr
            engine = self._engine_vex

        state = state.copy()
        state = engine.process(state, block=block, fail_fast=self._fail_fast)

        # clear the tmp store
        # state.tmp_uses.clear()
        # state.tmp_definitions.clear()

        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(ReachingDefinitionAnalysis, "ReachingDefinitions")
