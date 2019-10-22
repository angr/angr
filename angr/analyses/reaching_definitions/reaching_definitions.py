import logging
from collections import defaultdict

import ailment
import pyvex

from ...block import Block
from ...knowledge_plugins.functions.function_manager import Function
from ...codenode import CodeNode
from ...misc.ux import deprecated
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from ..code_location import CodeLocation
from .atoms import Register
from .constants import OP_BEFORE, OP_AFTER
from .live_definitions import LiveDefinitions
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX


l = logging.getLogger(name=__name__)


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
        :param angr.analyses.reaching_definitions.LiveDefinitions init_state:
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
