
import logging
from typing import Optional  # pylint:disable=unused-import
from collections import defaultdict

import ailment
import pyvex

from ...block import Block
from ...codenode import CodeNode
from ...misc.ux import deprecated
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis
from ..code_location import CodeLocation
from .atoms import Register
from .constants import OP_BEFORE, OP_AFTER
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX
from .live_definitions import LiveDefinitions
from .subject import Subject
from .uses import Uses


l = logging.getLogger(name=__name__)


class ReachingDefinitionsAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    ReachingDefinitionsAnalysis is a text-book implementation of a static data-flow analysis that works on either a
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
                 observation_points=None, init_state=None, cc=None, function_handler=None,
                 current_local_call_depth=1, maximum_local_call_depth=5, observe_all=False, visited_blocks=None,
                 dep_graph=None, observe_callback=None):
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
                                                Default to None: the analysis then initialize its own abstract state,
                                                based on the given <Subject>.
        :param SimCC cc:                        Calling convention of the function.
        :param list function_handler:           Handler for functions, naming scheme: handle_<func_name>|local_function(
                                                <ReachingDefinitions>, <Codeloc>, <IP address>).
        :param int current_local_call_depth:    Current local function recursion depth.
        :param int maximum_local_call_depth:    Maximum local function recursion depth.
        :param Boolean observe_all:             Observe every statement, both before and after.
        :param List<ailment.Block|Block|CodeNode|CFGNode> visited_blocks:
                                                A list of previously visited blocks.
        :param Optional[DepGraph] dep_graph:    An initial dependency graph to add the result of the analysis to. Set it
                                                to None to skip dependency graph generation.
        """

        self._subject = Subject(subject, self.kb.cfgs['CFGFast'], func_graph, cc)
        self._graph_visitor = self._subject.visitor

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=self._graph_visitor)

        self._track_tmps = track_tmps
        self._max_iterations = max_iterations
        self._observation_points = observation_points
        self._init_state = init_state
        self._function_handler = function_handler
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth

        self._dep_graph = dep_graph
        self.current_codeloc = None
        self.codeloc_uses = set()

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self

        self._observe_all = observe_all
        self._observe_callback = observe_callback

        # sanity check
        if self._observation_points and any(not type(op) is tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        if type(self) is ReachingDefinitionsAnalysis and \
                not self._observe_all and \
                not self._observation_points and \
                not self._observe_callback:
            l.warning('No observation point is specified. '
                      'You cannot get any analysis result from performing the analysis.'
                      )

        self._node_iterations = defaultdict(int)

        self._engine_vex = SimEngineRDVEX(self.project, self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)
        self._engine_ail = SimEngineRDAIL(self.project, self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)

        self._visited_blocks = visited_blocks or []

        self.observed_results = {}
        self.all_definitions = set()
        self.all_uses = Uses()

        self._analyze()

    @property
    def one_result(self):

        if not self.observed_results:
            raise ValueError('No result is available.')
        if len(self.observed_results) != 1:
            raise ValueError("More than one results are available.")

        return next(iter(self.observed_results.values()))

    @property
    def dep_graph(self):
        return self._dep_graph

    @property
    def visited_blocks(self):
        return self._visited_blocks

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
            raise KeyError("Reaching definitions are not available at observation point %s. "
                            "Did you specify that observation point?" % str(key))

        return self.observed_results[key]

    def node_observe(self, node_addr, state, op_type):
        """
        :param int node_addr:
        :param angr.analyses.reaching_definitions.LiveDefinitions state:
        :param angr.analyses.reaching_definitions.constants op_type: OP_BEFORE, OP_AFTER
        """

        key = 'node', node_addr, op_type

        observe = False

        if self._observe_all:
            observe = True
        elif self._observation_points is not None and key in self._observation_points:
            observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback('node', addr=node_addr, state=state, op_type=op_type)

        if observe:
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
        observe = False

        if self._observe_all:
            observe = True
        elif self._observation_points is not None and key in self._observation_points:
            observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback('insn', addr=insn_addr, stmt=stmt, block=block, state=state,
                                             op_type=op_type)

        if not observe:
            return

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

    @property
    def subject(self):
        return self._subject

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node):
        if self._init_state is not None:
            return self._init_state
        else:
            return LiveDefinitions(
                self.project.arch, self.subject, track_tmps=self._track_tmps, analysis=self
            )

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):
        """

        :param node:
        :param LiveDefinitions state:
        :return:
        """

        self._visited_blocks.append(node)

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
        state, self._visited_blocks = engine.process(
            state,
            block=block,
            fail_fast=self._fail_fast,
            visited_blocks=self._visited_blocks
        )  # type: LiveDefinitions, set

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

        # update all definitions and all uses
        self.all_definitions |= state.all_definitions
        for use in [state.stack_uses, state.register_uses]:
            self.all_uses.merge(use)

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass
