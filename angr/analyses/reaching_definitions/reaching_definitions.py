
import logging
from typing import Optional, DefaultDict, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING
from collections import defaultdict
from functools import partial

import ailment
import pyvex

from ...block import Block
from ...knowledge_plugins.cfg.cfg_node import CFGNode
from ...codenode import CodeNode
from ...engines.light import SimEngineLight
from ...knowledge_plugins.functions import Function
from ...knowledge_plugins.key_definitions import ReachingDefinitionsModel, LiveDefinitions
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...misc.ux import deprecated
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis
from ..cfg_slice_to_sink import slice_cfg_graph, slice_function_graph
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX
from .rd_state import ReachingDefinitionsState
from .subject import Subject, SubjectType
if TYPE_CHECKING:
    from .dep_graph import DepGraph


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
                 observation_points=None, init_state: ReachingDefinitionsState=None, cc=None, function_handler=None,
                 call_stack=None, maximum_local_call_depth=5, observe_all=False, visited_blocks=None,
                 dep_graph: Optional['DepGraph']=None, observe_callback=None):
        """
        :param Union[Block,Function,CFGSliceToSink] subject:
                                                The subject of the analysis: a function, a single basic block, or the
                                                representation of a slice to a sink.
        :param func_graph:                      Alternative graph for function.graph.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param Boolean track_tmps:              Whether or not temporary variables should be taken into consideration
                                                during the analysis.
        :param iterable observation_points:     A collection of tuples of ("node"|"insn", ins_addr, OP_TYPE) defining
                                                where reaching definitions should be copied and stored. OP_TYPE can be
                                                OP_BEFORE or OP_AFTER.
        :param init_state:                      An optional initialization state. The analysis creates and works on a
                                                copy.
                                                Default to None: the analysis then initialize its own abstract state,
                                                based on the given <Subject>.
        :param SimCC cc:                        Calling convention of the function.
        :param FunctionHandler function_handler:
                                                The function handler to update the analysis state and results on
                                                function calls.
        :param call_stack:                      An ordered list of Functions representing the call stack leading to the
                                                analysed subject, from older to newer calls.
        :param int maximum_local_call_depth:    Maximum local function recursion depth.
        :param Boolean observe_all:             Observe every statement, both before and after.
        :param visited_blocks:                  A set of previously visited blocks.
        :param dep_graph:                       An initial dependency graph to add the result of the analysis to. Set it
                                                to None to skip dependency graph generation.
        """

        self._subject = Subject(subject, self.kb.cfgs['CFGFast'], func_graph, cc)
        self._graph_visitor = self._subject.visitor

        if self._subject.type is SubjectType.CFGSliceToSink:
            self._update_kb_content_from_slice()
            self._graph_visitor.reset()

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=self._graph_visitor)

        self._track_tmps = track_tmps
        self._max_iterations = max_iterations
        self._observation_points = observation_points
        self._init_state = init_state
        self._maximum_local_call_depth = maximum_local_call_depth

        self._dep_graph = dep_graph

        if function_handler is None:
            self._function_handler = function_handler
        else:
            self._function_handler = function_handler.hook(self)

        def _init_call_stack(call_stack, subject):
            if self._subject.type == SubjectType.Function:
                return call_stack + [ subject ]
            elif self._subject.type == SubjectType.Block:
                cfg = self.kb.cfgs['CFGFast']
                function_address = cfg.get_any_node(subject.addr).function_address
                function = self.kb.functions.function(function_address)
                if len(call_stack) > 0 and call_stack[-1] == function:
                    return call_stack
                else:
                    return call_stack + [ function ]
            elif self._subject.type == SubjectType.CFGSliceToSink:
                # CFGSliceToSink does not update the "call stack" itself.
                return call_stack
            else:
                raise ValueError('self._subject.type is of unexpected kind')

        self._call_stack: List[Function] = _init_call_stack(call_stack or [], subject)

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

        self._node_iterations: DefaultDict[int, int] = defaultdict(int)

        self._engine_vex = SimEngineRDVEX(self.project, self._call_stack, self._maximum_local_call_depth,
                                          functions=self.kb.functions,
                                          function_handler=self._function_handler)
        self._engine_ail = SimEngineRDAIL(self.project, self._call_stack, self._maximum_local_call_depth,
                                          function_handler=self._function_handler)

        self._visited_blocks: Set[Any] = visited_blocks or set()
        self.model: ReachingDefinitionsModel = ReachingDefinitionsModel(
            func_addr=self.subject.content.addr if isinstance(self.subject.content, Function) else None)

        self._analyze()

    def _update_kb_content_from_slice(self):
        # Removes the nodes that are not in the slice from the CFG.
        cfg = self.kb.cfgs['CFGFast']
        slice_cfg_graph(cfg.graph, self._subject.content)
        for node in cfg.nodes():
            node._cfg_model = cfg

        # Removes the functions for which entrypoints are not present in the slice.
        for f in self.kb.functions:
            if f not in self._subject.content.nodes:
                del self.kb.functions[f]

        # Remove the nodes that are not in the slice from the functions' graphs.
        def _update_function_graph(cfg_slice_to_sink, function):
            if len(function.graph.nodes()) > 1:
                slice_function_graph(function.graph, cfg_slice_to_sink)
        list(map(
            partial(_update_function_graph, self._subject.content),
            self.kb.functions._function_map.values()
        ))

    @property
    def observed_results(self) -> Dict[Tuple[str,int,int],LiveDefinitions]:
        return self.model.observed_results

    @property
    def all_definitions(self):
        return self.model.all_definitions

    @all_definitions.setter
    def all_definitions(self, v):
        self.model.all_definitions = v

    @property
    def all_uses(self):
        return self.model.all_uses

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

    def _current_local_call_depth(self):
        return len(self._call_stack)

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

    def node_observe(self, node_addr: int, state: ReachingDefinitionsState, op_type: int) -> None:
        """
        :param node_addr:   Address of the node.
        :param state:       The analysis state.
        :param op_type:     Type of the bbservation point. Must be one of the following: OP_BEFORE, OP_AFTER.
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
            self.observed_results[key] = state.live_definitions

    def insn_observe(self, insn_addr: int, stmt: Union[ailment.Stmt.Statement,pyvex.stmt.IRStmt],
                     block: Union[Block,ailment.Block], state: ReachingDefinitionsState, op_type: int) -> None:
        """
        :param insn_addr:   Address of the instruction.
        :param stmt:        The statement.
        :param block:       The current block.
        :param state:       The abstract analysis state.
        :param op_type:     Type of the observation point. Must be one of the following: OP_BEORE, OP_AFTER.
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
                self.observed_results[key] = state.live_definitions.copy()
            # OP_AFTER: stmt has to be last stmt of block or next stmt has to be IMark
            elif op_type == OP_AFTER:
                idx = vex_block.statements.index(stmt)
                if idx == len(vex_block.statements) - 1 or type(
                        vex_block.statements[idx + 1]) is pyvex.IRStmt.IMark:
                    self.observed_results[key] = state.live_definitions.copy()
        elif isinstance(stmt, ailment.Stmt.Statement):
            # it's an AIL block
            self.observed_results[key] = state.live_definitions.copy()

    @property
    def subject(self):
        return self._subject

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node) -> ReachingDefinitionsState:
        if self._init_state is not None:
            return self._init_state
        else:
            return ReachingDefinitionsState(
                self.project.arch, self.subject, track_tmps=self._track_tmps, analysis=self
            )

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state: ReachingDefinitionsState):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (reached fix-point, successor state)
        """

        self._visited_blocks.add(node)

        engine: SimEngineLight

        if isinstance(node, ailment.Block):
            block = node
            engine = self._engine_ail
        elif isinstance(node, (Block, CodeNode)):
            block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
            engine = self._engine_vex
        elif isinstance(node, CFGNode):
            if node.is_simprocedure or node.is_syscall:
                return False, state.copy()
            block = node.block
            engine = self._engine_vex
        else:
            l.warning("Unsupported node type %s.", node.__class__)
            return False, state.copy()

        self.node_observe(node.addr, state, OP_BEFORE)

        state = state.copy()
        state, self._visited_blocks, self._dep_graph = engine.process(
            state,
            block=block,
            fail_fast=self._fail_fast,
            visited_blocks=self._visited_blocks,
            dep_graph=self._dep_graph,
        )

        block_key = node.addr
        self._node_iterations[block_key] += 1

        # The Slice analysis happens recursively, so there will be no need to "start" any RDA from nodes that were
        # analysed "down the stack" during a run on a node.
        if self._subject.type == SubjectType.CFGSliceToSink:
            self._graph_visitor.remove_from_sorted_nodes(self._visited_blocks)

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
