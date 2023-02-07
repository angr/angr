import logging
from typing import Optional, DefaultDict, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING
from collections import defaultdict

import ailment
import pyvex
from ..forward_analysis.visitors.graph import NodeType

from ...block import Block
from ...knowledge_plugins.cfg.cfg_node import CFGNode
from ...codenode import CodeNode
from ...engines.light import SimEngineLight
from ...knowledge_plugins.functions import Function
from ...knowledge_plugins.key_definitions import ReachingDefinitionsModel, LiveDefinitions
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER, ObservationPointType
from ...misc.ux import deprecated
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX
from .rd_state import ReachingDefinitionsState
from .subject import Subject, SubjectType
from .function_handler import FunctionHandler

if TYPE_CHECKING:
    from .dep_graph import DepGraph
    from typing import Literal, Iterable

    ObservationPoint = Tuple[Literal["insn", "node"], int, ObservationPointType]

l = logging.getLogger(name=__name__)


class ReachingDefinitionsAnalysis(
    ForwardAnalysis[ReachingDefinitionsState, NodeType], Analysis
):  # pylint:disable=abstract-method
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

    def __init__(
        self,
        subject: Union[Subject, ailment.Block, Block, Function] = None,
        func_graph=None,
        max_iterations=3,
        track_tmps=False,
        track_calls=None,
        track_consts=False,
        observation_points: "Iterable[ObservationPoint]" = None,
        init_state: ReachingDefinitionsState = None,
        cc=None,
        function_handler: "Optional[FunctionHandler]" = None,
        call_stack: Optional[List[int]] = None,
        maximum_local_call_depth=5,
        observe_all=False,
        visited_blocks=None,
        dep_graph: Optional["DepGraph"] = None,
        observe_callback=None,
        canonical_size=8,
    ):
        """
        :param subject:                         The subject of the analysis: a function, or a single basic block
        :param func_graph:                      Alternative graph for function.graph.
        :param int max_iterations:              The maximum number of iterations before the analysis is terminated.
        :param bool track_tmps:                 Whether or not temporary variables should be taken into consideration
                                                during the analysis.
        :param bool track_calls:                Whether or not calls will show up as elements in the def-use graph.
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
        :param call_stack:                      An ordered list of Function addresses representing the call stack
                                                leading to the analysed subject, from older to newer calls. Setting it
                                                to None to limit the analysis to a single function and disable call
                                                stack tracking; In that case, all contexts in CodeLocation will be
                                                None, which makes CodeLocation objects contextless.
        :param int maximum_local_call_depth:    Maximum local function recursion depth.
        :param Boolean observe_all:             Observe every statement, both before and after.
        :param visited_blocks:                  A set of previously visited blocks.
        :param dep_graph:                       An initial dependency graph to add the result of the analysis to. Set it
                                                to None to skip dependency graph generation.
        :param canonical_size:                  The sizes (in bytes) that objects with an UNKNOWN_SIZE are treated as
                                                for operations where sizes are necessary.
        """

        if not isinstance(subject, Subject):
            self._subject = Subject(subject, func_graph, cc)
        else:
            self._subject = subject
        self._graph_visitor = self._subject.visitor

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=self._graph_visitor
        )

        self._track_tmps = track_tmps
        self._track_calls = track_calls
        self._track_consts = track_consts
        self._max_iterations = max_iterations
        self._observation_points = observation_points
        self._init_state = init_state
        self._maximum_local_call_depth = maximum_local_call_depth
        self._canonical_size = canonical_size

        self._dep_graph = dep_graph

        if function_handler is None:
            self._function_handler = FunctionHandler().hook(self)
        else:
            self._function_handler = function_handler.hook(self)

        self._call_stack: Optional[List[int]] = None
        if call_stack is not None:
            self._call_stack = self._init_call_stack(call_stack, subject)

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self

        self._observe_all = observe_all
        self._observe_callback = observe_callback

        # sanity check
        if self._observation_points and any(type(op) is not tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        self._node_iterations: DefaultDict[int, int] = defaultdict(int)

        self._engine_vex = SimEngineRDVEX(
            self.project,
            self._call_stack,
            self._maximum_local_call_depth,
            functions=self.kb.functions,
            function_handler=self._function_handler,
        )
        self._engine_ail = SimEngineRDAIL(
            self.project, self._call_stack, self._maximum_local_call_depth, function_handler=self._function_handler
        )

        self._visited_blocks: Set[Any] = visited_blocks or set()
        self.model: ReachingDefinitionsModel = ReachingDefinitionsModel(
            func_addr=self.subject.content.addr if isinstance(self.subject.content, Function) else None
        )

        self._analyze()

    def _init_call_stack(self, call_stack: List[int], subject) -> List[int]:
        if self._subject.type == SubjectType.Function:
            return call_stack + [subject.addr]
        elif self._subject.type == SubjectType.Block:
            cfg = self.kb.cfgs.get_most_accurate()
            if cfg is None:
                # no CFG exists
                return call_stack
            cfg_node = cfg.get_any_node(subject.addr)
            if cfg_node is None:
                # we don't know which function this node belongs to
                return call_stack
            function_address = cfg_node.function_address
            function = self.kb.functions.function(function_address)
            if len(call_stack) > 0 and call_stack[-1] == function.addr:
                return call_stack
            else:
                return call_stack + [function.addr]
        elif self._subject.type == SubjectType.CallTrace:
            return call_stack + [self._subject.content.current_function_address()]
        else:
            raise ValueError("Unexpected subject type %s." % self._subject.type)

    @property
    def observed_results(self) -> Dict[Tuple[str, int, int], LiveDefinitions]:
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
            raise ValueError("No result is available.")
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
        key = "insn", ins_addr, op_type
        if key not in self.observed_results:
            raise KeyError(
                (
                    "Reaching definitions are not available at observation point %s. "
                    "Did you specify that observation point?"
                )
                % key
            )

        return self.observed_results[key]

    def get_reaching_definitions_by_node(self, node_addr, op_type):
        key = "node", node_addr, op_type
        if key not in self.observed_results:
            raise KeyError(
                "Reaching definitions are not available at observation point %s. "
                "Did you specify that observation point?" % str(key)
            )

        return self.observed_results[key]

    def node_observe(self, node_addr: int, state: ReachingDefinitionsState, op_type: ObservationPointType) -> None:
        """
        :param node_addr:   Address of the node.
        :param state:       The analysis state.
        :param op_type:     Type of the bbservation point. Must be one of the following: OP_BEFORE, OP_AFTER.
        """

        key = None

        observe = False

        if self._observe_all:
            observe = True
            key: ObservationPoint = ("node", node_addr, op_type)
        elif self._observation_points is not None:
            key: ObservationPoint = ("node", node_addr, op_type)
            if key in self._observation_points:
                observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback("node", addr=node_addr, state=state, op_type=op_type)
            if observe:
                key: ObservationPoint = ("node", node_addr, op_type)

        if observe:
            self.observed_results[key] = state.live_definitions

    def insn_observe(
        self,
        insn_addr: int,
        stmt: Union[ailment.Stmt.Statement, pyvex.stmt.IRStmt],
        block: Union[Block, ailment.Block],
        state: ReachingDefinitionsState,
        op_type: ObservationPointType,
    ) -> None:
        """
        :param insn_addr:   Address of the instruction.
        :param stmt:        The statement.
        :param block:       The current block.
        :param state:       The abstract analysis state.
        :param op_type:     Type of the observation point. Must be one of the following: OP_BEORE, OP_AFTER.
        """

        key = None
        observe = False

        if self._observe_all:
            observe = True
            key: ObservationPoint = ("insn", insn_addr, op_type)
        elif self._observation_points is not None:
            key: ObservationPoint = ("insn", insn_addr, op_type)
            if key in self._observation_points:
                observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback(
                "insn", addr=insn_addr, stmt=stmt, block=block, state=state, op_type=op_type
            )
            if observe:
                key: ObservationPoint = ("insn", insn_addr, op_type)

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
                if idx == len(vex_block.statements) - 1 or type(vex_block.statements[idx + 1]) is pyvex.IRStmt.IMark:
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

    def _initial_abstract_state(self, _node) -> ReachingDefinitionsState:
        if self._init_state is not None:
            return self._init_state
        else:
            return ReachingDefinitionsState(
                self.project.arch,
                self.subject,
                track_tmps=self._track_tmps,
                track_calls=self._track_calls,
                track_consts=self._track_consts,
                analysis=self,
                canonical_size=self._canonical_size,
            )

    # pylint: disable=no-self-use
    def _merge_states(self, _node, *states: ReachingDefinitionsState):
        merged_state, merge_occurred = states[0].merge(*states[1:])
        return merged_state, not merge_occurred

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

        self.node_observe(node.addr, state, OP_AFTER)

        # update all definitions and all uses
        self.all_definitions |= state.all_definitions
        for use in [state.stack_uses, state.heap_uses, state.register_uses, state.memory_uses]:
            self.all_uses.merge(use)

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass
