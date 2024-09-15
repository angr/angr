from __future__ import annotations
import logging
from typing import Any
from collections.abc import Iterable
from collections import defaultdict

import ailment
import pyvex

from angr.analyses import ForwardAnalysis
from ...block import Block
from ...knowledge_plugins.cfg.cfg_node import CFGNode
from ...codenode import CodeNode
from ...engines.light import SimEngineLight
from ...knowledge_plugins.functions import Function
from ...knowledge_plugins.key_definitions import ReachingDefinitionsModel, LiveDefinitions
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER, ObservationPointType, ObservationPoint
from ...code_location import CodeLocation, ExternalCodeLocation
from ...misc.ux import deprecated
from ..forward_analysis.visitors.graph import NodeType
from ..analysis import Analysis
from .engine_ail import SimEngineRDAIL
from .engine_vex import SimEngineRDVEX
from .rd_state import ReachingDefinitionsState
from .rd_initializer import RDAStateInitializer
from .subject import Subject, SubjectType
from .function_handler import FunctionHandler, FunctionCallRelationships
from .dep_graph import DepGraph
import contextlib


l = logging.getLogger(name=__name__)


class ReachingDefinitionsAnalysis(
    ForwardAnalysis[ReachingDefinitionsState, NodeType, object, object], Analysis
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
        subject: Subject | ailment.Block | Block | Function | str = None,
        func_graph=None,
        max_iterations=30,
        track_tmps=False,
        track_consts=True,
        observation_points: Iterable[ObservationPoint] | None = None,
        init_state: ReachingDefinitionsState = None,
        init_context=None,
        state_initializer: RDAStateInitializer | None = None,
        cc=None,
        function_handler: FunctionHandler | None = None,
        observe_all=False,
        visited_blocks=None,
        dep_graph: DepGraph | bool | None = True,
        observe_callback=None,
        canonical_size=8,
        stack_pointer_tracker=None,
        use_callee_saved_regs_at_return=True,
        interfunction_level: int = 0,
        track_liveness: bool = True,
        func_addr: int | None = None,
        element_limit: int = 5,
        merge_into_tops: bool = True,
    ):
        """
        :param subject:                         The subject of the analysis: a function, or a single basic block
        :param func_graph:                      Alternative graph for function.graph.
        :param max_iterations:                  The maximum number of iterations before the analysis is terminated.
        :param track_tmps:                      Whether or not temporary variables should be taken into consideration
                                                during the analysis.
        :param iterable observation_points:     A collection of tuples of ("node"|"insn", ins_addr, OP_TYPE) defining
                                                where reaching definitions should be copied and stored. OP_TYPE can be
                                                OP_BEFORE or OP_AFTER.
        :param init_state:                      An optional initialization state. The analysis creates and works on a
                                                copy.
                                                Default to None: the analysis then initialize its own abstract state,
                                                based on the given <Subject>.
        :param init_context:                    If init_state is not given, this is used to initialize the context
                                                field of the initial state's CodeLocation. The only default-supported
                                                type which may go here is a tuple of integers, i.e. a callstack.
                                                Anything else requires a custom FunctionHandler.
        :param cc:                              Calling convention of the function.
        :param function_handler:                The function handler to update the analysis state and results on
                                                function calls.
        :param observe_all:                     Observe every statement, both before and after.
        :param visited_blocks:                  A set of previously visited blocks.
        :param dep_graph:                       An initial dependency graph to add the result of the analysis to. Set it
                                                to None to skip dependency graph generation.
        :param canonical_size:                  The sizes (in bytes) that objects with an UNKNOWN_SIZE are treated as
                                                for operations where sizes are necessary.
        :param dep_graph:                       Set this to True to generate a dependency graph for the subject. It will
                                                be available as `result.dep_graph`.
        :param interfunction_level:             The number of functions we should recurse into. This parameter is only
                                                used if function_handler is not provided.
        :param track_liveness:                  Whether to track liveness information. This can consume
                                                sizeable amounts of RAM on large functions. (e.g. ~15GB for a function
                                                with 4k nodes)
        :param merge_into_tops:                 Merge known values into TOP if TOP is present.
                                                If True: {TOP} V {0xabc} = {TOP}
                                                If False: {TOP} V {0xabc} = {TOP, 0xabc}


        """

        if isinstance(subject, str):
            subject = self.kb.functions[subject]
        if not isinstance(subject, Subject):
            self._subject = Subject(subject, func_graph, cc)
        else:
            self._subject = subject
        self._graph_visitor = self._subject.visitor

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=self._graph_visitor
        )

        self._track_tmps = track_tmps
        self._track_consts = track_consts
        self._max_iterations = max_iterations
        self._observation_points = observation_points
        self._init_state = init_state
        self._canonical_size = canonical_size
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        self._func_addr = func_addr
        self._element_limit = element_limit
        self._merge_into_tops = merge_into_tops

        if dep_graph is None or dep_graph is False:
            self._dep_graph = None
        elif dep_graph is True:
            self._dep_graph = DepGraph()
        else:
            self._dep_graph = dep_graph

        if function_handler is None:
            self._function_handler = FunctionHandler(interfunction_level).hook(self)
        else:
            if interfunction_level != 0:
                l.warning("RDA(interfunction_level=XXX) doesn't do anything if you provide a function handler")
            self._function_handler = function_handler.hook(self)

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self
            # There should never be an initializer needed then
            self._state_initializer = None
        else:
            self._state_initializer = state_initializer

        self._init_context = init_context

        self._observe_all = observe_all
        self._observe_callback = observe_callback

        # sanity check
        if self._observation_points and any(type(op) is not tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        self._node_iterations: defaultdict[int, int] = defaultdict(int)

        self.model: ReachingDefinitionsModel = ReachingDefinitionsModel(
            func_addr=self.subject.content.addr if isinstance(self.subject.content, Function) else None,
            track_liveness=track_liveness,
        )

        bp_as_gpr = False
        the_func = None
        if isinstance(self.subject.content, Function):
            the_func = self.subject.content
        else:
            if self._func_addr is not None:
                with contextlib.suppress(KeyError):
                    the_func = self.kb.functions.get_by_addr(self._func_addr)
        if the_func is not None:
            bp_as_gpr = the_func.info.get("bp_as_gpr", False)

        self._engine_vex = SimEngineRDVEX(
            self.project,
            functions=self.kb.functions,
            function_handler=self._function_handler,
        )
        self._engine_ail = SimEngineRDAIL(
            self.project,
            function_handler=self._function_handler,
            stack_pointer_tracker=stack_pointer_tracker,
            use_callee_saved_regs_at_return=self._use_callee_saved_regs_at_return,
            bp_as_gpr=bp_as_gpr,
        )

        self._visited_blocks: set[Any] = visited_blocks or set()
        self.function_calls: dict[CodeLocation, FunctionCallRelationships] = {}

        self._analyze()

    @property
    def observed_results(self) -> dict[tuple[str, int, int], LiveDefinitions]:
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
    def dep_graph(self) -> DepGraph:
        if self._dep_graph is None:
            raise ValueError(
                "Cannot access dep_graph if the analysis was not configured to generate one. Try passing "
                "dep_graph=True to the RDA constructor."
            )
        return self._dep_graph

    @property
    def visited_blocks(self):
        return self._visited_blocks

    @deprecated(replacement="get_reaching_definitions_by_insn")
    def get_reaching_definitions(self, ins_addr, op_type):
        return self.get_reaching_definitions_by_insn(ins_addr, op_type)

    def get_reaching_definitions_by_insn(self, ins_addr, op_type):
        key = "insn", ins_addr, op_type
        if key not in self.observed_results:
            raise KeyError(
                f"Reaching definitions are not available at observation point {key!s}. "
                "Did you specify that observation point?"
            )

        return self.observed_results[key]

    def get_reaching_definitions_by_node(self, node_addr, op_type):
        key = "node", node_addr, op_type
        if key not in self.observed_results:
            raise KeyError(
                f"Reaching definitions are not available at observation point {key!s}. "
                "Did you specify that observation point?"
            )

        return self.observed_results[key]

    def node_observe(
        self,
        node_addr: int,
        state: ReachingDefinitionsState,
        op_type: ObservationPointType,
        node_idx: int | None = None,
    ) -> None:
        """
        :param node_addr:   Address of the node.
        :param state:       The analysis state.
        :param op_type:     Type of the observation point. Must be one of the following: OP_BEFORE, OP_AFTER.
        :param node_idx:    ID of the node. Used in AIL to differentiate blocks with the same address.
        """

        key = None

        observe = False

        if self._observe_all:
            observe = True
            key: ObservationPoint = (
                ("node", node_addr, op_type) if node_idx is None else ("node", (node_addr, node_idx), op_type)
            )
        elif self._observation_points is not None:
            key: ObservationPoint = (
                ("node", node_addr, op_type) if node_idx is None else ("node", (node_addr, node_idx), op_type)
            )
            if key in self._observation_points:
                observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback("node", addr=node_addr, state=state, op_type=op_type, node_idx=node_idx)
            if observe:
                key: ObservationPoint = (
                    ("node", node_addr, op_type) if node_idx is None else ("node", (node_addr, node_idx), op_type)
                )

        if observe:
            self.observed_results[key] = state.live_definitions

    def insn_observe(
        self,
        insn_addr: int,
        stmt: ailment.Stmt.Statement | pyvex.stmt.IRStmt,
        block: Block | ailment.Block,
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

    def stmt_observe(
        self,
        stmt_idx: int,
        stmt: ailment.Stmt.Statement | pyvex.stmt.IRStmt,
        block: Block | ailment.Block,
        state: ReachingDefinitionsState,
        op_type: ObservationPointType,
    ) -> None:
        """

        :param stmt_idx:
        :param stmt:
        :param block:
        :param state:
        :param op_type:
        :return:
        """

        key = None
        observe = False

        block_idx = block.idx if isinstance(block, ailment.Block) else None
        if self._observe_all:
            observe = True
            key: ObservationPoint = ("stmt", (block.addr, block_idx, stmt_idx), op_type)
        elif self._observation_points is not None:
            key: ObservationPoint = ("stmt", (block.addr, block_idx, stmt_idx), op_type)
            if key in self._observation_points:
                observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback(
                "stmt", stmt_idx=stmt_idx, stmt=stmt, block=block, state=state, op_type=op_type
            )
            if observe:
                key: ObservationPoint = ("stmt", (block.addr, block_idx, stmt_idx), op_type)

        if not observe:
            return

        if isinstance(stmt, pyvex.stmt.IRStmt):
            # it's an angr block
            self.observed_results[key] = state.live_definitions.copy()
        elif isinstance(stmt, ailment.Stmt.Statement):
            # it's an AIL block
            self.observed_results[key] = state.live_definitions.copy()

    def exit_observe(
        self,
        node_addr: int,
        exit_stmt_idx: int,
        block: Block | ailment.Block,
        state: ReachingDefinitionsState,
        node_idx: int | None = None,
    ):
        observe = False
        key = None

        if self._observe_all:
            observe = True
            key = (
                ("exit", (node_addr, exit_stmt_idx), ObservationPointType.OP_AFTER)
                if node_idx is None
                else ("exit", (node_addr, node_idx, exit_stmt_idx), ObservationPointType.OP_AFTER)
            )
        elif self._observation_points is not None:
            key = (
                ("exit", (node_addr, exit_stmt_idx), ObservationPointType.OP_AFTER)
                if node_idx is None
                else ("exit", (node_addr, node_idx, exit_stmt_idx), ObservationPointType.OP_AFTER)
            )
            if key in self._observation_points:
                observe = True
        elif self._observe_callback is not None:
            observe = self._observe_callback(
                "exit",
                node_addr=node_addr,
                exit_stmt_idx=exit_stmt_idx,
                block=block,
                state=state,
            )
            if observe:
                key = (
                    ("exit", (node_addr, exit_stmt_idx), ObservationPointType.OP_AFTER)
                    if node_idx is None
                    else ("exit", (node_addr, node_idx, exit_stmt_idx), ObservationPointType.OP_AFTER)
                )

        if not observe:
            return

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
        return ReachingDefinitionsState(
            CodeLocation(node.addr, stmt_idx=0, ins_addr=node.addr, context=self._init_context),
            self.project.arch,
            self.subject,
            track_tmps=self._track_tmps,
            track_consts=self._track_consts,
            analysis=self,
            canonical_size=self._canonical_size,
            initializer=self._state_initializer,
            element_limit=self._element_limit,
            merge_into_tops=self._merge_into_tops,
        )

    # pylint: disable=no-self-use,arguments-differ
    def _merge_states(self, _node, *states: ReachingDefinitionsState):
        assert len(states) >= 2
        merged_state, merge_occurred = states[0].merge(*states[1:])
        return merged_state, not merge_occurred

    def _compare_states(self, node, old_state: ReachingDefinitionsState, new_state: ReachingDefinitionsState) -> bool:
        """
        Return True if new_state >= old_state in the lattice.

        :param node:
        :param old_state:
        :param new_state:
        :return:
        """

        return new_state.compare(old_state)

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
            block_key = (node.addr, node.idx)
            engine = self._engine_ail
        elif isinstance(node, (Block, CodeNode)):
            block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
            engine = self._engine_vex
            block_key = node.addr
        elif isinstance(node, CFGNode):
            if node.is_simprocedure or node.is_syscall:
                return False, state.copy(discard_tmpdefs=True)
            block = node.block
            engine = self._engine_vex
            block_key = node.addr
        else:
            l.warning("Unsupported node type %s.", node.__class__)
            return False, state.copy(discard_tmpdefs=True)

        state = state.copy(discard_tmpdefs=True)
        self.node_observe(node.addr, state.copy(), OP_BEFORE)

        if self.subject.type == SubjectType.Function:
            node_parents = [
                CodeLocation(pred.addr, 0, block_idx=pred.idx if isinstance(pred, ailment.Block) else None)
                for pred in self._graph_visitor.predecessors(node)
            ]
            if node.addr == self.subject.content.addr:
                node_parents += [ExternalCodeLocation()]
            self.model.at_new_block(
                CodeLocation(block.addr, 0, block_idx=block.idx if isinstance(block, ailment.Block) else None),
                node_parents,
            )

        state = engine.process(
            state,
            block=block,
            fail_fast=self._fail_fast,
            visited_blocks=self._visited_blocks,
            dep_graph=self._dep_graph,
            model=self.model,
        )

        self._node_iterations[block_key] += 1

        self.node_observe(node.addr, state, OP_AFTER)

        # update all definitions and all uses
        self.all_definitions |= state.all_definitions
        for use in [state.stack_uses, state.heap_uses, state.register_uses, state.memory_uses]:
            self.all_uses.merge(use)

        if self._track_tmps:
            # merge tmp uses to all_uses
            for tmp_idx, locs in state.tmp_uses.items():
                tmp_def = next(iter(state.tmps[tmp_idx]))
                for loc in locs:
                    self.all_uses.add_use(tmp_def, loc)

        # drop definitions and uses because we will not need them anymore
        state.downsize()

        if self._node_iterations[block_key] < self._max_iterations:
            return None, state
        return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    def callsites_to(self, target: int | str | Function) -> Iterable[FunctionCallRelationships]:
        if isinstance(target, (str, int)):
            try:
                func_addr = self.project.kb.functions[target].addr
            except KeyError:
                return
        elif isinstance(target, Function):
            func_addr = target.addr
        else:
            raise TypeError(type(target))

        for info in self.function_calls.values():
            if info.target == func_addr:
                yield info
