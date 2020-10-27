import logging
import networkx

from typing import Optional, DefaultDict, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING
from ...code_location import CodeLocation
from ..forward_analysis import ForwardAnalysis, SingleNodeGraphVisitor
from ...block import Block
from ...knowledge_plugins.cfg.cfg_node import CFGNode
from ...codenode import CodeNode

l = logging.getLogger(name=__name__)


class StmtNode():
    def __init__(self, codeloc: CodeLocation, operand, operator=None,):
        self.operand = operand
        self.operator = operator
        self.codeloc = codeloc

class StatementDependencyState():
    def __init__(self):
        pass

class StatementDependencyAnalysis(ForwardAnalysis, Analysis):
    def __init__(self, all_definitions, vex):
        self._all_definitions = all_definitions
        self._vex = vex
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=SingleNodeGraphVisitor(self._vex))
        self._stmt_dep_graph = networkx.DiGraph()

        self._engine_vex = SimEngineSDVEX(self.project)
        self._visited_blocks: Set[Any]

        self._analyze()

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node) -> StatementDependencyState:
        if self._init_state is not None:
            return self._init_state
        else:
            return StatementDependencyState()

    def _run_on_node(self, node, state: StatementDependencyState):
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
        elif isinstance(node, Block):
            block = node
            engine = self._engine_vex
        elif isinstance(node, CodeNode):
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
        state, self._stmt_dep_graph = engine.process(
            state,
            block=block,
            fail_fast=self._fail_fast,
            visited_blocks=self._visited_blocks,
            stmt_dep_graph=self._stmt_dep_graph,
        )

        block_key = node.addr
        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

