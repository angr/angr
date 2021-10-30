from __future__ import annotations  # Makes all type hints strings that aren't evaluated (helps with cyclical imports)

import logging
import networkx

from typing import Optional, Set, TYPE_CHECKING, List
from angr.analyses.proximity_graph import BaseProxiNode, ProxiNodeTypes
from claripy import BV
from . import Analysis
from ..knowledge_plugins.functions import Function

from ..state_plugins import SimActionData, SimActionObject

if TYPE_CHECKING:
    from .. import SimState
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.xrefs import XRefManager
    from angr.analyses.decompiler.decompiler import Decompiler

_l = logging.getLogger(name=__name__)


class DepNodeTypes:
    Memory = 1
    Register = 2
    Integer = 3
    Unknown = 4


class BaseDepNode:
    """
    Base class for all nodes in a data-dependency graph
    """

    def __init__(self, type_: int):
        self.type_ = type_

    def __eq__(self, other):
        raise NotImplementedError()

    def __hash__(self):
        raise NotImplementedError()


class RegDepNode(BaseDepNode):
    def __init__(self, type_: int, reg: int):
        super(RegDepNode, self).__init__(type_)
        self.reg = reg

    def __eq__(self, other):
        return self.type_ == other.type_ and self.reg == other.reg

    def __hash__(self):
        return hash(self.type_) ^ hash(self.reg)


class MemDepNode(BaseDepNode):
    def __init__(self, type_: int, addr: int):
        super(MemDepNode, self).__init__(type_)
        self.addr = addr

    def __eq__(self, other):
        return self.type_ == other.type_ and self.addr == other.addr

    def __hash__(self):
        return hash(self.type_) ^ hash(self.addr)


class IntDepNode(BaseDepNode):
    def __init__(self, type_: int, value: int):
        super(IntDepNode, self).__init__(type_)
        self.value = value

    def __eq__(self, other):
        return self.type_ == other.type_ and self.value == other.value

    def __hash__(self):
        return hash(self.type_) ^ hash(self.value)


class DataDependencyGraphAnalysis(Analysis):
    """
    generates a proximity graph based off data-dependency.
    """

    def __init__(self, end_state: SimState, start_from):
        self._graph: Optional[networkx.DiGraph] = None
        self._end_state = end_state
        self._start_from = start_from
        self._graph_nodes: Set[BaseDepNode] = set()
        self._work()

    def _get_or_create_graph_node(self, type_: int, *constructor_params) -> BaseDepNode:
        """
        If the node already exists in the graph, that node is returned. Otherwise, a new node is created
        :param _type: Type of node to check/create
        :param constructor_params: Variadic list of arguments to supply for node lookup / creation
        :return: A reference to a node with the given parameters
        """

        if type_ is DepNodeTypes.Register:
            node = RegDepNode(type_, *constructor_params)
        elif type_ is DepNodeTypes.Memory:
            node = MemDepNode(type_, *constructor_params)
        elif type_ is DepNodeTypes.Integer:
            node = IntDepNode(type_, *constructor_params)
        else:
            raise TypeError("Type must be a type of DepNode.")

        # FIXME: This can definitely be done in O(1)...
        for n in self._graph_nodes:
            if n == node:
                return n
        else:
            self._graph_nodes.add(node)
            self._graph.add_node(node)
            return node

    def _work(self):
        """

        """
        self._graph = networkx.DiGraph()

        relevant_actions: List[SimActionObject] = self._end_state.history.filter_actions(block_addr=self._start_from)[
                                                  ::-1]

        for act in relevant_actions:
            # We only care about SimActionData for this analysis
            if not isinstance(act, SimActionData):
                continue

            if act.type is SimActionData.REG:
                # Retrieve register node
                reg_num = self._end_state.solver.eval(act.all_objects[0].ast)
                reg_node = self._get_or_create_graph_node(DepNodeTypes.Register, *[reg_num])

                # Retrieve integer node
                if act.action is SimActionData.READ:
                    val_node = self._get_or_create_graph_node(DepNodeTypes.Integer,
                                                              self._end_state.solver.eval(act.data.ast))
                    self._graph.add_edge(reg_node, val_node)  # Value is dependent on variable being read
                elif act.action is SimActionData.WRITE:
                    val_node = self._get_or_create_graph_node(DepNodeTypes.Integer,
                                                              self._end_state.solver.eval(act.actual_value.ast))
                    self._graph.add_edge(val_node, reg_node)  # Variable is dependent on value written
                else:
                    _l.error("Unable to parse SimActionData %r with action %s", act, act.action)
            elif act.type is SimActionData.TMP:
                # Retrieve temp node (uses Register class)
                tmp_num = self._end_state.solver.eval(act.all_objects[0].ast)
                tmp_node = self._get_or_create_graph_node(DepNodeTypes.Register, *[tmp_num])

                # Retrieve integer node
                val_node = self._get_or_create_graph_node(DepNodeTypes.Integer,
                                                          self._end_state.solver.eval(act.all_objects[1].ast))

                if act.action is SimActionData.READ:
                    self._graph.add_edge(tmp_node, val_node)  # Value is dependent on variable being read
                elif act.action is SimActionData.WRITE:
                    self._graph.add_edge(val_node, tmp_node)  # Variable is dependent on value written
                else:
                    _l.error("Unable to parse SimActionData %r with action %s", act, act.action)
            elif act.type is SimActionData.MEM:

                val_node = self._get_or_create_graph_node(DepNodeTypes.Integer,
                                                          self._end_state.solver.eval(act.data.ast))
                if act.action is SimActionData.READ:
                    mem_node = self._get_or_create_graph_node(DepNodeTypes.Memory,
                                                              self._end_state.solver.eval(act.addr.ast))
                    self._graph.add_edge(mem_node, val_node)  # Value is dependent on memory address
                elif act.action is SimActionData.WRITE:
                    mem_node = self._get_or_create_graph_node(DepNodeTypes.Memory, act.actual_addrs[0])
                    self._graph.add_edge(val_node, mem_node)  # Memory address is dependent on value
                else:
                    _l.error("Unable to parse SimActionData %r with action %s", act, act.action)
            else:
                _l.error("Unable to parse SimActionData %r with type %s", act, act.type)

            # Retrieve integer node

        # Run transitive reduction
        print(self._graph)
        print(self._graph.edges)
        # self._graph = networkx.algorithms.dag.transitive_reduction(self._graph)
        # print(self._graph)
        # Visualize the graph


# register this analysis
from angr.analyses import AnalysesHub

AnalysesHub.register_default('DataDep', DataDependencyGraphAnalysis)
