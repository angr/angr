from typing import Optional, Set, List, TYPE_CHECKING
import logging

import networkx

from . import Analysis
from ..knowledge_plugins.functions import Function

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.xrefs import XRefManager


_l = logging.getLogger(name=__name__)


class ProxiNodeTypes:
    String = 1
    Function = 2
    FunctionCall = 3


class BaseProxiNode:
    """
    Base class for all nodes in a proximity graph.
    """

    def __init__(self, type_: int, ref_at: Optional[Set[int]]=None):
        self.type_ = type_
        self.ref_at = ref_at


class FunctionProxiNode(BaseProxiNode):

    def __init__(self, func, ref_at: Optional[Set[int]]=None):
        super().__init__(ProxiNodeTypes.Function, ref_at=ref_at)
        self.func = func


class StringProxiNode(BaseProxiNode):

    def __init__(self, addr, content, ref_at: Optional[Set[int]]=None):
        super().__init__(ProxiNodeTypes.String, ref_at=ref_at)
        self.addr = addr
        self.content = content


class CallProxiNode(BaseProxiNode):

    def __init__(self, callee, ref_at: Optional[Set[int]]=None):
        super().__init__(ProxiNodeTypes.FunctionCall, ref_at=ref_at)
        self.callee = callee


class ProximityGraphAnalysis(Analysis):
    """
    Generate a proximity graph.
    """

    def __init__(self, func: 'Function', cfg_model: 'CFGModel', xrefs: 'XRefManager', pred_depth=1, succ_depth=1,
                 expand_funcs: Optional[Set[int]]=None):
        self._function = func
        self._cfg_model = cfg_model
        self._xrefs = xrefs
        self._pred_depth: int = pred_depth
        self._succ_depth: int = succ_depth
        self._expand_funcs = expand_funcs.copy() if expand_funcs else None

        self.graph: Optional[networkx.DiGraph] = None

        self._work()

    def _work(self):

        self.graph = networkx.DiGraph()

        # Process the function graph
        to_expand = self._process_function(self._function, self.graph)

        for func_node in to_expand:
            if self._expand_funcs:
                self._expand_funcs.discard(func_node.func.addr)

            subgraph = networkx.DiGraph()
            self._process_function(func_node.func, subgraph, func_proxi_node=func_node)

            # merge subgraph into the original graph
            self.graph.add_nodes_from(subgraph.nodes())
            self.graph.add_edges_from(subgraph.edges())

    def _process_function(self, func: 'Function', graph: networkx.DiGraph,
                          func_proxi_node: Optional[FunctionProxiNode]=None) -> List[FunctionProxiNode]:

        proxi_nodes: List[BaseProxiNode] = [ ]
        to_expand: List[FunctionProxiNode] = [ ]

        # strings
        for v in self._cfg_model.memory_data.values():
            if v.sort == "string":
                xrefs = self._xrefs.xrefs_by_dst[v.addr]
                for xref in xrefs:
                    if xref.block_addr in func.block_addrs_set:
                        # include this node
                        node = StringProxiNode(v.addr, v.content, ref_at=set(x.ins_addr for x in xrefs))
                        proxi_nodes.append(node)
                        break

        # function calls
        for n_ in func.nodes:
            if isinstance(n_, Function):
                func_node = n_
                ref_at = set()
                for _, _, data in func.transition_graph.in_edges(func_node, data=True):
                    if 'ins_addr' in data:
                        ref_at.add(data['ins_addr'])
                if self._expand_funcs and func_node.addr in self._expand_funcs:
                    node = FunctionProxiNode(func_node, ref_at=ref_at)
                    to_expand.append(node)
                else:
                    node = CallProxiNode(func_node, ref_at=ref_at)
                proxi_nodes.append(node)

        # the function
        if func_proxi_node is None:
            func_proxi_node = FunctionProxiNode(func)

        # add it to the graph
        graph.add_node(func_proxi_node)

        for pn in proxi_nodes:
            graph.add_edge(func_proxi_node, pn)

        return to_expand


from angr.analyses import AnalysesHub
AnalysesHub.register_default('Proximity', ProximityGraphAnalysis)
