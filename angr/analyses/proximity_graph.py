from typing import Optional, Set, List, Tuple, TYPE_CHECKING
import logging

import networkx

import ailment

from ..knowledge_plugins.functions import Function
from . import Analysis
from .decompiler.ailgraph_walker import AILGraphWalker
from .decompiler.ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.xrefs import XRefManager
    from angr.analyses.decompiler.decompiler import Decompiler


_l = logging.getLogger(name=__name__)


class ProxiNodeTypes:
    String = 1
    Function = 2
    FunctionCall = 3
    Integer = 4
    Unknown = 5


class BaseProxiNode:
    """
    Base class for all nodes in a proximity graph.
    """

    def __init__(self, type_: int, ref_at: Optional[Set[int]]=None):
        self.type_ = type_
        self.ref_at = ref_at

    def __eq__(self, other):
        raise NotImplementedError()

    def __hash__(self):
        raise NotImplementedError()


class FunctionProxiNode(BaseProxiNode):

    def __init__(self, func, ref_at: Optional[Set[int]]=None):
        super().__init__(ProxiNodeTypes.Function, ref_at=ref_at)
        self.func = func

    def __eq__(self, other):
        return isinstance(other, FunctionProxiNode) and \
            other.type_ == self.type_ and \
            self.func == other.func

    def __hash__(self):
        return hash((FunctionProxiNode, self.func))


class StringProxiNode(BaseProxiNode):

    def __init__(self, addr, content, ref_at: Optional[Set[int]]=None):
        super().__init__(ProxiNodeTypes.String, ref_at=ref_at)
        self.addr = addr
        self.content = content

    def __eq__(self, other):
        return isinstance(other, StringProxiNode) and \
            other.type_ == self.type_ and \
            self.addr == other.addr

    def __hash__(self):
        return hash((StringProxiNode, self.addr))


class CallProxiNode(BaseProxiNode):

    def __init__(self, callee, ref_at: Optional[Set[int]]=None, args: Optional[Tuple[BaseProxiNode]]=None):
        super().__init__(ProxiNodeTypes.FunctionCall, ref_at=ref_at)
        self.callee = callee
        self.args = args

    def __eq__(self, other):
        return isinstance(other, CallProxiNode) and \
            other.type_ == self.type_ and \
            self.callee == other.callee and \
            self.args == other.args

    def __hash__(self):
        return hash((CallProxiNode, self.callee, self.args))


class IntegerProxiNode(BaseProxiNode):
    def __init__(self, value: int, ref_at: Optional[Set[int]]=None):
        super().__init__(ProxiNodeTypes.Integer, ref_at=ref_at)
        self.value = value

    def __eq__(self, other):
        return isinstance(other, IntegerProxiNode) and \
            self.type_ == other.type_ and \
            self.value == other.value

    def __hash__(self):
        return hash((IntegerProxiNode, self.value))


class UnknownProxiNode(BaseProxiNode):
    def __init__(self, dummy_value: str):
        super().__init__(ProxiNodeTypes.Unknown)
        self.dummy_value = dummy_value

    def __eq__(self, other):
        return isinstance(other, UnknownProxiNode) and \
            self.type_ == other.type_ and \
            self.dummy_value == other.dummy_value

    def __hash__(self):
        return hash((UnknownProxiNode, self.dummy_value))


class ProximityGraphAnalysis(Analysis):
    """
    Generate a proximity graph.
    """

    def __init__(self, func: 'Function', cfg_model: 'CFGModel', xrefs: 'XRefManager',
                 decompilation: Optional['Decompiler']=None,
                 pred_depth=1, succ_depth=1,
                 expand_funcs: Optional[Set[int]]=None):
        self._function = func
        self._cfg_model = cfg_model
        self._xrefs = xrefs
        self._decompilation = decompilation
        self._pred_depth: int = pred_depth
        self._succ_depth: int = succ_depth
        self._expand_funcs = expand_funcs.copy() if expand_funcs else None

        self.graph: Optional[networkx.DiGraph] = None

        self._work()

    def _work(self):

        self.graph = networkx.DiGraph()

        # the function
        func_proxi_node = FunctionProxiNode(self._function)

        # Process the function graph
        if not self._decompilation:
            to_expand = self._process_function(self._function, self.graph, func_proxi_node=func_proxi_node)
        else:
            to_expand = self._process_decompilation(self._function, self.graph, func_proxi_node=func_proxi_node)

        for func_node in to_expand:
            if self._expand_funcs:
                self._expand_funcs.discard(func_node.func.addr)

            subgraph = networkx.DiGraph()
            self._process_function(func_node.func, subgraph, func_proxi_node=func_node)

            # merge subgraph into the original graph
            self.graph.add_nodes_from(subgraph.nodes())
            self.graph.add_edges_from(subgraph.edges())

    def _process_strings(self, func, proxi_nodes, exclude_string_refs: Set[int]=None):
        # strings
        for v in self._cfg_model.memory_data.values():
            if exclude_string_refs and v.addr in exclude_string_refs:
                continue
            if v.sort == "string":
                xrefs = self._xrefs.xrefs_by_dst[v.addr]
                for xref in xrefs:
                    if xref.block_addr in func.block_addrs_set:
                        # include this node
                        node = StringProxiNode(v.addr, v.content, ref_at=set(x.ins_addr for x in xrefs))
                        proxi_nodes.append(node)
                        break

    def _process_function(self, func: 'Function', graph: networkx.DiGraph,
                          func_proxi_node: Optional[FunctionProxiNode]=None) -> List[FunctionProxiNode]:

        proxi_nodes: List[BaseProxiNode] = [ ]
        to_expand: List[FunctionProxiNode] = [ ]

        self._process_strings(func, proxi_nodes)

        # function calls
        for n_ in func.nodes:
            if isinstance(n_, Function):
                func_node = n_
                ref_at = set()
                for _, _, data in func.transition_graph.in_edges(func_node, data=True):
                    if 'ins_addr' in data:
                        ref_at.add(data['ins_addr'])
                if self._expand_funcs and func_node.addr in self._expand_funcs:  # pylint:disable=unsupported-membership-test
                    node = FunctionProxiNode(func_node, ref_at=ref_at)
                    to_expand.append(node)
                else:
                    node = CallProxiNode(func_node, ref_at=ref_at)
                proxi_nodes.append(node)

        # add it to the graph
        graph.add_node(func_proxi_node)
        for pn in proxi_nodes:
            graph.add_edge(func_proxi_node, pn)

        return to_expand

    def _process_decompilation(self, func: 'Function', graph: networkx.DiGraph,
                               func_proxi_node: Optional[FunctionProxiNode]=None) -> List[FunctionProxiNode]:
        proxi_nodes: List[BaseProxiNode] = [ ]
        to_expand: List[FunctionProxiNode] = [ ]

        # dedup
        string_refs: Set[int] = set()
        func_calls: Set[CallProxiNode] = set()

        # Walk the clinic structure to dump string references and function calls
        ail_graph = self._decompilation.clinic.graph

        def _handle_Call(stmt_idx: int, stmt: ailment.Stmt.Call, block: Optional[ailment.Block]):  # pylint:disable=unused-argument
            func_node = self.kb.functions[stmt.target.value]
            ref_at = { stmt.ins_addr }

            # extract arguments
            args = [ ]
            if stmt.args:
                for arg in stmt.args:
                    if isinstance(arg, ailment.Expr.Const):
                        # is it a reference to a string?
                        if arg.value in self._cfg_model.memory_data:
                            md = self._cfg_model.memory_data[arg.value]
                            if md.sort == "string":
                                # Yes!
                                args.append(StringProxiNode(arg.value, md.content))
                                string_refs.add(arg.value)
                        else:
                            # not a string. present it as a constant integer
                            args.append(IntegerProxiNode(arg.value, None))
                    else:
                        args.append(UnknownProxiNode("_"))

            if self._expand_funcs and func_node.addr in self._expand_funcs:  # pylint:disable=unsupported-membership-test
                node = FunctionProxiNode(func_node, ref_at=ref_at)
                to_expand.append(node)
            else:
                node = CallProxiNode(func_node, ref_at=ref_at, args=tuple(args) if args is not None else None)

            if node in func_calls:
                return
            func_calls.add(node)
            proxi_nodes.append(node)

        def _handle_CallExpr(self, expr_idx: int, expr: ailment.Stmt.Call, stmt_idx: int, stmt: ailment.Stmt.Statement, block: Optional[ailment.Block]):  # pylint:disable=unused-argument
            func_node = self.kb.functions[expr.target.value]
            ref_at = { stmt.ins_addr }
            if self._expand_funcs and func_node.addr in self._expand_funcs:
                node = FunctionProxiNode(func_node, ref_at=ref_at)
                to_expand.append(node)
            else:
                node = CallProxiNode(func_node, ref_at=ref_at)
            proxi_nodes.append(node)

        stmt_handlers = {
            ailment.Stmt.Call: _handle_Call,
        }
        expr_handlers = {
            ailment.Stmt.Call: _handle_CallExpr,
        }

        block_walker = AILBlockWalker(stmt_handlers=stmt_handlers, expr_handlers=expr_handlers)

        def _graph_walker_handler(node):
            block_walker.walk(node)

        AILGraphWalker(ail_graph, _graph_walker_handler, replace_nodes=False).walk()


        # add strings references that are not used in function calls
        self._process_strings(func, proxi_nodes, exclude_string_refs=string_refs)

        # add it to the graph
        graph.add_node(func_proxi_node)
        for pn in proxi_nodes:
            graph.add_edge(func_proxi_node, pn)

        return to_expand


from angr.analyses import AnalysesHub
AnalysesHub.register_default('Proximity', ProximityGraphAnalysis)
