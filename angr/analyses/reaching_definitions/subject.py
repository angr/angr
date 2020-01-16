from enum import Enum

import ailment

from ...block import Block
from ...knowledge_plugins.functions.function_manager import Function
from ..forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor


class SubjectType(Enum):
    Function = 1
    Block = 2


class Subject:
    def __init__(self, content, cfg, func_graph=None, cc=None):
        """
        The thing being analysed, and the way (visitor) to analyse it.

        :param ailment.Block|angr.Block|Function content:
            Thing to be analysed.
        :param angr.knowledge_plugins.cfg.cfg_model.CFGModel cfg:
            CFG of the program the thing was found in. Only used when analysing a slice.
        :param networkx.DiGraph func_graph: Alternative graph for function.graph.
        :param SimCC cc: Calling convention of the function.
        """

        self._content = content

        if isinstance(content, Function):
            self._cc = cc
            self._func_graph = func_graph
            self._type = SubjectType.Function
            self._visitor = FunctionGraphVisitor(content, func_graph)
        elif isinstance(content, (ailment.Block, Block)):
            self._type = SubjectType.Block
            self._visitor = SingleNodeGraphVisitor(content)
        else:
            raise TypeError('Unsupported analysis target.')

    @property
    def cc(self):
        if self.type is not SubjectType.Function:
            raise TypeError('There are no `cc` attribute for <%s>.' % self.type)
        return self._cc

    @property
    def content(self):
        return self._content

    @property
    def func_graph(self):
        if self.type is not SubjectType.Function:
            raise TypeError('There are no `func_graph` attribute for <%s>.' % self.type)
        return self._func_graph

    @property
    def type(self):
        return self._type

    @property
    def visitor(self):
        return self._visitor
