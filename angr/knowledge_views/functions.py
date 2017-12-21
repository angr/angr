from itertools import imap

import networkx as nx

from .view import KnowledgeView
from .transitions import TransitionsView

import logging
l = logging.getLogger(name=__name__)


class FunctionsView(KnowledgeView):
    """
    TODO: Update documentation.
    """

    def __init__(self, kb, transitions=None, blocks=None):
        super(FunctionsView, self).__init__(kb)
        self._trans = transitions or TransitionsView(kb, blocks=blocks)

    def __getitem__(self, item):
        return FunctionView(self._kb, item, self._trans)

    def __iter__(self):
        return imap(self.get_function, self._kb.funcs)

    def __contains__(self, item):
        return item in self._kb.funcs

    def __len__(self):
        return len(self._kb.funcs)

    #
    #   ...
    #

    def get_function(self, entry):
        """

        :param entry:
        :return:
        """
        try:
            return self[entry]
        except KeyError:
            return None


class FunctionView(KnowledgeView):
    """
    TODO: Update documentation.
    """

    def __init__(self, kb, entry, transitions=None, blocks=None):
        """

        :param kb:
        :param entry:
        :param transitions:
        """
        super(FunctionView, self).__init__(kb)
        self._func = self._kb.funcs[entry]
        self._trans = transitions or TransitionsView(kb, blocks=blocks)

        self._graph = nx.MultiDiGraph()
        self._in_trans = []
        self._out_trans = []

    @property
    def entry(self):
        return self._func.entry

    @property
    def nodes(self):
        return self._func.nodes

    @property
    def returning(self):
        return self._func.returning

    @property
    @KnowledgeView.syncedmethod
    def graph(self):
        return self._graph

    @property
    @KnowledgeView.syncedmethod
    def ret_sites(self):
        return {t.from_addr for t in self._out_trans if t.type == 'ret'}

    @property
    @KnowledgeView.syncedmethod
    def call_sites(self):
        return {t.from_addr for t in self._out_trans if t.type == 'call'}

    @property
    @KnowledgeView.syncedmethod
    def jump_sites(self):
        return {t.from_addr for t in self._out_trans if t.type == 'transition'}

    @property
    @KnowledgeView.syncedmethod
    def callout_sites(self):
        return {n for n in self.call_sites if not self._graph.succ[n]}

    @property
    @KnowledgeView.syncedmethod
    def endpoints(self):
        return self.ret_sites | self.jump_sites | self.callout_sites

    @property
    @KnowledgeView.syncedmethod
    def in_transitions(self):
        return self._in_trans

    @property
    @KnowledgeView.syncedmethod
    def out_transitions(self):
        return self._out_trans

    #
    #   ...
    #

    def _do_sync_caches(self):
        self._graph.clear()
        del self._in_trans[:]
        del self._out_trans[:]

        graph = nx.induced_subgraph(self._trans.graph, self._func.nodes)
        self._graph.add_nodes_from(graph.nodes(data=True))
        self._graph.add_edges_from(graph.edges(data=True, keys=True))

        for n in (n for n in graph.nodes if not graph.succ[n]):
            for trans in self._trans.iter_transitions(from_addr=n):
                if trans.type != 'fakeret':
                    self._out_trans.append(trans)

        for n in (n for n in graph.nodes - {self.entry} if not graph.pred[n]):
            for trans in self._trans.iter_transitions(from_addr=n):
                if trans.type not in ('ret', 'fakeret'):
                    self._in_trans.append(trans)
