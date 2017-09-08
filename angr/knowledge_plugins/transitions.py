import networkx as nx

from ..errors import AngrError
from .plugin import KnowledgeBasePlugin

import logging

l = logging.getLogger("angr.knowledge.transitions")


class TransitionsPlugin(KnowledgeBasePlugin):
    """
    Storage for information about the transitions between basic blocks. Access as kb.transitions.

    Suggested jumpkind-to-transition map is:
        - transition    -> Ijk_Boring
        - call          -> Ijk_Call
        - syscall       -> Ijk_Sys*
        - ret           -> Ijk_Ret
        - fakeret       -> Ijk_FakeRet
    """

    def __init__(self):
        super(TransitionsPlugin, self).__init__()
        self._graph = nx.MultiDiGraph()

    def add_transition(self, from_addr, to_addr, jumpkind, ins_addr=None, stmt_idx=None, outside=None):
        """Register new transition of a given jumpkind between two basic blocks.

        :param from_addr:       The address of the basic block that control flow leaves during this transition.
        :param to_addr:         The address of the basic block that control flow enters during this transition.
        :param jumpkind:        The jumpkind that should be used to select the transition type.
        :param ins_addr:        The address of the instruction that produces this transition.
        :param stmt_idx:        The index of the statement that produces this transition.
        :param bool outside:    If this is a transition to another function, e.g. tail call optimization
        :return:
        """
        if jumpkind == 'Ijk_Boring':
            self._add_transition_to(
                from_addr=from_addr,
                to_addr=to_addr,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
                outside=outside
            )

        elif jumpkind == "Ijk_Call":
            self._add_call_to(
                from_addr=from_addr,
                to_addr=to_addr,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx
            )

        elif jumpkind == 'Ijk_Ret':
            self._add_return_to(
                from_addr=from_addr,
                to_addr=to_addr,
            )

        elif jumpkind == 'Ijk_FakeRet':
            self._add_fakeret_to(
                from_addr=from_addr,
                to_addr=to_addr,
            )

        elif jumpkind.startswith('Ijk_Sys'):
            self._add_call_to(
                from_addr=from_addr,
                to_addr=to_addr,
                stmt_idx=stmt_idx,
                ins_addr=ins_addr
            )

    def get_transition(self, from_addr=None, to_addr=None, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        # TODO: Subject to optimization.
        iter_transitions = self.iter_transitions(from_addr, to_addr, type, **attrs)
        first_transition = next(iter_transitions, None)
        if not first_transition and next(iter_transitions, None) is not None:
            raise AngrError("Multiple transitions")
        return first_transition

    def has_transition(self, from_addr=None, to_addr=None, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        iter_transitions = self.iter_transitions(from_addr, to_addr, type, **attrs)
        return next(iter_transitions, None) is not None

    def del_transition(self, from_addr=None, to_addr=None, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        iter_transitions = self.iter_transitions(from_addr, to_addr, type, **attrs)
        self._graph.remove_edges_from(iter_transitions)

    def iter_transitions(self, from_addr=None, to_addr=None, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        if from_addr is None and to_addr is None:
            return self._iter_transitions_all(type, **attrs)
        elif to_addr is None:
            return self._iter_transitions_from(from_addr, type, **attrs)
        elif from_addr is None:
            return self._iter_transitions_to(to_addr, type, **attrs)
        else:
            return self._iter_transitions_between(from_addr, to_addr, type, **attrs)

    def count_transitions(self, from_addr=None, to_addr=None, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        # TODO: Subject to optimization.
        return sum(1 for _ in self.iter_transitions(from_addr, to_addr, type, **attrs))

    #
    #   ...
    #

    def _add_transition_to(self, from_addr, to_addr, ins_addr=None, stmt_idx=None, outside=None):
        """
        Registers a transition edge between basic blocks in the transition graph.

        :param from_addr:       The address of the basic block that control flow leaves during this transition.
        :param to_addr:         The address of the basic block that control flow enters during this transition.
        :param ins_addr:        The address of the instruction that produces this transition.
        :param stmt_idx:        The index of the statement that produces this transition.
        :param bool outside:    If this is a transition to another function, e.g. tail call optimization
        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'transition',
                             ins_addr=ins_addr, stmt_idx=stmt_idx, outside=outside)

    def _add_call_to(self, from_addr, to_addr, ins_addr=None, stmt_idx=None):
        """
        Registers a call edge between a caller basic block and the callee entry block.

        :param from_addr:       The address of the basic block that control flow leaves during this transition.
        :param to_addr:         The address of the basic block that control flow enters during this transition.
        :param ins_addr:        The address of the instruction that produces this transition.
        :param stmt_idx:        The index of the statement that produces this transition.
        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'call',
                             ins_addr=ins_addr, stmt_idx=stmt_idx)

    def _add_return_to(self, from_addr, to_addr):
        """
        Registers a return edge in the transition graph.

        Note that there are no ins_addr or stmt_idx arguments presents. This is due to Ijk_Ret
        does always come from last instruction and has a 'default' stmt_idx.

        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'ret')

    def _add_fakeret_to(self, from_addr, to_addr):
        """
        Registers a fake-return edge in the transition graph.

        Note that there are no ins_addr or stmt_idx arguments presents. This is due to Ijk_FakeRet
        does always come from last instruction and has a 'default' stmt_idx.

        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'fakeret')

    def _iter_transitions_between(self, from_addr, to_addr, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        if from_addr in self._graph.edge and to_addr in self._graph.edge[from_addr]:
            for k, d in self._graph.edge[from_addr][to_addr].iteritems():
                if self._match_type(k, type) and self._match_attrs(d, attrs):
                    yield Transition(from_addr, to_addr, k, d)

    def _iter_transitions_to(self, to_addr, type=None, **attrs):
        """

        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        for u, _, k, d in self._graph.in_edges_iter(to_addr, data=True, keys=True):
            if self._match_type(k, type) and self._match_attrs(d, attrs):
                yield Transition(u, to_addr, type, d)

    def _iter_transitions_from(self, from_addr, type=None, **attrs):
        """

        :param from_addr:
        :param type:
        :param attrs:
        :return:
        """
        for _, v, k, d in self._graph.out_edges_iter(from_addr, data=True, keys=True):
            if self._match_type(k, type) and self._match_attrs(d, attrs):
                yield Transition(from_addr, v, type, d)

    def _iter_transitions_all(self, type=None, **attrs):
        """

        :param type:
        :param attrs:
        :return:
        """
        for u, v, k, d in self._graph.edges_iter(data=True, keys=True):
            if self._match_type(k, type) and self._match_attrs(d, attrs):
                yield Transition(u, v, k, d)

    @staticmethod
    def _match_type(this, other):
        return other is None or other == this

    @staticmethod
    def _match_attrs(this, other):
        if set(this) >= set(other):
            return all((this[k] == other[k] for k in other))
        return False


class Transition(object):

    def __init__(self, from_addr, to_addr, type, attrs):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.type = type
        self.attrs = attrs


KnowledgeBasePlugin.register_default('transitions', TransitionsPlugin)
