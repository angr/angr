import networkx as nx

from ...errors import AngrError
from ..view import KnowledgeBaseView

import logging
l = logging.getLogger("angr.knowledge_views.transitions")


class TransitionsView(KnowledgeBaseView):
    """
    Suggested jumpkind-to-transition map is:
        - transition    -> Ijk_Boring
        - call          -> Ijk_Call
        - syscall       -> Ijk_Sys*
        - ret           -> Ijk_Ret
        - fakeret       -> Ijk_FakeRet
    """

    def __init__(self, kb):
        """

        :param kb:
        """
        super(TransitionsView, self).\
            __init__(kb, provides='transitions',
                     consumes=('basic_blocks', 'indirect_jumps'))

        self._graph = nx.MultiDiGraph()

    def reconstruct(self):
        """

        :return:
        """
        self._graph.clear()

        for block in self._kb.blocks.iter_blocks():
            self._add_transitions_from_block(block)

        for from_addr, targets in self._kb.indirect_jumps.iteritems():
            for to_addr, specs in targets.iteritems():
                self._add_transitions_from_ijump(from_addr, to_addr, specs)

    #
    #   ...
    #

    @property
    def graph(self):
        return self._graph

    #
    #   ...
    #

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

    def _observe_basic_blocks_add_block(self, basic_block=None):
        block = self._kb.blocks.get(basic_block.addr, size=basic_block.size, thumb=basic_block.thumb)
        self._add_transitions_from_block(block)

    def _observe_indirect_jumps_register_jump(self, from_addr=None, to_addr=None, specs=None):
        self._add_transitions_from_ijump(from_addr, to_addr, specs)

    #
    #   ...
    #

    def _add_transitions_from_block(self, basic_block):
        """

        :param basic_block:
        :return:
        """
        from_addr = basic_block.addr
        direct_jumps = self._collect_exits(basic_block)
        for to_addr, specs in direct_jumps.iteritems():
            jumpkind, insn_addr, stmt_idx = specs
            self._add_transition(from_addr, to_addr, jumpkind, insn_addr, stmt_idx)

        # If the basic_block doesn't have no incoming, nor outgoing transitions registered yet,
        # then we should at least denote that the basic_block.addr can be transitioned to.
        if basic_block.addr not in self._graph:
            self._graph.add_node(basic_block.addr)

    def _add_transitions_from_ijump(self, from_addr, to_addr, specs):
        """

        :param from_addr:
        :param to_addr:
        :param specs:
        :return:
        """
        jumpkind, insn_addr, stmt_idx = specs
        self._add_transition(from_addr, to_addr, jumpkind, insn_addr, stmt_idx)

    def _add_transition(self, from_addr, to_addr, jumpkind, ins_addr=None, stmt_idx=None):
        """Register new transition of a given jumpkind between two basic blocks.

        :param from_addr:       The address of the basic block that control flow leaves during this transition.
        :param to_addr:         The address of the basic block that control flow enters during this transition.
        :param jumpkind:        The jumpkind that should be used to select the transition type.
        :param ins_addr:        The address of the instruction that produces this transition.
        :param stmt_idx:        The index of the statement that produces this transition.
        :return:
        """
        if jumpkind == 'Ijk_Boring':
            transition = self._add_transition_to(
                from_addr=from_addr,
                to_addr=to_addr,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

        elif jumpkind == "Ijk_Call":
            transition = self._add_call_to(
                from_addr=from_addr,
                to_addr=to_addr,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx
            )

        elif jumpkind == 'Ijk_Ret':
            transition = self._add_return_to(
                from_addr=from_addr,
                to_addr=to_addr,
            )

        elif jumpkind == 'Ijk_FakeRet':
            transition = self._add_fakeret_to(
                from_addr=from_addr,
                to_addr=to_addr,
            )

        elif jumpkind.startswith('Ijk_Sys'):
            transition = self._add_call_to(
                from_addr=from_addr,
                to_addr=to_addr,
                stmt_idx=stmt_idx,
                ins_addr=ins_addr
            )

        else:
            l.warn("Do not know how to handle %s" % jumpkind)
            return

        self._update_observers('add_transition', transition=transition)

    def _add_transition_to(self, from_addr, to_addr, ins_addr=None, stmt_idx=None):
        """
        Registers a transition edge between basic blocks in the transition graph.

        :param from_addr:       The address of the basic block that control flow leaves during this transition.
        :param to_addr:         The address of the basic block that control flow enters during this transition.
        :param ins_addr:        The address of the instruction that produces this transition.
        :param stmt_idx:        The index of the statement that produces this transition.
        :param bool outside:    If this is a transition to another function, e.g. tail call optimization
        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'transition', ins_addr=ins_addr, stmt_idx=stmt_idx)
        return Transition(from_addr, to_addr, 'transition', {'ins_addr': ins_addr, 'stmt_idx': stmt_idx})

    def _add_call_to(self, from_addr, to_addr, ins_addr=None, stmt_idx=None):
        """
        Registers a call edge between a caller basic block and the callee entry block.

        :param from_addr:       The address of the basic block that control flow leaves during this transition.
        :param to_addr:         The address of the basic block that control flow enters during this transition.
        :param ins_addr:        The address of the instruction that produces this transition.
        :param stmt_idx:        The index of the statement that produces this transition.
        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'call', ins_addr=ins_addr, stmt_idx=stmt_idx)
        return Transition(from_addr, to_addr, 'call', {'ins_addr': ins_addr, 'stmt_idx': stmt_idx})

    def _add_return_to(self, from_addr, to_addr):
        """
        Registers a return edge in the transition graph.

        Note that there are no ins_addr or stmt_idx arguments presents. This is due to Ijk_Ret
        does always come from last instruction and has a 'default' stmt_idx.

        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'ret')
        return Transition(from_addr, to_addr, 'ret', {})

    def _add_fakeret_to(self, from_addr, to_addr):
        """
        Registers a fake-return edge in the transition graph.

        Note that there are no ins_addr or stmt_idx arguments presents. This is due to Ijk_FakeRet
        does always come from last instruction and has a 'default' stmt_idx.

        :return: None
        """
        self._graph.add_edge(from_addr, to_addr, 'fakeret')
        return Transition(from_addr, to_addr, 'fakeret', {})

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

    #
    #   ...
    #

    @staticmethod
    def _collect_exits(block):
        """
        Loosely based on constant_jump_targets_and_jumpkinds

        :param block:
        :return:
        """
        exits = {}

        insn_addr = None
        for stmt_idx, stmt in enumerate(block.vex.statements):
            if stmt.tag == 'Ist_IMark':
                insn_addr = stmt.addr + stmt.delta
            elif stmt.tag == 'Ist_Exit':
                assert insn_addr is not None
                exits[stmt.dst.value] = stmt.jumpkind, insn_addr, stmt_idx

        default_target = block.vex._get_defaultexit_target()
        if default_target is not None:
            assert insn_addr is not None
            exits[default_target] = block.vex.jumpkind, insn_addr, None

        return exits

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

    def __repr__(self):
        return "<Transition(%#x, %#x, '%s', %r)>" % \
               (self.from_addr, self.to_addr, self.type, self.attrs)

    def to_nx_edge(self):
        return self.from_addr, self.to_addr, self.type, self.attrs
