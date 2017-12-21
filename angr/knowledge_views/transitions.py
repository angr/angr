import capstone.arm_const as _arm_const
import networkx as nx

from ..errors import AngrError
from .view import KnowledgeView
from .blocks import BlocksView

import logging
l = logging.getLogger(name=__name__)


class TransitionsView(KnowledgeView):
    """
    Suggested jumpkind-to-transition map is:
        - transition    -> Ijk_Boring
        - call          -> Ijk_Call
        - syscall       -> Ijk_Sys*
        - ret           -> Ijk_Ret
        - fakeret       -> Ijk_FakeRet
    """

    def __init__(self, kb, blocks=None):
        super(TransitionsView, self).__init__(kb)

        self._blocks = blocks or BlocksView(kb)

        self._cached_blocks = set()
        self._cached_ijumps = set()
        self._cached_complete = set()
        self._graph = nx.MultiDiGraph()

    @property
    @KnowledgeView.syncedmethod
    def graph(self):
        return self._graph

    #
    #   ...
    #

    @KnowledgeView.syncedmethod
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

    @KnowledgeView.syncedmethod
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

    @KnowledgeView.syncedmethod
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

    @KnowledgeView.syncedmethod
    def count_transitions(self, from_addr=None, to_addr=None, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        return sum(1 for _ in self.iter_transitions(from_addr, to_addr, type, **attrs))

    #
    #   ...
    #

    def _iter_transitions_between(self, from_addr, to_addr, type=None, **attrs):
        """

        :param from_addr:
        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        if self._graph.has_edge(from_addr, to_addr):
            for k, d in self._graph.adj[from_addr][to_addr].iteritems():
                if self._match_type(k, type) and self._match_attrs(d, attrs):
                    yield Transition(from_addr, to_addr, k, d)

    def _iter_transitions_to(self, to_addr, type=None, **attrs):
        """

        :param to_addr:
        :param type:
        :param attrs:
        :return:
        """
        if self._graph.has_node(to_addr):
            for u, _, k, d in self._graph.in_edges(to_addr, data=True, keys=True):
                if self._match_type(k, type) and self._match_attrs(d, attrs):
                    yield Transition(u, to_addr, k, d)

    def _iter_transitions_from(self, from_addr, type=None, **attrs):
        """

        :param from_addr:
        :param type:
        :param attrs:
        :return:
        """
        if self._graph.has_node(from_addr):
            for _, v, k, d in self._graph.out_edges(from_addr, data=True, keys=True):
                if self._match_type(k, type) and self._match_attrs(d, attrs):
                    yield Transition(from_addr, v, k, d)

    def _iter_transitions_all(self, type=None, **attrs):
        """

        :param type:
        :param attrs:
        :return:
        """
        for u, v, k, d in self._graph.edges(data=True, keys=True):
            if self._match_type(k, type) and self._match_attrs(d, attrs):
                yield Transition(u, v, k, d)

    #
    #   ...
    #

    @staticmethod
    def _match_type(this, other):
        return other is None or other == this

    @staticmethod
    def _match_attrs(this, other):
        if set(this) >= set(other):
            return all((this[k] == other[k] for k in other))
        return False

    @staticmethod
    def _jumpkind_to_type(jumpkind):
        """

        :param jumpkind:
        :return:
        """
        if jumpkind == 'Ijk_Boring':
            return 'transition'
        elif jumpkind == "Ijk_Call":
            return 'call'
        elif jumpkind == 'Ijk_Ret':
            return 'ret'
        elif jumpkind == 'Ijk_FakeRet':
            return 'fakeret'
        elif jumpkind.startswith('Ijk_Sys'):
            return 'call'
        else:
            return 'unknown'

    #
    #   ...
    #

    def _do_sync_caches(self):
        # TODO: Add comment.
        if self.kb.has_plugin('blocks'):
            fresh_blocks = self.kb.blocks.addrs - self._cached_blocks

            for block in map(self._blocks.get_block, fresh_blocks):
                self._graph.add_node(block.addr)

                self._graph.nodes[block.addr]['complete'] = \
                    self._graph.nodes[block.addr].get('complete', False) or \
                    block.vex.direct_next

                static_exits = self._collect_static_exits(block)
                for target, jump_specs in static_exits.items():
                    jump_type = self._jumpkind_to_type(jump_specs['jumpkind'])
                    self._graph.add_edge(block.addr, target, jump_type, **jump_specs)

            self._cached_blocks |= fresh_blocks

        # TODO: Add comment.
        if self.kb.has_plugin('ijumps'):
            fresh_ijumps = set(self.kb.ijumps.jumps) - self._cached_ijumps

            for ijump_addr in fresh_ijumps:
                self._graph.add_node(ijump_addr)

                self._graph.nodes[ijump_addr]['complete'] = \
                    self._graph.nodes[ijump_addr].get('complete', False) or \
                    self.kb.ijumps.is_complete(ijump_addr)

                for target, jump_specs in self.kb.ijumps.get_jump_targets(ijump_addr):
                    jump_type = self._jumpkind_to_type(jump_specs['jumpkind'])
                    self._graph.add_edge(ijump_addr, target, jump_type, **jump_specs)

            self._cached_ijumps |= fresh_ijumps

            # TODO: Add comment.
            fresh_complete = set(self.kb.ijumps.complete_jumps) - self._cached_complete

            for complete_addr in fresh_complete:
                self._graph.nodes[complete_addr]['complete'] = complete_addr

            self._cached_complete |= fresh_complete

    def _collect_static_exits(self, block):
        """Collect static exits from block.

        Loosely based on irsb.constant_jump_targets_and_jumpkinds

        :return:
        """
        exits = {}

        ins_addr = None
        for stmt_idx, stmt in enumerate(block.vex.statements):
            if stmt.tag == 'Ist_IMark':
                ins_addr = stmt.addr + stmt.delta
            elif stmt.tag == 'Ist_Exit':
                assert ins_addr is not None
                exits[stmt.dst.value] = {'jumpkind': stmt.jumpkind,
                                         'ins_addr': ins_addr,
                                         'stmt_idx': stmt_idx}

        default_target = block.vex._get_defaultexit_target()
        if default_target is not None:
            assert ins_addr is not None
            exits[default_target] = {'jumpkind': block.vex.jumpkind,
                                     'ins_addr': ins_addr,
                                     'stmt_idx': 'default'}

        if block.thumb:
            exits = self._arm_thumb_filter(block, exits)

        return exits

    def _arm_thumb_filter(self, block, exits):
        """

        :param block:
        :param exits:
        :return:
        """

        def _filter_func(target, jumpkind=None, ins_addr=None, stmt_idx=None):
            """

            :param target:
            :param jumpkind:
            :param ins_addr:
            :param stmt_idx:
            :return:
            """
            if stmt_idx == 'default':
                return True

            if ins_addr not in can_produce_exits:
                return False

            if jumpkind == 'Ijk_NoDecode':
                return False

            cs_insn = can_produce_exits[ins_addr]
            if not cs_insn.jump_targets:
                if target == cs_insn.address + cs_insn.size:
                    return False
            elif target not in cs_insn.jump_targets:
                return False

            return True

        can_produce_exits = {}
        for cs_insn in block.capstone.insns:
            if _arm_const.ARM_REG_PC in cs_insn.regs_write:
                can_produce_exits[cs_insn.address] = cs_insn

        return {target: spec for target, spec in exits.items() if
                _filter_func(target, **spec)}


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
