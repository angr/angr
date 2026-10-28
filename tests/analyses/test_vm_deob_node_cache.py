#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation, detects_changes


class _Node:
    """Stands in for a CFGENode: value-hashed, carries an irsb-like shape."""

    def __init__(self, addr, nstmts=1):
        self.addr = addr
        self.irsb = type("IRSB", (), {"statements": [None] * nstmts, "next": None})()

    def __eq__(self, other):
        return isinstance(other, _Node) and self.addr == other.addr

    def __hash__(self):
        return hash(self.addr)


class _Graph:
    def __init__(self, nodes):
        self._nodes = list(nodes)

    def nodes(self):
        return list(self._nodes)

    def number_of_edges(self):
        return 0


class _CFG:
    def __init__(self, nodes):
        self.graph = _Graph(nodes)


def _analysis():
    # the cache bookkeeping needs none of the pipeline state, so skip __init__
    self = VMDeobfuscation.__new__(VMDeobfuscation)
    self.project = None
    self._pass_changed = False
    self._change_counter = 0
    self._coarse_epoch = 0
    self._pass_seen = {}
    self._node_dirty = {}
    self._node_seen = {}
    return self


class TestNodeCleanCache(unittest.TestCase):
    def _examine(self, a, name, node):
        epoch, counter = a._coarse_epoch, a._change_counter
        a._mark_node_clean(name, node, epoch, counter)

    def test_clean_entry_survives_graph_change(self):
        a = _analysis()
        n = _Node(0x1000)
        self._examine(a, "p", n)
        assert a._node_is_clean("p", n)
        a._note_graph_change()
        assert a._pass_changed and a._change_counter == 1
        assert a._node_is_clean("p", n)
        # a coarse change still retires everything
        a._note_change()
        assert not a._node_is_clean("p", n)

    def test_node_edit_dirties_only_that_node(self):
        a = _analysis()
        n1, n2 = _Node(0x1000), _Node(0x2000)
        self._examine(a, "p", n1)
        self._examine(a, "p", n2)
        a._note_change(n1)
        assert not a._node_is_clean("p", n1)
        assert a._node_is_clean("p", n2)
        # an examination that starts after the edit sees the edited block
        self._examine(a, "p", n1)
        assert a._node_is_clean("p", n1)

    def test_edit_during_examination_is_not_clean(self):
        a = _analysis()
        n = _Node(0x1000)
        epoch, counter = a._coarse_epoch, a._change_counter
        a._note_change(n)
        a._mark_node_clean("p", n, epoch, counter)
        assert not a._node_is_clean("p", n)

    def test_cache_is_per_pass(self):
        a = _analysis()
        n = _Node(0x1000)
        self._examine(a, "p", n)
        assert a._node_is_clean("p", n)
        assert not a._node_is_clean("q", n)

    def test_detects_changes_keeps_node_cache(self):
        a = _analysis()
        n1, n2 = _Node(0x1000, 2), _Node(0x2000, 2)
        cfg = _CFG([n1, n2])
        self._examine(a, "p", n1)

        @detects_changes
        def drop_node(self, cfg):
            cfg.graph._nodes.remove(n2)
            return cfg

        drop_node(a, cfg)
        assert a._pass_changed and a._change_counter == 1
        assert a._node_is_clean("p", n1)


if __name__ == "__main__":
    unittest.main()
