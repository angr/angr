#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
import unittest
import angr
from angr.utils.graph import Dominators, TemporaryNode
import networkx as nx

class TestGraph(unittest.TestCase):
    def test_dominators(self):
        G = nx.DiGraph()
        G.add_edge('1', '2')
        G.add_edge('1', '3')
        G.add_edge('2', '5')
        G.add_edge('2', '7')
        G.add_edge('3', '4')
        G.add_edge('4', '5')
        G.add_edge('4', '6')
        G.add_edge('4', '7')
        G.add_edge('5', '8')
        G.add_edge('7', '8')
        G.add_edge('8', '6')
        d = Dominators(G, '1')
        start_node = TemporaryNode("start_node")
        end_node = TemporaryNode("end_node")
        idom_succ = {start_node: {'1': {}}, '1': {'2': {}, '3': {}, '5': {}, '6': {}, '7': {}, '8': {}}, '3': {'4': {}}, '4': {}, '7': {}, '8': {}, '6': {end_node: {}}, end_node: {}, '5': {}, '2': {}}
        assert d.dom.succ == idom_succ

if __name__ == "__main__":
    unittest.main()