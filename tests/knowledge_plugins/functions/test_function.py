#!/usr/bin/env python3
from __future__ import annotations

import os
from unittest import TestCase, main

import archinfo
import networkx

import angr
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions import Function
from angr.sim_type import parse_defns
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def makeFunction(function_manager, function_address, function_name):
    # Fill some value that are not relevant for the tests, but help circumvent a lot of mocking.
    f = Function(
        function_manager,
        function_address,
        name=function_name,
        syscall=False,
        is_simprocedure=False,
        is_plt=False,
        binary_name="rpaulson.bin",
        returning=True,
    )
    function_manager._function_map[function_address] = f
    return f


class MockFunctionManager:
    def __init__(self):
        self.callgraph = networkx.MultiDiGraph()
        self._function_map = {}

    def function(self, address):
        return self._function_map[address]

    def noop(self, *args, **kwargs):
        pass

    def contains_addr(self, addr):
        return addr in self._function_map

    def get_by_addr(self, addr):
        return self._function_map[addr]

    set_function_returning = noop


class TestFunction(TestCase):
    def setUp(self):
        self.function_manager = MockFunctionManager()

    def test_functions_called_returns_all_functions_that_can_be_reached_from_the_function(self):
        A = makeFunction(self.function_manager, 0x40, "A")
        B = makeFunction(self.function_manager, 0x41, "B")
        function = makeFunction(self.function_manager, 0x42, "function")
        C = makeFunction(self.function_manager, 0x43, "C")
        D = makeFunction(self.function_manager, 0x44, "D")
        E = makeFunction(self.function_manager, 0x45, "E")

        # A -> B
        # function -> C -> D
        # function -> E
        self.function_manager.callgraph.add_edges_from(
            [
                (A.addr, B.addr),
                (function.addr, C.addr),
                (function.addr, E.addr),
                (C.addr, D.addr),
            ]
        )

        self.assertEqual(function.functions_reachable(), {C, D, E})

    def test_functions_called_with_recursive_function(self):
        recursive_function = makeFunction(self.function_manager, 0x40, "recursive_function")
        B = makeFunction(self.function_manager, 0x41, "B")

        # recursive_function -> B
        # recursive_function -> recursive_function
        self.function_manager.callgraph.add_edges_from(
            [
                (recursive_function.addr, B.addr),
                (recursive_function.addr, recursive_function.addr),
            ]
        )

        self.assertEqual(recursive_function.functions_reachable(), {recursive_function, B})

    def test_functions_called_with_cyclic_dependencies(self):
        function = makeFunction(self.function_manager, 0x42, "function")
        C = makeFunction(self.function_manager, 0x43, "C")

        # function -> C -> function
        self.function_manager.callgraph.add_edges_from(
            [
                (function.addr, C.addr),
                (C.addr, function.addr),
            ]
        )

        self.assertEqual(function.functions_reachable(), {function, C})

    def test_function_set_prototype_without_parameter_names(self):
        function = makeFunction(self.function_manager, 0x42, "function")
        parsed_proto = parse_defns("int func(int, char*);")["func"]
        function.prototype = parsed_proto.with_arch(archinfo.arch_from_id("AMD64"))

        assert len(function.prototype.args) == 2
        assert len(function.prototype.arg_names) == 2
        # default function argument names apply
        assert function.prototype.arg_names[0] == "a0"
        assert function.prototype.arg_names[1] == "a1"

    def test_function_set_prototype_missing_a_parameter_name(self):
        function = makeFunction(self.function_manager, 0x42, "function")
        parsed_proto = parse_defns("int func(int, char*);")["func"]
        parsed_proto.arg_names = ["", "a3"]
        function.prototype = parsed_proto.with_arch(archinfo.arch_from_id("AMD64"))

        assert len(function.prototype.args) == 2
        assert len(function.prototype.arg_names) == 2
        # default function argument names apply
        assert function.prototype.arg_names[0] == "a0"
        # the original argument name should be kept
        assert function.prototype.arg_names[1] == "a3"

    def test_function_set_prototype_none(self):
        # you can set Function.prototype to None to clear it
        function = makeFunction(self.function_manager, 0x42, "function")
        function.prototype = None
        assert function.prototype is None


if __name__ == "__main__":
    main()


class TestLocalTransitionGraphCache(TestCase):
    """function.graph is cached; registering a node must invalidate it, or a reader that touched the graph earlier
    (e.g. a GUI thread during CFG recovery) leaves get_node() pointing at a node the cached graph does not contain."""

    def test_registering_a_node_invalidates_the_cached_graph(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        func = proj.kb.functions.function(0x40071D, create=True)
        assert func.get_node(0x40071D) is None
        cached = func.graph  # populate the cache while the function is still empty

        node = BlockNode(0x40071D, 4, graph=func.transition_graph)
        func._register_node(True, node)

        assert func.get_node(0x40071D) is node
        assert func.graph is not cached
        assert node in func.graph
        assert list(func.graph.successors(node)) == []
