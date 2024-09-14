#!/usr/bin/env python3
from __future__ import annotations
from unittest import main, TestCase

import networkx

from angr.knowledge_plugins.functions import Function


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


if __name__ == "__main__":
    main()
