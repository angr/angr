#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations
from random import randrange
from unittest import main, mock, TestCase
import networkx

import claripy

from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation, Register
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.analyses.reaching_definitions.dep_graph import DepGraph


_PAST_N = set()


def unique_randrange(range_):
    n = randrange(range_)
    while n in _PAST_N:
        n = randrange(range_)
    _PAST_N.add(n)
    return n


def _a_mock_definition(atom: Atom = None):
    # Randomise code locations to forcefully produce "different" <Definition>s.
    statement_index = unique_randrange(1000)
    code_location = CodeLocation(0x42, statement_index)
    return Definition(atom, code_location)


class TestDepGraph(TestCase):
    class ArchMock:
        def __init__(self):
            pass

        @property
        def bits(self):
            return 32

    class CFGMock:
        def __init__(self, memory_data):
            self._memory_data = memory_data

        @property
        def memory_data(self):
            return self._memory_data

    class MemoryDataMock:
        def __init__(self, address, content, size, sort):
            self._address = address
            self._content = content
            self._size = size
            self._sort = sort

        @property
        def address(self):
            return self._address

        @property
        def content(self):
            return self._content

        @property
        def size(self):
            return self._size

        @property
        def sort(self):
            return self._sort

    class SectionMock:
        def __init__(self, is_writable):
            self._is_writable = is_writable

        @property
        def is_writable(self):
            return self._is_writable

    class MainObjectMock:
        def __init__(self, section):
            self._section = section

        def find_section_containing(self, _):
            return self._section

    class LoaderMock:
        def __init__(self, main_object):
            self._main_object = main_object

        @property
        def main_object(self):
            return self._main_object

    def setUp(self):
        self.memory_address = 0x42424242

        self.string_in_memory = "some string of data in memory"
        self.string_in_memory_length = len(self.string_in_memory + "\x00")

    def test_dep_graph_has_a_default_graph(self):
        dep_graph = DepGraph()
        self.assertEqual(isinstance(dep_graph.graph, networkx.DiGraph), True)

    def test_dep_graph_refuses_to_instantiate_with_an_inadequate_graph(self):
        a_graph = networkx.DiGraph([(1, 2)])
        self.assertRaises(TypeError, DepGraph, a_graph)

    def test_delegate_add_node_to_the_underlying_graph_object(self):
        with mock.patch.object(networkx.DiGraph, "add_node") as digraph_add_node_mock:
            definition = _a_mock_definition()
            dep_graph = DepGraph()
            dep_graph.add_node(definition)

            digraph_add_node_mock.assert_called_once_with(definition)

    def test_delegate_nodes_to_the_underlying_graph_object(self):
        with mock.patch.object(networkx.DiGraph, "nodes") as digraph_nodes_mock:
            dep_graph = DepGraph()
            dep_graph.nodes()

            digraph_nodes_mock.assert_called_once()

    def test_delegate_predecessors_to_the_underlying_graph_object(self):
        with mock.patch.object(networkx.DiGraph, "predecessors") as digraph_predecessors_mock:
            definition = _a_mock_definition()
            dep_graph = DepGraph()
            dep_graph.predecessors(definition)

            digraph_predecessors_mock.assert_called_once_with(definition)

    def test_delegate_add_edge_to_the_underlying_graph_object(self):
        with mock.patch.object(networkx.DiGraph, "add_edge") as digraph_add_edge_mock:
            use = (_a_mock_definition(), _a_mock_definition())
            labels = {"attribute1": "value1", "attribute2": "value2"}

            dep_graph = DepGraph()
            dep_graph.add_edge(*use, **labels)

            digraph_add_edge_mock.assert_called_once_with(*use, **labels)

    def test_transitive_closure_of_a_node(self):
        dep_graph = DepGraph()

        # A -> B, B -> D, C -> D
        A = _a_mock_definition()
        B = _a_mock_definition()
        C = _a_mock_definition()
        D = _a_mock_definition()
        uses = [
            (A, B),
            (B, D),
            (C, D),
        ]

        for use in uses:
            dep_graph.add_edge(*use)

        result = dep_graph.transitive_closure(D)
        result_nodes = set(result.nodes)
        result_edges = set(result.edges)

        self.assertSetEqual(result_nodes, {D, B, C, A})
        self.assertSetEqual(result_edges, {(B, D), (C, D), (A, B)})

    def test_transitive_closure_includes_beginning_node_with_memoized_content(self):
        dep_graph = DepGraph()
        # A -> B
        # B -> C
        # C -> D
        A = _a_mock_definition()
        B = _a_mock_definition()
        C = _a_mock_definition()
        D = _a_mock_definition()
        uses = [(A, B), (B, C), (C, D)]
        for use in uses:
            dep_graph.add_edge(*use)

        closure_0 = dep_graph.transitive_closure(C)
        self.assertNotIn(D, closure_0)

        closure_1 = dep_graph.transitive_closure(D)
        self.assertIn(D, closure_1)
        self.assertTrue(closure_1.has_edge(A, B))
        self.assertTrue(closure_1.has_edge(B, C))
        self.assertTrue(closure_1.has_edge(C, D))

    def test_transitive_closure_of_a_node_should_copy_labels_from_original_graph(self):
        dep_graph = DepGraph()

        # A -> B
        A = _a_mock_definition()
        B = _a_mock_definition()
        uses = [(A, B)]

        for use in uses:
            dep_graph.add_edge(*use, label="some data")

        result = dep_graph.transitive_closure(B).get_edge_data(A, B)["label"]

        self.assertEqual(result, "some data")

    def test_transitive_closure_of_a_node_on_a_graph_with_loops_should_still_terminate(self):
        dep_graph = DepGraph()

        # A -> B, B -> C, C -> D, D -> A
        A = _a_mock_definition()
        B = _a_mock_definition()
        C = _a_mock_definition()
        D = _a_mock_definition()
        uses = [
            (A, B),
            (B, C),
            (C, D),
            (D, A),
        ]

        for use in uses:
            dep_graph.add_edge(*use)

        result = dep_graph.transitive_closure(C)
        result_nodes = set(result.nodes)
        result_edges = set(result.edges)

        self.assertSetEqual(result_nodes, {A, B, C, D})
        self.assertSetEqual(result_edges, {(A, B), (B, C), (C, D), (D, A)})

    def test_contains_atom_returns_true_if_the_dependency_graph_contains_a_definition_of_the_given_atom(self):
        dep_graph = DepGraph()

        r0 = Register(8, 4)

        # A -> B
        A = _a_mock_definition(r0)
        B = _a_mock_definition()

        uses = [(A, B)]

        for use in uses:
            dep_graph.add_edge(*use)

        result = dep_graph.contains_atom(r0)
        self.assertTrue(result)

    def test_contains_atom_returns_false_if_the_dependency_graph_does_not_contain_a_definition_of_the_given_atom(self):
        dep_graph = DepGraph()

        # A -> B
        A = _a_mock_definition()
        B = _a_mock_definition()

        uses = [(A, B)]

        for use in uses:
            dep_graph.add_edge(*use)

        result = dep_graph.contains_atom(Register(8, 4))
        self.assertFalse(result)

    def test_add_dependencies_for_concrete_pointers_of_fails_if_the_given_definition_is_not_in_the_graph(self):
        dependency_graph = DepGraph()

        definition = Definition(
            Register(0, 4),
            CodeLocation(0x42, 0),
        )

        with self.assertRaises(AssertionError) as cm:
            dependency_graph.add_dependencies_for_concrete_pointers_of([claripy.BVS("TOP", 32)], definition, None, None)

        ex = cm.exception
        self.assertEqual(str(ex), "The given Definition must be present in the given graph.")

    def test_add_dependencies_for_concrete_pointers_of_adds_a_definition_for_data_pointed_to_by_given_definition(self):
        arch = self.ArchMock()
        loader = self.LoaderMock(self.MainObjectMock(self.SectionMock(True)))

        memory_datum = self.MemoryDataMock(
            self.memory_address, str.encode(self.string_in_memory), len(self.string_in_memory), "string"
        )
        cfg = self.CFGMock({self.memory_address: memory_datum})

        register_definition = Definition(
            Register(0, 4),
            None,
        )

        dependency_graph = DepGraph()
        dependency_graph.add_node(register_definition)

        dependency_graph.add_dependencies_for_concrete_pointers_of(
            [claripy.BVV(self.memory_address, arch.bits)], register_definition, cfg, loader
        )

        memory_definition = Definition(
            MemoryLocation(self.memory_address, self.string_in_memory_length),
            ExternalCodeLocation(),
        )

        nodes = list(dependency_graph.nodes())
        predecessors = list(dependency_graph.graph.predecessors(register_definition))
        self.assertEqual(nodes, [register_definition, memory_definition])
        self.assertListEqual(predecessors, [memory_definition])

    def test_add_dependencies_for_concrete_pointers_of_does_nothing_if_data_pointed_to_by_definition_is_already_in_dependency_graph(
        self,
    ):
        arch = self.ArchMock()
        loader = self.LoaderMock(self.MainObjectMock(self.SectionMock(True)))

        memory_datum = self.MemoryDataMock(
            self.memory_address, str.encode(self.string_in_memory), len(self.string_in_memory), "string"
        )
        cfg = self.CFGMock({self.memory_address: memory_datum})

        memory_location_definition = Definition(
            MemoryLocation(self.memory_address, self.string_in_memory_length),
            CodeLocation(0, 0),
        )

        register_definition = Definition(
            Register(0, 4),
            CodeLocation(0x42, 0),
        )

        dependency_graph = DepGraph(networkx.DiGraph([(memory_location_definition, register_definition)]))

        nodes_before_call = dependency_graph.nodes()

        dependency_graph.add_dependencies_for_concrete_pointers_of(
            [claripy.BVV(self.memory_address, arch.bits)], register_definition, cfg, loader
        )

        self.assertEqual(nodes_before_call, dependency_graph.nodes())

    def test_add_dependencies_for_concrete_pointers_of_does_nothing_if_pointer_is_not_concrete(self):
        arch = self.ArchMock()
        cfg = self.CFGMock({})
        loader = self.LoaderMock(self.MainObjectMock(self.SectionMock(True)))

        register_definition = Definition(
            Register(0, 4),
            CodeLocation(0x42, 0),
        )

        dependency_graph = DepGraph()
        dependency_graph.add_node(register_definition)

        nodes_before_call = dependency_graph.nodes()

        dependency_graph.add_dependencies_for_concrete_pointers_of(
            [claripy.BVS("TOP", arch.bits)],
            register_definition,
            cfg,
            loader,
        )

        self.assertEqual(nodes_before_call, dependency_graph.nodes())

    def test_add_dependencies_for_concrete_pointers_of_create_memory_location_with_undefined_data_if_data_pointed_to_by_definition_is_not_known(
        self,
    ):
        arch = self.ArchMock()
        loader = self.LoaderMock(self.MainObjectMock(self.SectionMock(True)))

        datum_content = None
        datum_size = 0x4242
        memory_datum = self.MemoryDataMock(self.memory_address, datum_content, datum_size, "unknown")
        cfg = self.CFGMock({self.memory_address: memory_datum})

        memory_definition = Definition(
            MemoryLocation(self.memory_address, datum_size),
            ExternalCodeLocation(),
        )

        register_definition = Definition(
            Register(0, 4),
            CodeLocation(0x42, 0),
        )

        dependency_graph = DepGraph()
        dependency_graph.add_node(register_definition)

        dependency_graph.add_dependencies_for_concrete_pointers_of(
            [claripy.BVV(self.memory_address, arch.bits)],
            register_definition,
            cfg,
            loader,
        )

        nodes = list(dependency_graph.nodes())
        predecessors = list(dependency_graph.graph.predecessors(register_definition))
        self.assertEqual(nodes, [register_definition, memory_definition])
        self.assertListEqual(predecessors, [memory_definition])

    def test_add_dependencies_for_concrete_pointers_of_adds_a_definition_with_codelocation_in_binary_if_data_in_readonly_memory(
        self,
    ):
        arch = self.ArchMock()

        writable = False
        loader = self.LoaderMock(self.MainObjectMock(self.SectionMock(writable)))

        memory_datum = self.MemoryDataMock(
            self.memory_address, str.encode(self.string_in_memory), len(self.string_in_memory), "string"
        )
        cfg = self.CFGMock({self.memory_address: memory_datum})

        register_definition = Definition(
            Register(0, 4),
            CodeLocation(0x42, 0),
        )

        dependency_graph = DepGraph()
        dependency_graph.add_node(register_definition)

        dependency_graph.add_dependencies_for_concrete_pointers_of(
            [claripy.BVV(self.memory_address, arch.bits)],
            register_definition,
            cfg,
            loader,
        )

        origin_codelocation = CodeLocation(0, 0, info={"readonly": True})

        predecessor = next(iter(dependency_graph.graph.predecessors(register_definition)))
        self.assertEqual(predecessor.codeloc, origin_codelocation)


if __name__ == "__main__":
    main()
