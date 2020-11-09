import os
import unittest

from angr.analyses.cfg_slice_to_sink import CFGSliceToSink
from angr.project import Project


class TestCFGSliceToSink(unittest.TestCase):
    def test_get_transitions_from_slice(self):
        transitions = {1: [2, 3]}
        my_slice = CFGSliceToSink(None, transitions)

        self.assertDictEqual(my_slice.transitions, transitions)

    def test_get_entrypoints_from_slice(self):
        transitions = {0: [2], 1: [2, 3], 2: [4, 5]}
        my_slice = CFGSliceToSink(None, transitions)

        self.assertListEqual(my_slice.entrypoints, [0, 1])

    def test_add_transitions_updates_the_slice(self):
        my_slice = CFGSliceToSink(None, {1: [2, 3]})
        transitions_to_add = { 1: [4], 2: [4] }

        result = my_slice.add_transitions(transitions_to_add)

        expected_result = {
            1: [2, 3, 4],
            2: [4],
        }

        self.assertDictEqual(result, expected_result)

    def test_nodes(self):
        my_slice = CFGSliceToSink(None, {
            1: [2, 3],
            2: [3],
        })

        expected_result = [1, 2, 3]
        result = my_slice.nodes

        self.assertListEqual(result, expected_result)

    def test_transitions_as_tuples(self):
        my_slice = CFGSliceToSink(None, {
            1: [2, 3],
            2: [3]
        })

        expected_result = [(1, 2), (1, 3), (2, 3)]
        result = my_slice.transitions_as_tuples

        self.assertListEqual(result, expected_result)

    def disable_emptyness(self):
        # disabled since binaries-private is not checked out for angr CI
        binaries_path = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'binaries-private', 'operation-mango'
        )
        binary_path = os.path.join(binaries_path, 'air-live-bu-2015', 'cgi_test.cgi')
        project = Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()
        printf = cfg.kb.functions.function(name='printf', plt=False)
        printf_node = cfg.model.get_all_nodes(printf.addr)[0]

        printf_predecessor = printf_node.predecessors[0]

        empty_slice = CFGSliceToSink(printf, {})
        non_empty_slice = CFGSliceToSink(printf, { printf_predecessor.addr: [printf.addr] })

        self.assertEqual(empty_slice.is_empty(), True)
        self.assertEqual(non_empty_slice.is_empty(), False)

    def test_path_between_returns_True_only_if_there_exists_at_least_a_path_between_two_nodes_in_the_slice(self):
        my_slice = CFGSliceToSink(None, {
            1: [2, 3],
            2: [4]
        })

        self.assertTrue(my_slice.path_between(1, 2))
        self.assertTrue(my_slice.path_between(1, 3))
        self.assertTrue(my_slice.path_between(2, 4))
        self.assertTrue(my_slice.path_between(1, 4))

        self.assertFalse(my_slice.path_between(3, 4))

    def test_path_between_deals_with_loops(self):
        my_slice = CFGSliceToSink(None, {
            1: [2, 3],
            2: [1]
        })

        self.assertFalse(my_slice.path_between(1, 4))
