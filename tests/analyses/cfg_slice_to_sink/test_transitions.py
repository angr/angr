import unittest

from angr.analyses.cfg_slice_to_sink.transitions import merge_transitions


class TestTrasitions(unittest.TestCase):
    def test_merge_transitions(self):
        t1 = {1: [2, 3]}
        t2 = {2: [4]}

        result = merge_transitions(t1, t2)
        expected_result = {1: [2, 3], 2: [4]}

        self.assertEqual(result, expected_result)

    def test_merging_transitions_with_a_from_node_present_in_both_operands(self):
        t1 = {1: [2, 3]}
        t2 = {1: [4]}

        result = merge_transitions(t1, t2)
        expected_result = {1: [2, 3, 4]}

        self.assertEqual(result, expected_result)
