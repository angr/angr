import nose

from angr.analyses.cfg_slice_to_sink.transitions import merge_transitions


def test_merge_transitions():
    t1 = {1: [2, 3]}
    t2 = {2: [4]}

    result = merge_transitions(t1, t2)
    expected_result = {1: [2, 3], 2: [4]}

    nose.tools.assert_equal(result, expected_result)


def test_merging_transitions_with_a_from_node_present_in_both_operands():
    t1 = {1: [2, 3]}
    t2 = {1: [4]}

    result = merge_transitions(t1, t2)
    expected_result = {1: [2, 3, 4]}

    nose.tools.assert_equal(result, expected_result)
