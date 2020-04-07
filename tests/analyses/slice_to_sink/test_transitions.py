import nose
import os

from angr.analyses.slice_to_sink.transitions import merge_transitions
from angr.project import Project


BINARIES_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', 'binaries-private', 'operation-mango'
)
BINARY_PATH = os.path.join(BINARIES_PATH, 'air-live-bu-2015', 'cgi_test.cgi')
PROJECT = Project(BINARY_PATH, auto_load_libs=False)
CFG = PROJECT.analyses.CFGFast()
PRINTF = CFG.kb.functions.function(name='printf', plt=False)
PRINTF_NODE = CFG.model.get_all_nodes(PRINTF.addr)[0]


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
