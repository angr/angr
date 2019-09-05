import nose
import os

from angr.analyses.slice_to_sink.transitions import direct_transitions_to, merge_transitions
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


def test_transitions_to_returns_transitions_to_a_node():
    printf_predecessor = PRINTF_NODE.predecessors[0]
    printf_ancestors = printf_predecessor.predecessors

    nodes = [ PRINTF_NODE, printf_predecessor ]

    expected_results = [{
        printf_predecessor.addr: [PRINTF.addr],
    }, {
        printf_ancestors[0].addr: [printf_predecessor.addr],
        printf_ancestors[1].addr: [printf_predecessor.addr],
        printf_ancestors[2].addr: [printf_predecessor.addr],
    }]

    results = list(map(
        direct_transitions_to,
        nodes
    ))

    nose.tools.assert_list_equal(results, expected_results)


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
